package collect

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// Runner executes a registry against one system and gathers the result into a
// single fact set.
//
// The runner exists to make three guarantees a collector author does not have
// to implement: a collector runs after everything it depends on, no two
// Expensive collectors run at once, and a collector that hangs, panics or
// lacks the privilege it declared produces a recorded fact error rather than a
// hung, crashed or quietly incomplete scan.
//
// Nothing here decides whether an observation is good or bad. That is a
// check's job, and keeping the two apart is what makes checks testable.
type Runner struct {
	// Registry supplies the collectors and their dependency order.
	Registry *Registry

	// Timeout is the fallback budget for a collector whose own Timeout is
	// zero. A collector that declares one is bounded by its own, because what
	// is pathological for a config-file read is normal for a filesystem walk.
	//
	// Either way the budget is measured from the moment the collector actually
	// starts — after its dependencies finish and after it acquires the
	// Expensive slot — so that a collector is never charged for time it spent
	// queued behind another.
	//
	// Zero on both means no per-collector budget: the context passed to Run is
	// then the only bound, which is the whole-scan --timeout from CLI-SPEC §
	// collect.
	Timeout time.Duration

	// Evidence, when set, receives the raw bytes of every file a collector
	// reads, so that findings can cite content-addressed sources. Nil means
	// evidence is not being kept for this run.
	Evidence EvidenceRecorder

	// Observer, when set, is told as each collector finishes, so that a caller
	// can show progress during the slow half of a scan.
	//
	// **It is called from the collector goroutines and they run concurrently**,
	// so an implementation must be safe for concurrent use. This is the only
	// place in the project where that is true of an observer — catalog.Observer
	// is called from one goroutine — and the two are deliberately separate
	// interfaces so that neither package has to know about the other's
	// concurrency.
	//
	// Order is completion order, which is not registration order and is not
	// stable between runs: collectors finish when they finish. Nothing that
	// needs determinism may be built on these events. The findings are
	// deterministic; this is a progress display.
	Observer Observer
}

// Observer is notified as each collector finishes, however it finished.
// Exactly one call is made per collector in the run.
type Observer interface {
	CollectorDone(id string, status CollectorStatus, took time.Duration)
}

// CollectorStatus is how one collector's run ended.
//
// It is coarser than the fact.Error it produces, and deliberately: this is
// what a person watching a scan needs to know, and the error is what the
// report carries. A collector that could not run for want of privilege and one
// whose dependency was never registered are both Skipped here and are two very
// different entries in errors.json.
type CollectorStatus string

const (
	// CollectorOK: it ran and reported no error. Its facts are in the set.
	CollectorOK CollectorStatus = "ok"
	// CollectorFailed: it ran and something went wrong — an error it returned,
	// or a panic. A panic discards its output; an error does not.
	CollectorFailed CollectorStatus = "failed"
	// CollectorSkipped: it never ran. Insufficient privilege, or a dependency
	// that is not registered.
	CollectorSkipped CollectorStatus = "skipped"
	// CollectorTimedOut: it ran out of time, or the scan ended underneath it.
	CollectorTimedOut CollectorStatus = "timeout"
)

// observe reports one collector's outcome, if anyone is listening.
func (r Runner) observe(id string, status CollectorStatus, took time.Duration) {
	if r.Observer != nil {
		r.Observer.CollectorDone(id, status, took)
	}
}

// Run executes every registered collector and records the result in fs.
//
// It returns an error only when the run could not start at all. Everything a
// collector does wrong — a hang, a panic, a missing privilege, an unresolvable
// dependency — is recorded as a fact.Error and the run continues, because a
// scan that aborts on its first bad collector tells the operator nothing about
// the other eleven.
//
// Writes to fs are the runner's alone: each collector receives a private set
// and the runner merges it once the collector has finished. fact.Set is not
// safe for concurrent writes (DATA-MODEL §4), and handing the same one to
// concurrent collectors would be a data race that shows up as a corrupted
// audit rather than as a crash.
func (r Runner) Run(ctx context.Context, s system.System, fs *fact.Set) error {
	switch {
	case r.Registry == nil:
		return errors.New("collect: runner has no registry")
	case s == nil:
		return errors.New("collect: runner has no system")
	case fs == nil:
		return errors.New("collect: runner has no fact set")
	}

	if r.Evidence != nil {
		s = recordingSystem{System: s, rec: r.Evidence}
	}

	order := r.Registry.Order()
	missing := r.Registry.MissingDependencies()

	// One channel per collector, closed when it is finished for any reason.
	// A collector that was skipped still closes its channel: its dependents
	// are entitled to run and record their own account of what was missing,
	// and blocking them forever would turn one wiring bug into a hung scan.
	done := make(map[string]chan struct{}, len(order))
	for _, id := range order {
		done[id] = make(chan struct{})
	}

	var (
		mu sync.Mutex // guards every write to fs
		wg sync.WaitGroup
	)
	// record files one fact error against every fact the collector was
	// responsible for. A check looks up the fact it requires, not the
	// collector that was supposed to produce it, so an error filed under the
	// collector's name is an error no check ever sees.
	record := func(c Collector, kind fact.ErrorKind, msg string) {
		mu.Lock()
		defer mu.Unlock()
		for _, id := range blame(c) {
			fs.PutError(fact.Error{Fact: id, Kind: kind, Msg: msg})
		}
	}
	// A slot of one. This is the constraint enforced by the runner rather than
	// by convention, because convention is what produced twelve simultaneous
	// filesystem walks in the design this replaces.
	expensive := make(chan struct{}, 1)

	for _, id := range order {
		c, ok := r.Registry.Get(id)
		if !ok {
			continue // unreachable: order comes from the registry
		}

		wg.Add(1)
		go func(c Collector) {
			defer wg.Done()
			defer close(done[c.ID()])

			// One event per collector, on every path out of this function,
			// including the ones that never reach runOne. A progress display
			// that silently drops the collectors which could not run is one
			// that looks tidiest on the hosts it understands least.
			status, took := CollectorSkipped, time.Duration(0)
			defer func() { r.observe(c.ID(), status, took) }()

			if deps := missing[c.ID()]; len(deps) > 0 {
				record(c, fact.ErrInternal,
					fmt.Sprintf("collector %s depends on unregistered collector(s) %v; it was not run",
						c.ID(), deps))
				return
			}

			// Privilege is checked before anything is waited on: there is no
			// point queueing a collector that cannot observe truthfully.
			if euid := s.Euid(); !c.Requires().satisfiedBy(euid) {
				record(c, fact.ErrPermission,
					fmt.Sprintf("collector %s requires %s and the scan is running as euid %d; it was not run",
						c.ID(), c.Requires(), euid))
				return
			}

			for _, d := range c.DependsOn() {
				ch, known := done[d]
				if !known {
					continue // reported as a missing dependency above
				}
				select {
				case <-ch:
				case <-ctx.Done():
					status = CollectorTimedOut
					record(c, fact.ErrTimeout, cancelledMsg(c, ctx.Err(), "waiting for dependency "+d))
					return
				}
			}

			if c.Cost() == Expensive {
				select {
				case expensive <- struct{}{}:
					defer func() { <-expensive }()
				case <-ctx.Done():
					status = CollectorTimedOut
					record(c, fact.ErrTimeout, cancelledMsg(c, ctx.Err(), "waiting for the expensive-collector slot"))
					return
				}
			}

			status, took = r.runOne(ctx, c, s, fs, &mu, record)
		}(c)
	}

	wg.Wait()
	return nil
}

// result is how a collector's goroutine reports back. A panic is carried
// rather than re-raised: the runner classifies it, and re-panicking on the
// runner's goroutine would take the scan down with it.
type result struct {
	err      error
	panicked bool
	panicVal any
}

// runOne executes a single collector under its budget, isolating a panic and
// abandoning a collector that outruns the clock.
// The returned status and duration are for Observer. The duration is the time
// the collector actually spent working, measured from here rather than from
// the goroutine's start: a collector queued behind the Expensive slot did not
// spend that time doing anything, and charging it to the collector would tell
// an operator that a cheap read took thirty seconds.
func (r Runner) runOne(ctx context.Context, c Collector, s system.System, fs *fact.Set, mu *sync.Mutex, record func(Collector, fact.ErrorKind, string)) (CollectorStatus, time.Duration) {
	// Once the scan is over, no new collector starts. Waiting for a
	// dependency and waiting for the Expensive slot both race the scan
	// deadline, and without this a collector could win that race and go on
	// working a host whose scan has already ended.
	if err := ctx.Err(); err != nil {
		record(c, fact.ErrTimeout, cancelledMsg(c, err, "the scan ended before it could start"))
		return CollectorTimedOut, 0
	}

	started := time.Now()

	// The collector's own budget wins; the runner's is the fallback for one
	// that does not declare a preference.
	budget := c.Timeout()
	if budget <= 0 {
		budget = r.Timeout
	}
	cctx := ctx
	if budget > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	// The collector writes here. Nothing else reads this set until the
	// collector has returned, so a collector we abandon cannot race the merge.
	private := fact.NewSet()

	res := make(chan result, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				res <- result{panicked: true, panicVal: rec}
			}
		}()
		res <- result{err: c.Collect(cctx, s, private)}
	}()

	select {
	case got := <-res:
		switch {
		case got.panicked:
			// A collector bug. Its partial output is not trustworthy — it
			// stopped somewhere it did not choose — so it is discarded rather
			// than merged into an audit.
			record(c, fact.ErrInternal,
				fmt.Sprintf("collector %s panicked: %v", c.ID(), got.panicVal))
			return CollectorFailed, time.Since(started)

		case cctx.Err() != nil && got.err != nil:
			// It noticed the deadline and returned rather than being
			// abandoned. Same situation, same verdict: the budget decided the
			// outcome, so this is a timeout and not whatever error it chose to
			// return on the way out.
			record(c, fact.ErrTimeout, timedOutMsg(c, cctx, ctx))
			return CollectorTimedOut, time.Since(started)

		default:
			mu.Lock()
			mergeInto(fs, private)
			mu.Unlock()
			if got.err != nil {
				recordCollectorError(fs, mu, c, got.err)
				return CollectorFailed, time.Since(started)
			}
			return CollectorOK, time.Since(started)
		}

	case <-cctx.Done():
		// Abandoned. The goroutine is still running and still owns private,
		// so private is never touched again from here; it is garbage that
		// nobody else can see. Partial facts from a collector that ran out of
		// time are exactly the kind of half-truth this project refuses to
		// report as an observation.
		record(c, fact.ErrTimeout, timedOutMsg(c, cctx, ctx))
		return CollectorTimedOut, time.Since(started)
	}
}

// timedOut distinguishes a collector that spent its own budget from a scan
// that was cancelled underneath it. Both are ErrTimeout — fact.ErrorKind has
// no separate cancellation kind — but the message has to say which, or an
// operator reading errors.json six months later cannot tell whether to raise
// the budget or stop pressing Ctrl-C.
func timedOutMsg(c Collector, cctx, parent context.Context) string {
	switch {
	case parent.Err() != nil:
		return fmt.Sprintf("collector %s stopped: the scan was cancelled (%v)", c.ID(), parent.Err())
	case errors.Is(cctx.Err(), context.Canceled):
		return fmt.Sprintf("collector %s stopped: %v", c.ID(), cctx.Err())
	default:
		return fmt.Sprintf("collector %s exceeded its budget", c.ID())
	}
}

// blame names the facts a runner-level failure should be filed against. A
// collector that declares nothing is filed under its own ID: that loses the
// attribution a check needs, but losing the record entirely would be worse.
func blame(c Collector) []fact.ID {
	if ids := c.Produces(); len(ids) > 0 {
		return ids
	}
	return []fact.ID{fact.ID(c.ID())}
}

// cancelled records a collector that never started because the scan ended
// while it was queued. It is not the collector's fault and not a host
// condition, but it is still a gap, and a gap nobody recorded is a gap nobody
// can explain.
func cancelledMsg(c Collector, err error, waitingFor string) string {
	return fmt.Sprintf("collector %s did not run: the scan ended while %s (%v)", c.ID(), waitingFor, err)
}

// recordCollectorError files an error a collector returned. A fact.Error is
// recorded exactly as written — the collector knows which fact is missing and
// why, and that attribution is better than anything the runner could infer.
// Anything else is a failure it could not classify, which makes it a collector
// bug, filed against every fact it was responsible for.
func recordCollectorError(fs *fact.Set, mu *sync.Mutex, c Collector, err error) {
	var fe fact.Error
	if errors.As(err, &fe) {
		mu.Lock()
		defer mu.Unlock()
		fs.PutError(fe)
		return
	}
	msg := fmt.Sprintf("collector %s returned an unclassified error: %v", c.ID(), err)
	mu.Lock()
	defer mu.Unlock()
	for _, id := range blame(c) {
		fs.PutError(fact.Error{Fact: id, Kind: fact.ErrInternal, Msg: msg})
	}
}

// mergeInto copies one collector's private set into the run's set. Facts are
// copied before errors so that a collector recording both for one ID ends on
// the error, which is the conservative of the two.
func mergeInto(dst, src *fact.Set) {
	for _, id := range src.IDs() {
		f, _, ok := fact.Get[fact.Fact](src, id)
		if !ok {
			continue // unreachable: IDs lists exactly what is present
		}
		dst.Put(f)
	}
	for _, e := range src.Errors() {
		dst.PutError(e)
	}
}

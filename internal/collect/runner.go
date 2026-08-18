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

	// Timeout bounds one collector, measured from the moment it actually
	// starts — after its dependencies finish and after it acquires the
	// Expensive slot — so that a collector is never charged for time it spent
	// queued behind another.
	//
	// Zero means no per-collector budget: the context passed to Run is then
	// the only bound, which is the whole-scan --timeout from CLI-SPEC §
	// collect. Set it explicitly for an unattended scan; a collector blocked
	// on a pathological filesystem otherwise consumes the entire scan budget
	// on its own.
	Timeout time.Duration
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
	record := func(e fact.Error) {
		mu.Lock()
		defer mu.Unlock()
		fs.PutError(e)
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

			if deps := missing[c.ID()]; len(deps) > 0 {
				record(fact.Error{
					Fact: fact.ID(c.ID()),
					Kind: fact.ErrInternal,
					Msg: fmt.Sprintf("collector %s depends on unregistered collector(s) %v; it was not run",
						c.ID(), deps),
				})
				return
			}

			// Privilege is checked before anything is waited on: there is no
			// point queueing a collector that cannot observe truthfully.
			if euid := s.Euid(); !c.Requires().satisfiedBy(euid) {
				record(fact.Error{
					Fact: fact.ID(c.ID()),
					Kind: fact.ErrPermission,
					Msg: fmt.Sprintf("collector %s requires %s and the scan is running as euid %d; it was not run",
						c.ID(), c.Requires(), euid),
				})
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
					record(cancelled(c, ctx.Err(), "waiting for dependency "+d))
					return
				}
			}

			if c.Cost() == Expensive {
				select {
				case expensive <- struct{}{}:
					defer func() { <-expensive }()
				case <-ctx.Done():
					record(cancelled(c, ctx.Err(), "waiting for the expensive-collector slot"))
					return
				}
			}

			r.runOne(ctx, c, s, fs, &mu, record)
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
func (r Runner) runOne(ctx context.Context, c Collector, s system.System, fs *fact.Set, mu *sync.Mutex, record func(fact.Error)) {
	// Once the scan is over, no new collector starts. Waiting for a
	// dependency and waiting for the Expensive slot both race the scan
	// deadline, and without this a collector could win that race and go on
	// working a host whose scan has already ended.
	if err := ctx.Err(); err != nil {
		record(cancelled(c, err, "the scan ended before it could start"))
		return
	}

	cctx := ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, r.Timeout)
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
			record(fact.Error{
				Fact: fact.ID(c.ID()),
				Kind: fact.ErrInternal,
				Msg:  fmt.Sprintf("collector %s panicked: %v", c.ID(), got.panicVal),
			})

		case cctx.Err() != nil && got.err != nil:
			// It noticed the deadline and returned rather than being
			// abandoned. Same situation, same verdict: the budget decided the
			// outcome, so this is a timeout and not whatever error it chose to
			// return on the way out.
			record(timedOut(c, cctx, ctx))

		default:
			mu.Lock()
			mergeInto(fs, private)
			mu.Unlock()
			if got.err != nil {
				record(collectorError(c, got.err))
			}
		}

	case <-cctx.Done():
		// Abandoned. The goroutine is still running and still owns private,
		// so private is never touched again from here; it is garbage that
		// nobody else can see. Partial facts from a collector that ran out of
		// time are exactly the kind of half-truth this project refuses to
		// report as an observation.
		record(timedOut(c, cctx, ctx))
	}
}

// timedOut distinguishes a collector that spent its own budget from a scan
// that was cancelled underneath it. Both are ErrTimeout — fact.ErrorKind has
// no separate cancellation kind — but the message has to say which, or an
// operator reading errors.json six months later cannot tell whether to raise
// the budget or stop pressing Ctrl-C.
func timedOut(c Collector, cctx, parent context.Context) fact.Error {
	msg := fmt.Sprintf("collector %s exceeded its budget", c.ID())
	if parent.Err() != nil {
		msg = fmt.Sprintf("collector %s stopped: the scan was cancelled (%v)", c.ID(), parent.Err())
	} else if errors.Is(cctx.Err(), context.Canceled) {
		msg = fmt.Sprintf("collector %s stopped: %v", c.ID(), cctx.Err())
	}
	return fact.Error{Fact: fact.ID(c.ID()), Kind: fact.ErrTimeout, Msg: msg}
}

// cancelled records a collector that never started because the scan ended
// while it was queued. It is not the collector's fault and not a host
// condition, but it is still a gap, and a gap nobody recorded is a gap nobody
// can explain.
func cancelled(c Collector, err error, waitingFor string) fact.Error {
	return fact.Error{
		Fact: fact.ID(c.ID()),
		Kind: fact.ErrTimeout,
		Msg:  fmt.Sprintf("collector %s did not run: the scan ended while %s (%v)", c.ID(), waitingFor, err),
	}
}

// collectorError records an error a collector returned. A fact.Error is
// recorded as written, because the collector knows which fact is missing and
// why; anything else is a failure it could not classify, which makes it a
// collector bug.
func collectorError(c Collector, err error) fact.Error {
	var fe fact.Error
	if errors.As(err, &fe) {
		return fe
	}
	return fact.Error{
		Fact: fact.ID(c.ID()),
		Kind: fact.ErrInternal,
		Msg:  fmt.Sprintf("collector %s returned an unclassified error: %v", c.ID(), err),
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

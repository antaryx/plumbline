package collect_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"
	"github.com/antaryx/plumbline/internal/collect"
	sshdcollector "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// sys loads a fixture. Fixtures carry the euid a scan believes it is running
// as, which is how an unprivileged run is simulated without needing real
// permissions in git: sshd-hardened is euid 0, sshd-unreadable is euid 1000.
func sys(t *testing.T, fixture string) system.System {
	t.Helper()
	s, err := fake.New(filepath.Join(fixtureRoot, fixture))
	if err != nil {
		t.Fatalf("load fixture %s: %v", fixture, err)
	}
	return s
}

// run executes a registry and returns the resulting fact set.
func run(t *testing.T, r collect.Runner, s system.System) *fact.Set {
	t.Helper()
	fs := fact.NewSet()
	if err := r.Run(context.Background(), s, fs); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return fs
}

// wantError asserts a fact error of a given kind was recorded for id.
func wantError(t *testing.T, fs *fact.Set, id string, kind fact.ErrorKind, msgContains string) fact.Error {
	t.Helper()
	e, ok := fs.Err(fact.ID(id))
	if !ok {
		t.Fatalf("no fact error recorded for %q; errors are %+v", id, fs.Errors())
	}
	if e.Kind != kind {
		t.Errorf("%s: kind = %q, want %q (msg: %s)", id, e.Kind, kind, e.Msg)
	}
	if msgContains != "" && !strings.Contains(e.Msg, msgContains) {
		t.Errorf("%s: message %q does not mention %q", id, e.Msg, msgContains)
	}
	return e
}

// TestTimeoutYieldsErrTimeoutAndTheRunCompletes is the acceptance criterion.
// Both shapes of overrun are covered: a collector that watches its context and
// gives up, and one that ignores it entirely and has to be abandoned. An
// operator cannot tell the difference and neither verdict may differ.
func TestTimeoutYieldsErrTimeoutAndTheRunCompletes(t *testing.T) {
	cases := []struct {
		name string
		body func(ctx context.Context, s system.System, fs *fact.Set) error
	}{
		{"honours the deadline", func(ctx context.Context, _ system.System, _ *fact.Set) error {
			<-ctx.Done()
			return ctx.Err()
		}},
		{"ignores the deadline", func(_ context.Context, _ system.System, _ *fact.Set) error {
			time.Sleep(200 * time.Millisecond)
			return nil
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := newJournal()
			r := collect.NewRegistry()
			r.Register(stub{id: "slow", run: tc.body})
			r.Register(stub{id: "quick", run: j.mark("quick", 0)})

			fs := run(t, collect.Runner{Registry: r, Timeout: 40 * time.Millisecond}, sys(t, "sshd-hardened"))

			wantError(t, fs, "slow", fact.ErrTimeout, "budget")

			// The run completed: the other collector still ran, and nothing
			// about it was disturbed by its neighbour running out of time.
			if !j.didRun("quick") {
				t.Error("the rest of the run did not happen")
			}
			if _, bad := fs.Err(fact.ID("quick")); bad {
				t.Error("a healthy collector was blamed for its neighbour's timeout")
			}
		})
	}
}

// TestTimeoutDiscardsPartialWork: a collector that ran out of time wrote half
// an observation. Half an observation reported as fact is how a scanner ends
// up asserting something it never finished looking at.
func TestTimeoutDiscardsPartialWork(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{id: "half", run: func(ctx context.Context, _ system.System, fs *fact.Set) error {
		fs.Put(fact.SSHDConfig{Installed: true}) // written, then overrun
		<-ctx.Done()
		return ctx.Err()
	}})

	fs := run(t, collect.Runner{Registry: r, Timeout: 30 * time.Millisecond}, sys(t, "sshd-hardened"))

	wantError(t, fs, "half", fact.ErrTimeout, "")
	if ids := fs.IDs(); len(ids) != 0 {
		t.Errorf("partial facts from an abandoned collector were kept: %v", ids)
	}
}

// TestPanicYieldsErrInternalAndTheRunCompletes is the acceptance criterion. A
// collector bug must not take the scan down with it — and must not be silent
// either, because a collector that vanished is indistinguishable from a host
// with nothing to report.
func TestPanicYieldsErrInternalAndTheRunCompletes(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "boom", run: func(context.Context, system.System, *fact.Set) error {
		panic("collector bug: nil map write")
	}})
	r.Register(stub{id: "after", deps: []string{"boom"}, run: j.mark("after", 0)})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened"))

	wantError(t, fs, "boom", fact.ErrInternal, "nil map write")
	if !j.didRun("after") {
		t.Error("a collector downstream of the panic never ran")
	}
}

// TestDependencyOrderIsRespected is the acceptance criterion's synthetic
// four-node DAG:
//
//	a → b ─┐
//	 └→ c ─┴→ d
//
// It asserts both halves of what a DAG means: b and c wait for a and d waits
// for both, while b and c — which have no relationship — actually overlap
// rather than merely being allowed to.
func TestDependencyOrderIsRespected(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "a", run: j.mark("a", 20*time.Millisecond)})
	r.Register(stub{id: "b", deps: []string{"a"}, run: j.mark("b", 40*time.Millisecond)})
	r.Register(stub{id: "c", deps: []string{"a"}, run: j.mark("c", 40*time.Millisecond)})
	r.Register(stub{id: "d", deps: []string{"b", "c"}, run: j.mark("d", 20*time.Millisecond)})

	run(t, collect.Runner{Registry: r, Timeout: 5 * time.Second}, sys(t, "sshd-hardened"))

	for _, edge := range [][2]string{{"a", "b"}, {"a", "c"}, {"b", "d"}, {"c", "d"}} {
		before, ok := j.span(edge[0])
		if !ok {
			t.Fatalf("%s never ran", edge[0])
		}
		after, ok := j.span(edge[1])
		if !ok {
			t.Fatalf("%s never ran", edge[1])
		}
		if !before.end.Before(after.start) && !before.end.Equal(after.start) {
			t.Errorf("%s finished at %s, after %s started at %s",
				edge[0], before.end, edge[1], after.start)
		}
	}

	// Independent branches are concurrent, not merely permitted to be. If b
	// and c serialised, the runner would be correct and useless.
	b, _ := j.span("b")
	c, _ := j.span("c")
	if !b.start.Before(c.end) || !c.start.Before(b.end) {
		t.Errorf("independent collectors did not overlap: b %s..%s, c %s..%s",
			b.start, b.end, c.start, c.end)
	}
}

// TestExpensiveCollectorsNeverOverlap is the acceptance criterion, asserted
// with timestamps. This is the fix for the audited design's twelve
// simultaneous filesystem walks, and it has to be enforced by the runner: a
// convention that collectors are polite is not a constraint.
func TestExpensiveCollectorsNeverOverlap(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "walk-1", cost: collect.Expensive, run: j.mark("walk-1", 40*time.Millisecond)})
	r.Register(stub{id: "walk-2", cost: collect.Expensive, run: j.mark("walk-2", 40*time.Millisecond)})
	r.Register(stub{id: "walk-3", cost: collect.Expensive, run: j.mark("walk-3", 40*time.Millisecond)})
	r.Register(stub{id: "cheap", run: j.mark("cheap", 40*time.Millisecond)})

	run(t, collect.Runner{Registry: r, Timeout: 5 * time.Second}, sys(t, "sshd-hardened"))

	ids := []string{"walk-1", "walk-2", "walk-3"}
	for i := 0; i < len(ids); i++ {
		for k := i + 1; k < len(ids); k++ {
			x, okx := j.span(ids[i])
			y, oky := j.span(ids[k])
			if !okx || !oky {
				t.Fatalf("%s or %s never ran", ids[i], ids[k])
			}
			if x.start.Before(y.end) && y.start.Before(x.end) {
				t.Errorf("expensive collectors overlapped: %s %s..%s, %s %s..%s",
					ids[i], x.start, x.end, ids[k], y.start, y.end)
			}
		}
	}

	// The serialisation is for expensive work only. A cheap collector that had
	// to queue behind three filesystem walks would make the whole cost
	// classification pointless.
	cheap, _ := j.span("cheap")
	var overlapped bool
	for _, id := range ids {
		s, _ := j.span(id)
		if cheap.start.Before(s.end) && s.start.Before(cheap.end) {
			overlapped = true
		}
	}
	if !overlapped {
		t.Error("a cheap collector was serialised behind the expensive ones")
	}
}

// TestCapabilityShortfallYieldsErrPermission is the acceptance criterion: a
// collector that needs root, on a scan that is not root, is recorded rather
// than omitted. An omitted collector is indistinguishable from a host with
// nothing to report, which is how an unprivileged scan comes to look clean.
func TestCapabilityShortfallYieldsErrPermission(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "needs-root", requires: collect.CapRoot, run: j.mark("needs-root", 0)})
	r.Register(stub{id: "needs-nothing", run: j.mark("needs-nothing", 0)})

	// sshd-unreadable is the fixture that declares euid 1000.
	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-unreadable"))

	e := wantError(t, fs, "needs-root", fact.ErrPermission, "euid 1000")
	if !strings.Contains(e.Msg, "root") {
		t.Errorf("message does not say what was required: %q", e.Msg)
	}
	if j.didRun("needs-root") {
		t.Error("a collector ran without the privilege it declared it needed")
	}
	if !j.didRun("needs-nothing") {
		t.Error("an unprivileged collector was skipped along with the privileged one")
	}
}

// TestCapabilitySatisfiedRuns is the other half: the gate must not be a
// blanket refusal.
func TestCapabilitySatisfiedRuns(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "needs-root", requires: collect.CapRoot, run: j.mark("needs-root", 0)})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened")) // euid 0

	if !j.didRun("needs-root") {
		t.Error("a root collector did not run on a root scan")
	}
	if _, bad := fs.Err(fact.ID("needs-root")); bad {
		t.Error("a collector that had its privilege was still recorded as failing")
	}
}

// TestUnresolvedDependencyIsRecorded: a collector whose dependency nobody
// registered is a wiring bug. It is not run, and it is not silent.
func TestUnresolvedDependencyIsRecorded(t *testing.T) {
	j := newJournal()
	r := collect.NewRegistry()
	r.Register(stub{id: "orphan", deps: []string{"nobody"}, run: j.mark("orphan", 0)})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened"))

	wantError(t, fs, "orphan", fact.ErrInternal, "nobody")
	if j.didRun("orphan") {
		t.Error("a collector ran despite an unregistered dependency")
	}
}

// TestReturnedFactErrorIsRecordedAsWritten: when a collector returns a typed
// fact error, the runner keeps its attribution instead of relabelling it as a
// collector fault. The fact it names is the one a check will look for.
func TestReturnedFactErrorIsRecordedAsWritten(t *testing.T) {
	want := fact.Error{
		Fact: fact.ID("kernel.params"),
		Kind: fact.ErrTruncated,
		Msg:  "/proc/cmdline exceeded the read cap",
		Path: "/proc/cmdline",
	}
	r := collect.NewRegistry()
	r.Register(stub{id: "kernel", run: func(context.Context, system.System, *fact.Set) error {
		return want
	}})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened"))

	got, ok := fs.Err(want.Fact)
	if !ok {
		t.Fatalf("the returned fact error was not recorded; errors are %+v", fs.Errors())
	}
	if got != want {
		t.Errorf("fact error = %+v, want %+v", got, want)
	}
}

// TestUnclassifiedErrorBecomesInternal: an error a collector could not
// classify is a collector bug, and is recorded as one rather than being
// dressed up as a host condition.
func TestUnclassifiedErrorBecomesInternal(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{id: "vague", run: func(context.Context, system.System, *fact.Set) error {
		return errors.New("something went wrong")
	}})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened"))
	wantError(t, fs, "vague", fact.ErrInternal, "something went wrong")
}

// TestSSHDCollectorThroughTheRunner is the acceptance criterion that ties the
// port to the runner: running as euid 1000 against sshd-unreadable yields
// ErrPermission — not a crash, and not a missing fact.
//
// The collector declares CapNone, so the runner does not gate it. That is the
// point: the collector tries, fails on this specific path, and says so. The
// error names sshd.config, which is the fact SSHD-0002 requires, so the check
// resolves to UNKNOWN(insufficient_privileges) rather than to a default.
func TestSSHDCollectorThroughTheRunner(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(sshdcollector.New())

	fs := run(t, collect.Runner{Registry: r, Timeout: 5 * time.Second}, sys(t, "sshd-unreadable"))

	e := wantError(t, fs, string(fact.SSHDConfigID), fact.ErrPermission, "sshd configuration")
	if e.Path != "/etc/ssh/sshd_config" {
		t.Errorf("error path = %q, want the file it could not read", e.Path)
	}
	if _, _, ok := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID); ok {
		t.Error("a fact was reported for a file that could not be read")
	}
}

// TestSSHDCollectorProducesTheFact: the ported collector still collects.
func TestSSHDCollectorProducesTheFact(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(sshdcollector.New())

	fs := run(t, collect.Runner{Registry: r, Timeout: 5 * time.Second}, sys(t, "sshd-include"))

	cfg, ferr, ok := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID)
	if !ok {
		t.Fatalf("sshd.config not collected: %v", ferr)
	}
	if !cfg.Installed {
		t.Error("sshd.config reports not installed for a fixture that has one")
	}
	// The include-resolution semantics survived the port: the drop-in is
	// included on line 1, so its value is obtained first and wins.
	d, found := cfg.Effective("PermitRootLogin")
	if !found || d.Value != "no" {
		t.Errorf("effective PermitRootLogin = %+v (found=%v), want no", d, found)
	}
}

// TestRunRejectsAnUnusableRunner: a wiring mistake is an error, not a nil
// dereference in the middle of a scan.
func TestRunRejectsAnUnusableRunner(t *testing.T) {
	s := sys(t, "sshd-hardened")
	cases := []struct {
		name string
		r    collect.Runner
		s    system.System
		fs   *fact.Set
	}{
		{"no registry", collect.Runner{}, s, fact.NewSet()},
		{"no system", collect.Runner{Registry: collect.NewRegistry()}, nil, fact.NewSet()},
		{"no fact set", collect.Runner{Registry: collect.NewRegistry()}, s, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.r.Run(context.Background(), tc.s, tc.fs); err == nil {
				t.Error("Run accepted an unusable configuration")
			}
		})
	}
}

// TestCancelledScanRecordsEveryCollector: when the scan is cancelled, the
// collectors that never got to run are still accounted for. A bundle whose
// errors.json is silent about eleven collectors cannot explain the gap.
func TestCancelledScanRecordsEveryCollector(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{id: "first", cost: collect.Expensive, run: func(ctx context.Context, _ system.System, _ *fact.Set) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	// Both wait on "first", so the scan is already over by the time either
	// could start. Ordering them behind it is what makes the case
	// deterministic: an unordered collector races the cancellation and may
	// legitimately have finished before it.
	r.Register(stub{id: "queued", deps: []string{"first"}, cost: collect.Expensive, run: func(context.Context, system.System, *fact.Set) error {
		return nil
	}})
	r.Register(stub{id: "downstream", deps: []string{"first"}, run: func(context.Context, system.System, *fact.Set) error {
		return nil
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	fs := fact.NewSet()
	if err := (collect.Runner{Registry: r}).Run(ctx, sys(t, "sshd-hardened"), fs); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, id := range []string{"first", "queued", "downstream"} {
		if _, ok := fs.Err(fact.ID(id)); !ok {
			t.Errorf("collector %q left no account of itself; errors are %+v", id, fs.Errors())
		}
	}
}

// --- WP-09: error attribution and evidence ---------------------------------

// TestRunnerErrorsAreAttributedToProducedFacts is the interface-gap fix. A
// check looks up the fact it requires, never the collector that was supposed
// to produce it, so an error filed under the collector's name is an error no
// check ever sees. Before Produces() existed, a timeout on the sshd collector
// reached SSHD-0002 as "sshd.config was never collected" — still UNKNOWN, but
// UNKNOWN for the wrong reason, which sends an operator hunting a bug instead
// of raising a budget.
func TestRunnerErrorsAreAttributedToProducedFacts(t *testing.T) {
	const produced = fact.ID("kernel.params")

	cases := []struct {
		name    string
		fixture string
		want    fact.ErrorKind
		stub    stub
	}{
		{
			name:    "timeout",
			fixture: "sshd-hardened",
			want:    fact.ErrTimeout,
			stub: stub{
				id: "kernel", produces: []fact.ID{produced}, timeout: 30 * time.Millisecond,
				run: func(ctx context.Context, _ system.System, _ *fact.Set) error {
					<-ctx.Done()
					return ctx.Err()
				},
			},
		},
		{
			name:    "panic",
			fixture: "sshd-hardened",
			want:    fact.ErrInternal,
			stub: stub{
				id: "kernel", produces: []fact.ID{produced},
				run: func(context.Context, system.System, *fact.Set) error {
					panic("collector bug")
				},
			},
		},
		{
			name:    "capability shortfall",
			fixture: "sshd-unreadable", // euid 1000
			want:    fact.ErrPermission,
			stub: stub{
				id: "kernel", produces: []fact.ID{produced}, requires: collect.CapRoot,
				run: func(context.Context, system.System, *fact.Set) error { return nil },
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := collect.NewRegistry()
			r.Register(tc.stub)

			fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, tc.fixture))

			wantError(t, fs, string(produced), tc.want, "")
			if _, filed := fs.Err(fact.ID("kernel")); filed {
				t.Error("the error was also filed under the collector ID, where no check looks")
			}
		})
	}
}

// TestAttributionReachesTheCheck is what the attribution is for. A collector
// that timed out must reach a check as "could not determine", with the reason
// the operator needs, rather than as "never collected".
func TestAttributionReachesTheCheck(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{
		id:       "sshd",
		produces: []fact.ID{fact.SSHDConfigID},
		timeout:  30 * time.Millisecond,
		run: func(ctx context.Context, _ system.System, _ *fact.Set) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})

	fs := run(t, collect.Runner{Registry: r, Timeout: time.Second}, sys(t, "sshd-hardened"))

	got := catalog.MustNew(checks.Check0002).Evaluate(fs)[0]
	if got.Result != finding.Unknown {
		t.Fatalf("result = %s, want UNKNOWN", got.Result)
	}
	if got.UnknownReason == finding.ReasonFactMissing {
		t.Error("a timeout still reaches the check as 'never collected'")
	}
	if got.UnknownReason != finding.ReasonAmbiguousState {
		t.Errorf("unknown reason = %q, want %q", got.UnknownReason, finding.ReasonAmbiguousState)
	}
}

// TestCollectorDeclaredTimeoutWins: ARCHITECTURE.md says each collector
// declares its own budget, because what is pathological for a config-file read
// is normal for a filesystem walk.
func TestCollectorDeclaredTimeoutWins(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{
		id:      "impatient",
		timeout: 30 * time.Millisecond,
		run: func(ctx context.Context, _ system.System, _ *fact.Set) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})

	start := time.Now()
	// The runner's fallback is generous; the collector's own budget is not.
	fs := run(t, collect.Runner{Registry: r, Timeout: 30 * time.Second}, sys(t, "sshd-hardened"))
	elapsed := time.Since(start)

	wantError(t, fs, "impatient", fact.ErrTimeout, "budget")
	if elapsed > 5*time.Second {
		t.Errorf("the collector's own 30ms budget was ignored; the run took %s", elapsed)
	}
}

// TestReadsAreRecordedAsEvidence closes the loop the evidence store exists
// for: the collector reads a file, the runner records the bytes, the check
// cites their digest, and the digest resolves in the bundle. Any break in that
// chain leaves findings citing evidence nobody kept.
func TestReadsAreRecordedAsEvidence(t *testing.T) {
	store := bundle.NewEvidenceStore()
	r := collect.NewRegistry()
	r.Register(sshdcollector.New())

	fs := fact.NewSet()
	runner := collect.Runner{Registry: r, Timeout: 5 * time.Second, Evidence: store}
	if err := runner.Run(context.Background(), sys(t, "sshd-include"), fs); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// sshd-include is two files: the main config and the drop-in it includes.
	if got := store.Len(); got != 2 {
		t.Errorf("evidence store holds %d blobs, want 2", got)
	}

	cfg, _, ok := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID)
	if !ok {
		t.Fatal("sshd.config was not collected")
	}
	for _, f := range cfg.Files {
		sum, recorded := cfg.Digests[f]
		if !recorded {
			t.Errorf("no digest recorded for %s", f)
			continue
		}
		if _, stored := store.Get(sum); !stored {
			t.Errorf("the fact cites digest %s for %s, which the evidence store does not hold", sum, f)
		}
	}

	// And the finding cites a digest that resolves to the bytes it quotes.
	got := catalog.MustNew(checks.Check0002).Evaluate(fs)[0]
	if len(got.Evidence) == 0 {
		t.Fatal("the finding cites no evidence")
	}
	ev := got.Evidence[0]
	if ev.SHA256 == "" {
		t.Fatal("the finding cites evidence with no digest")
	}
	blob, stored := store.Get(ev.SHA256)
	if !stored {
		t.Fatalf("the finding cites digest %s, which is not in the evidence store", ev.SHA256)
	}
	if !strings.Contains(string(blob), ev.Excerpt) {
		t.Errorf("the excerpt %q is not present in the source it cites", ev.Excerpt)
	}
}

// TestOpaqueReadsAreNotRecordedAsEvidence is the other half of the rule above,
// and it exists because the exclusion is invisible by construction: nothing
// about a bundle that quietly grew by two hundred megabytes says which read
// put it there.
//
// The two reads are of the same file, so the only variable is which method the
// collector called. ReadFile stores the bytes; ReadOpaque does not, and still
// returns the digest — which is the whole point, because the digest is what a
// finding cites and what `sha256sum` on the host reproduces.
func TestOpaqueReadsAreNotRecordedAsEvidence(t *testing.T) {
	const path = "/etc/ssh/sshd_config"

	readWith := func(t *testing.T, read func(system.System) (system.ReadResult, error)) (*bundle.EvidenceStore, system.ReadResult) {
		t.Helper()
		store := bundle.NewEvidenceStore()
		var res system.ReadResult

		r := collect.NewRegistry()
		r.Register(stub{
			id:       "reader",
			produces: []fact.ID{fact.ID("test.read")},
			run: func(_ context.Context, s system.System, _ *fact.Set) error {
				var err error
				res, err = read(s)
				return err
			},
		})
		runner := collect.Runner{Registry: r, Timeout: 5 * time.Second, Evidence: store}
		if err := runner.Run(context.Background(), sys(t, "sshd-hardened"), fact.NewSet()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return store, res
	}

	recorded, viaReadFile := readWith(t, func(s system.System) (system.ReadResult, error) {
		return s.ReadFile(path, 0)
	})
	if got := recorded.Len(); got != 1 {
		t.Fatalf("ReadFile stored %d blobs, want 1; the control case is broken, so the comparison below proves nothing", got)
	}

	excluded, viaReadOpaque := readWith(t, func(s system.System) (system.ReadResult, error) {
		return s.ReadOpaque(path, 0)
	})
	if got := excluded.Len(); got != 0 {
		t.Errorf("ReadOpaque stored %d blobs, want 0; the bytes of a file read opaquely reached the bundle", got)
	}
	if got := excluded.TotalBytes(); got != 0 {
		t.Errorf("the evidence store holds %d bytes after an opaque read, want 0", got)
	}

	// Same bytes, same digest, whichever way they were read. A check citing an
	// opaque source is citing something an auditor can still verify, against
	// the host rather than against a copy this scan kept.
	if viaReadOpaque.SHA256 == "" {
		t.Error("ReadOpaque returned no digest; there would be nothing left to cite")
	}
	if viaReadOpaque.SHA256 != viaReadFile.SHA256 {
		t.Errorf("digest differs by read method: opaque %s, recorded %s", viaReadOpaque.SHA256, viaReadFile.SHA256)
	}
	if !bytes.Equal(viaReadOpaque.Data, viaReadFile.Data) {
		t.Error("ReadOpaque returned different bytes from ReadFile; the two reads must differ only in disposition")
	}
}

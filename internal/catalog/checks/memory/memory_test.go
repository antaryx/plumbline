package memory_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/memory"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/memory"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the MEMORY module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003, checks.Check0004,
}

func collectFixture(t *testing.T, name string) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	return facts
}

// evalCheck runs the real collector against a fixture and then one real check
// against the resulting facts. Tests exercise the whole vertical slice, not the
// check in isolation, because most check bugs are actually collector bugs.
func evalCheck(t *testing.T, check catalog.Check, name string) finding.Finding {
	t.Helper()

	got := catalog.MustNew(check).Evaluate(collectFixture(t, name))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

type tc struct {
	fixture  string
	result   finding.Result
	severity finding.Severity
	reason   finding.UnknownReason
	// detailContains guards against a correct verdict with a misleading
	// explanation, which is its own class of bug.
	detailContains string
}

func run(t *testing.T, check catalog.Check, cases []tc) {
	t.Helper()

	for _, c := range cases {
		t.Run(check.ID+"/"+c.fixture, func(t *testing.T) {
			got := evalCheck(t, check, c.fixture)

			if got.Result != c.result {
				t.Errorf("result = %s, want %s\n detail: %s", got.Result, c.result, got.Detail)
			}
			if c.severity != "" && got.Severity != c.severity {
				t.Errorf("severity = %s, want %s", got.Severity, c.severity)
			}
			if c.reason != "" && got.UnknownReason != c.reason {
				t.Errorf("unknown reason = %q, want %q", got.UnknownReason, c.reason)
			}
			if !strings.Contains(strings.ToLower(got.Detail), strings.ToLower(c.detailContains)) {
				t.Errorf("detail %q does not contain %q", got.Detail, c.detailContains)
			}

			if got.CheckID != check.ID || got.Module != "MEMORY" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
			if got.BaseSeverity != check.BaseSeverity {
				t.Errorf("base severity mutated: %s", got.BaseSeverity)
			}
			if got.Fingerprint == "" {
				t.Error("fingerprint is empty")
			}
			if got.Result == finding.Unknown && got.UnknownReason == "" {
				t.Error("UNKNOWN without a reason code")
			}
			if got.Result == finding.Fail && got.Remediation == nil {
				t.Error("FAIL without remediation")
			}
			if got.Result != finding.Fail && got.Remediation != nil {
				t.Error("remediation attached to a non-FAIL result")
			}
			if (got.Result == finding.Fail || got.Result == finding.Unknown) && len(got.Evidence) == 0 {
				t.Errorf("%s carries no evidence; a verdict an auditor cannot follow up is not actionable", got.Result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCheck0001PIE(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "memory-hardened", result: finding.Pass, detailContains: "position-independent"},
		{fixture: "memory-nopie", result: finding.Fail, severity: finding.Medium, detailContains: "/usr/bin/sudo"},
		{fixture: "memory-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be examined"},
		// The asymmetry: one offender found, one binary unreadable. The
		// offender is still an offender.
		{fixture: "memory-nopie-denied", result: finding.Fail, severity: finding.Medium, detailContains: "may be incomplete"},
		{fixture: "memory-absent", result: finding.NotApplicable, detailContains: "nothing to report"},
		// A stripped image still answers the PIE question: the ELF type is in
		// the header, not the symbol table.
		{fixture: "memory-stripped", result: finding.Pass, detailContains: "position-independent"},
		{fixture: "memory-wrapper", result: finding.Pass, detailContains: "position-independent"},
	})
}

func TestCheck0002FullRELRO(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "memory-hardened", result: finding.Pass, detailContains: "full relro"},
		// Partial RELRO with lazy binding. The segment is present and the GOT
		// is still writable, which is exactly what "partial" means.
		{fixture: "memory-lazy-binding", result: finding.Fail, severity: finding.Medium, detailContains: "/usr/bin/sudo"},
		{fixture: "memory-nopie", result: finding.Fail, severity: finding.Medium, detailContains: "relocation table"},
		{fixture: "memory-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be examined"},
		{fixture: "memory-absent", result: finding.NotApplicable, detailContains: "dynamically linked"},
		// Statically linked: no relocation table to protect, so the property
		// does not arise rather than failing.
		{fixture: "memory-static", result: finding.NotApplicable, detailContains: "dynamically linked"},
		// Stripped changes nothing here: RELRO and BIND_NOW come from program
		// headers and the dynamic section, neither of which stripping removes.
		{fixture: "memory-stripped", result: finding.Pass, detailContains: "full relro"},
	})
}

func TestCheck0003StackProtection(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "memory-hardened", result: finding.Pass, detailContains: "__stack_chk_fail"},
		{fixture: "memory-nocanary", result: finding.Fail, severity: finding.Medium, detailContains: "/usr/bin/sudo"},
		{fixture: "memory-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be examined"},
		{fixture: "memory-absent", result: finding.NotApplicable, detailContains: "nothing to report"},
		// The silence that is not an absence: no symbol table means no
		// evidence either way, which is UNKNOWN and never FAIL.
		{fixture: "memory-stripped", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "no symbol table"},
		// .symtab is where an unstripped static binary keeps its symbols.
		// Reading only .dynsym would report this as stripped.
		{fixture: "memory-static", result: finding.Pass, detailContains: "__stack_chk_fail"},
	})
}

func TestCheck0004Fortify(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "memory-hardened", result: finding.Pass, detailContains: "_chk"},
		{fixture: "memory-nofortify", result: finding.Fail, severity: finding.Low, detailContains: "/usr/bin/sudo"},
		{fixture: "memory-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be examined"},
		// Calls nothing the option could substitute. Not a failure: there is
		// no call for _FORTIFY_SOURCE to have changed.
		{fixture: "memory-nothing-to-fortify", result: finding.NotApplicable, detailContains: "would make no difference"},
		{fixture: "memory-absent", result: finding.NotApplicable, detailContains: "would make no difference"},
		{fixture: "memory-stripped", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "no symbol table"},
		{fixture: "memory-static", result: finding.Pass, detailContains: "_chk"},
	})
}

// ---------------------------------------------------------------------------
// module-wide invariants
// ---------------------------------------------------------------------------

// TestCompliantHostPassesEveryCheck is the fixture-coverage backstop. A check
// added without a correct value in memory-hardened fails here immediately,
// which is a better error than discovering later that the good-case fixture
// never satisfied it.
func TestCompliantHostPassesEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "memory-hardened")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over memory-hardened, want PASS. Either the check is wrong or the fixture is missing its correct value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestAbsentBinariesAreNotApplicableEverywhere. A host without these binaries
// has not satisfied the control; it has removed the subject of the sentence.
// PASS would inflate the posture score with a control never tested.
func TestAbsentBinariesAreNotApplicableEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "memory-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over memory-absent, want NOT_APPLICABLE: %s", check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnreadableBinariesNeverProduceAPass is the module's central property and
// the reason memory-denied exists. Every binary in that fixture is fully
// hardened on disk and none can be read: a PASS would be a verdict drawn from
// files the scan never opened, which is the failure CONTRIBUTING.md rule 3
// exists to prevent.
func TestUnreadableBinariesNeverProduceAPass(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "memory-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over memory-denied, want UNKNOWN: %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q; re-running as root is the action and the code has to say so",
				check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestAStrippedImageNeverFailsASymbolCheck is the symbol half of the same
// property. A stripped binary has no symbol table to be absent from, so
// "no __stack_chk_fail" is not evidence of anything. Reporting FAIL there
// would condemn a hardened binary for having nothing to look at, and it is a
// mistake that only shows up on the binaries distributions actually ship —
// every one of which is stripped of .symtab.
func TestAStrippedImageNeverFailsASymbolCheck(t *testing.T) {
	for _, check := range []catalog.Check{checks.Check0003, checks.Check0004} {
		got := evalCheck(t, check, "memory-stripped")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over memory-stripped, want UNKNOWN: %s", check.ID, got.Result, got.Detail)
		}
		if !strings.Contains(got.Detail, "no symbol table") {
			t.Errorf("%s does not say why it cannot tell: %s", check.ID, got.Detail)
		}
	}

	// The two header-derived checks are unaffected: stripping removes symbols,
	// not program headers.
	for _, check := range []catalog.Check{checks.Check0001, checks.Check0002} {
		if got := evalCheck(t, check, "memory-stripped"); got.Result != finding.Pass {
			t.Errorf("%s = %s over memory-stripped, want PASS; stripping does not remove program headers: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestFailOutranksUnknownEverywhere. An incomplete examination can invalidate a
// negative result and can never invalidate a positive one (ADR-0014). A binary
// that was read and violates the property still violates it whatever the
// unreadable ones turn out to be, and degrading to UNKNOWN would discard a
// finding this scan actually made.
func TestFailOutranksUnknownEverywhere(t *testing.T) {
	got := evalCheck(t, checks.Check0001, "memory-nopie-denied")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s over memory-nopie-denied, want FAIL: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "may be incomplete") {
		t.Errorf("a FAIL drawn from a partial examination does not say so: %s", got.Detail)
	}
}

// TestFailNamesTheOffenderNotTheCount. A report that says "2 binaries are not
// hardened" makes the operator re-derive which, and a report that makes
// somebody re-derive its own conclusion is one they stop reading.
func TestFailNamesTheOffenderNotTheCount(t *testing.T) {
	cases := []struct {
		check   catalog.Check
		fixture string
	}{
		{checks.Check0001, "memory-nopie"},
		{checks.Check0002, "memory-lazy-binding"},
		{checks.Check0003, "memory-nocanary"},
		{checks.Check0004, "memory-nofortify"},
	}

	for _, c := range cases {
		t.Run(c.check.ID, func(t *testing.T) {
			got := evalCheck(t, c.check, c.fixture)
			if got.Result != finding.Fail {
				t.Fatalf("result = %s over %s, want FAIL: %s", got.Result, c.fixture, got.Detail)
			}
			if !strings.Contains(got.Detail, "/usr/bin/sudo") {
				t.Errorf("detail does not name the offending binary: %s", got.Detail)
			}
			if got.Subject != "/usr/bin/sudo" {
				t.Errorf("subject = %q, want the offender; the fingerprint is built from it", got.Subject)
			}

			// Asserted over Evidence rather than the detail string, because the
			// paths overlap: /usr/bin/su is a prefix of /usr/bin/sudo, so a
			// substring search over prose reports an innocent binary.
			cited := map[string]bool{}
			for _, ev := range got.Evidence {
				cited[ev.Source] = true
			}
			for _, innocent := range []string{"/usr/bin/su", "/usr/bin/passwd", "/usr/sbin/sshd"} {
				if cited[innocent] {
					t.Errorf("evidence cites %s, which satisfies this check", innocent)
				}
			}
			if !cited["/usr/bin/sudo"] {
				t.Errorf("evidence does not cite the offender; it cites %v", got.Evidence)
			}
		})
	}
}

// TestEvidenceCitesADigestItDoesNotStore. Binary bytes are read through the
// seam's opaque path and never enter the evidence store, so citing them in
// Evidence.SHA256 would send an auditor looking for a blob nobody kept. The
// digest belongs in the excerpt, where `sha256sum` on the host reproduces it.
func TestEvidenceCitesADigestItDoesNotStore(t *testing.T) {
	got := evalCheck(t, checks.Check0001, "memory-nopie")

	for _, ev := range got.Evidence {
		if ev.SHA256 != "" {
			t.Errorf("evidence for %s carries SHA256 %q, which is not in the evidence store", ev.Source, ev.SHA256)
		}
		if !strings.Contains(ev.Excerpt, "sha256 ") {
			t.Errorf("evidence excerpt for %s does not carry the digest an operator can verify: %q", ev.Source, ev.Excerpt)
		}
	}
}

// TestATruncatedProbeCannotPass. The collector stopped early, so the targets it
// never reached are absent from the fact. Absence there means "never looked
// at", and a negative claim over what was never looked at is not PASS.
func TestATruncatedProbeCannotPass(t *testing.T) {
	facts := collectFixture(t, "memory-hardened")
	h, _, ok := fact.Get[fact.ELFHardening](facts, fact.ELFHardeningID)
	if !ok {
		t.Fatal("memory.elf was not collected")
	}
	for _, check := range all {
		if got := catalog.MustNew(check).Evaluate(facts)[0]; got.Result != finding.Pass {
			t.Fatalf("%s is %s over the untruncated fixture, not PASS; the comparison below proves nothing", check.ID, got.Result)
		}
	}

	h.Truncated = true
	facts.Put(h)

	for _, check := range all {
		got := catalog.MustNew(check).Evaluate(facts)[0]
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over a truncated probe, want UNKNOWN: %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonTruncated {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonTruncated)
		}
	}
}

// TestMissingFactResolvesToUnknown. The runner is what turns a missing required
// fact into UNKNOWN, and this asserts every check declared the dependency that
// makes it happen. A check naming the wrong fact ID would evaluate against a
// zero value and report over a host nobody looked at.
func TestMissingFactResolvesToUnknown(t *testing.T) {
	for _, check := range all {
		got := catalog.MustNew(check).Evaluate(fact.NewSet())
		if len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", check.ID, len(got))
		}
		if got[0].Result != finding.Unknown {
			t.Errorf("%s = %s with no facts at all, want UNKNOWN", check.ID, got[0].Result)
		}
		if got[0].UnknownReason != finding.ReasonFactMissing {
			t.Errorf("%s reason = %q, want %q", check.ID, got[0].UnknownReason, finding.ReasonFactMissing)
		}
	}
}

// TestChecksAreIndependent. Each fixture breaks exactly one property, so each
// must fail exactly one check. A check that failed on a fixture built to break
// a different property is reading a field it does not own — the bug that turns
// four checks into one noisy one.
func TestChecksAreIndependent(t *testing.T) {
	cases := map[string]string{
		"memory-lazy-binding": "MEMORY-0002",
		"memory-nocanary":     "MEMORY-0003",
		"memory-nofortify":    "MEMORY-0004",
	}

	for fixture, wantFail := range cases {
		t.Run(fixture, func(t *testing.T) {
			for _, check := range all {
				got := evalCheck(t, check, fixture)
				switch {
				case check.ID == wantFail && got.Result != finding.Fail:
					t.Errorf("%s = %s, want FAIL: %s", check.ID, got.Result, got.Detail)
				case check.ID != wantFail && got.Result == finding.Fail:
					t.Errorf("%s also failed on a fixture built to break %s; it is reading a property it does not own: %s",
						check.ID, wantFail, got.Detail)
				}
			}
		})
	}
}

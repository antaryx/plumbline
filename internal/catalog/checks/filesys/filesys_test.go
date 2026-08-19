package filesys_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/filesys"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/collect/walker"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the FILESYS module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003,
	checks.Check0004, checks.Check0005, checks.Check0006,
	checks.Check0007, checks.Check0008, checks.Check0009,
}

// inodeChecks are the six that rest on the traversal. The three mount checks
// read the mount table instead and are unaffected by a truncated walk, which
// is why the truncation test names these explicitly rather than looping over
// everything.
var inodeChecks = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003,
	checks.Check0004, checks.Check0005, checks.Check0006,
}

var mountChecks = []catalog.Check{checks.Check0007, checks.Check0008, checks.Check0009}

// collectFixture runs the real shared walk over a fixture, with the real
// interests the filesys package registered at init.
func collectFixture(t *testing.T, name string, cfg walker.Config) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	c := walker.New()
	if cfg.MaxInodes > 0 || cfg.MaxDepth > 0 {
		c = walker.NewWithConfig(cfg)
	}
	if err := c.Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	return facts
}

// evalCheck runs the real walk against a fixture and then one real check
// against the resulting facts. Tests exercise the whole vertical slice, not
// the check in isolation, because most check bugs are actually collector bugs.
func evalCheck(t *testing.T, check catalog.Check, name string) finding.Finding {
	t.Helper()
	return evalCheckWith(t, check, name, walker.Config{})
}

func evalCheckWith(t *testing.T, check catalog.Check, name string, cfg walker.Config) finding.Finding {
	t.Helper()

	got := catalog.MustNew(check).Evaluate(collectFixture(t, name, cfg))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// ---------------------------------------------------------------------------
// the truncation rule — written first, per BUILD-RUNBOOK-v0.2.md WP-23
// ---------------------------------------------------------------------------

// TestTruncatedWalkMakesEveryAbsenceClaimUnknown is the acceptance criterion
// for this whole module.
//
//	A truncated walk can invalidate a negative result.
//	It can never invalidate a positive one.
//
// filesys-truncated violates nothing. Over a complete walk every inode check
// passes it. Over a walk cut short by the inode budget, every one of them must
// return UNKNOWN(source_truncated) instead — because the claim each makes is
// about everything the traversal never reached, and PASS would convert "we
// stopped looking" into "there is nothing there". That is the single failure
// mode this project exists to prevent.
func TestTruncatedWalkMakesEveryAbsenceClaimUnknown(t *testing.T) {
	// Sanity first: over a complete walk this fixture is clean. Without this
	// half, a check that returned UNKNOWN unconditionally would pass the test
	// below while being useless.
	for _, check := range inodeChecks {
		if got := evalCheck(t, check, "filesys-truncated"); got.Result != finding.Pass {
			t.Fatalf("%s = %s over a COMPLETE walk of filesys-truncated, want PASS — the fixture is supposed to violate nothing:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}

	// Now cut the walk short and require every one of them to refuse.
	capped := walker.Config{MaxInodes: 4}
	for _, check := range inodeChecks {
		got := evalCheckWith(t, check, "filesys-truncated", capped)

		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over a TRUNCATED walk, want UNKNOWN — a partial traversal cannot prove an absence:\n  %s",
				check.ID, got.Result, got.Detail)
			continue
		}
		if got.UnknownReason != finding.ReasonTruncated {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonTruncated)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s: UNKNOWN with no evidence; an operator cannot tell which limit fired", check.ID)
		}
		if !strings.Contains(strings.ToLower(got.Detail), "did not finish") {
			t.Errorf("%s detail does not say the walk was incomplete: %s", check.ID, got.Detail)
		}
	}
}

// TestATruncatedWalkStillReportsWhatItFound is the other half of the rule, and
// the half that is easy to lose by gating too early. A SUID binary the walk
// found is a SUID binary that exists; stopping the traversal afterwards cannot
// unmake it. A check that returned UNKNOWN here would be suppressing a real
// finding out of misplaced caution.
func TestATruncatedWalkStillReportsWhatItFound(t *testing.T) {
	// A budget large enough to reach the offending inode and small enough to
	// truncate the walk. filesys-suid-outside carries three setuid files.
	capped := walker.Config{MaxInodes: 12}
	facts := collectFixture(t, "filesys-suid-outside", capped)

	suid, _, _ := fact.Get[fact.FSMatches](facts, fact.FSFactID("suid"))
	if suid.Complete() {
		t.Skip("the budget did not truncate this walk; the test cannot say anything")
	}
	if len(suid.Rows) == 0 {
		t.Skip("the truncated walk reached no setuid file; nothing positive to report")
	}

	got := catalog.MustNew(checks.Check0002).Evaluate(facts)[0]
	if got.Result != finding.Fail {
		t.Errorf("FILESYS-0002 = %s over a truncated walk that DID find a setuid binary outside the system directories, want FAIL. A partial walk invalidates absence, never presence:\n  %s",
			got.Result, got.Detail)
	}
}

// ---------------------------------------------------------------------------
// table harness
// ---------------------------------------------------------------------------

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

			if got.CheckID != check.ID || got.Module != "FILESYS" {
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
// module-wide invariants
// ---------------------------------------------------------------------------

// TestCleanHostPassesEveryCheck is the fixture-coverage backstop. A check added
// without a correct value in filesys-clean fails here immediately, which is a
// far better error than discovering later that the good-case fixture never
// satisfied it.
func TestCleanHostPassesEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "filesys-clean")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over filesys-clean, want PASS. Either the check is wrong or the fixture is missing its correct value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnreadableMountTableIsUnknownForEveryMountCheck: a table we could not
// read is not a table with nothing in it, and the two conclusions lead to
// opposite actions.
func TestUnreadableMountTableIsUnknownForEveryMountCheck(t *testing.T) {
	for _, check := range mountChecks {
		got := evalCheck(t, check, "filesys-mounts-unknown")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over an unreadable mount table, want UNKNOWN:\n  %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonTruncated {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonTruncated)
		}
	}
}

// TestEveryCheckIsRegisteredAtCatalogEleven guards the one piece of metadata a
// reviewer cannot see from the diff: a check whose SinceCatalog is wrong claims
// to have existed in a version that never shipped it, and suppression files
// written against that version silently do not match.
func TestEveryCheckIsRegisteredAtCatalogEleven(t *testing.T) {
	for _, check := range all {
		if check.SinceCatalog != 11 {
			t.Errorf("%s SinceCatalog = %d, want 11", check.ID, check.SinceCatalog)
		}
		if len(check.Requires) == 0 {
			t.Errorf("%s declares no required facts", check.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCheck0001(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "writable by their owner alone"},
		{fixture: "filesys-suid-writable", result: finding.Fail, severity: finding.Critical,
			detailContains: "/opt/vendor/helper"},
		// Owned by root and mode 4755: not writable by anyone else, so this
		// check correctly stays quiet and 0002 does the reporting.
		{fixture: "filesys-suid-outside", result: finding.Pass, detailContains: "setuid and setgid"},
	})
}

func TestCheck0002(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "package manager installs into"},
		{fixture: "filesys-suid-outside", result: finding.Fail, severity: finding.High,
			detailContains: "/home/alice/.cache-helper"},
		// /opt is a directory a package manager installs into, so a setuid
		// binary there is not this check's finding even though it is 0001's.
		{fixture: "filesys-suid-writable", result: finding.Pass, detailContains: "package manager"},
	})
}

func TestCheck0003(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "no world-writable file"},
		{fixture: "filesys-world-writable", result: finding.Fail, severity: finding.High,
			detailContains: "/opt/app/config.env"},
	})
}

func TestCheck0004(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "sticky bit"},
		{fixture: "filesys-sticky", result: finding.Fail, severity: finding.Medium,
			detailContains: "/var/spool/upload"},
		// World-writable AND sticky: 0004 is satisfied, and 0005 is not.
		{fixture: "filesys-system-dir", result: finding.Pass, detailContains: "sticky bit"},
	})
}

func TestCheck0005(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "no directory the operating system depends on"},
		{fixture: "filesys-system-dir", result: finding.Fail, severity: finding.Critical,
			detailContains: "/etc/cron.d"},
		// /var/spool/upload is not a system directory, so the missing sticky
		// bit is 0004's finding and not this one's.
		{fixture: "filesys-sticky", result: finding.Pass, detailContains: "world-writable"},
	})
}

func TestCheck0006(t *testing.T) {
	run(t, checks.Check0006, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "no block or character device node"},
		{fixture: "filesys-device", result: finding.Fail, severity: finding.High,
			detailContains: "/var/tmp/.hidden-disk"},
	})
}

func TestCheck0007(t *testing.T) {
	run(t, checks.Check0007, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "separate tmpfs mount"},
		{fixture: "filesys-mounts-weak", result: finding.Fail, severity: finding.Medium,
			detailContains: "not a separate mount"},
		{fixture: "filesys-mounts-unknown", result: finding.Unknown, reason: finding.ReasonTruncated,
			detailContains: "could not be read"},
	})
}

func TestCheck0008(t *testing.T) {
	run(t, checks.Check0008, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "/dev/shm"},
		{fixture: "filesys-mounts-weak", result: finding.Fail, severity: finding.Medium,
			detailContains: "noexec"},
		{fixture: "filesys-mounts-unknown", result: finding.Unknown, reason: finding.ReasonTruncated,
			detailContains: "mount table"},
	})
}

func TestCheck0009(t *testing.T) {
	run(t, checks.Check0009, []tc{
		{fixture: "filesys-clean", result: finding.Pass, detailContains: "/home"},
		{fixture: "filesys-mounts-weak", result: finding.Fail, severity: finding.Low,
			detailContains: "nodev and nosuid"},
		{fixture: "filesys-mounts-unknown", result: finding.Unknown, reason: finding.ReasonTruncated,
			detailContains: "mount table"},
	})
}

// TestHomeObservesNoexecRatherThanRequiringIt.
//
// Enforcing noexec on /home breaks virtualenvs, local Go and Rust builds,
// node_modules with native binaries and every ~/.local/bin on the host — which
// is most of what a developer workstation exists to do. CIS treats it as a
// separate, stricter item for that reason. A check whose right answer is to
// ignore it teaches people to ignore the next one, so /home reports noexec and
// fails only on nodev and nosuid.
func TestHomeObservesNoexecRatherThanRequiringIt(t *testing.T) {
	got := evalCheck(t, checks.Check0009, "filesys-clean")
	if got.Result != finding.Pass {
		t.Fatalf("FILESYS-0009 = %s over a /home with nodev,nosuid and no noexec, want PASS: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "noexec") {
		t.Errorf("the detail does not mention noexec at all; it is supposed to be observed:\n  %s", got.Detail)
	}
	// /tmp, by contrast, does require it.
	if got := evalCheck(t, checks.Check0007, "filesys-mounts-weak"); got.Result != finding.Fail {
		t.Errorf("FILESYS-0007 = %s, want FAIL: /tmp requires noexec even though /home does not", got.Result)
	}
}

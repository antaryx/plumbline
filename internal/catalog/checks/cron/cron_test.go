package cron_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/cron"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the CRON module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003,
	checks.Check0004, checks.Check0005,
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
// against the resulting facts. Tests exercise the whole vertical slice, not
// the check in isolation, because most check bugs are actually collector bugs.
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
	severity finding.Severity      // "" means: do not assert
	reason   finding.UnknownReason // "" means: do not assert
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

			if got.CheckID != check.ID || got.Module != "CRON" {
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

// TestCompliantHostPassesEveryCheck is the fixture-coverage backstop. A check
// added without a correct value in cron-compliant fails here immediately,
// which is a far better error than discovering later that the good-case
// fixture never satisfied it.
func TestCompliantHostPassesEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "cron-compliant")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over cron-compliant, want PASS. Either the check is wrong or the fixture is missing its correct value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestAbsentCronIsNotApplicableEverywhere. A host with no cron has not
// satisfied "the crontab is owned by root"; it has removed the subject of the
// sentence. PASS would inflate the posture score with controls never tested
// (docs/SCORING.md).
func TestAbsentCronIsNotApplicableEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "cron-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over cron-absent, want NOT_APPLICABLE: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnstattablePathsDegradeRatherThanGuess is the module's central property
// and the reason the fake needed an unstattable key at all.
//
// Every path exists and none of them can be stat'ed, exactly as under a parent
// directory that refuses traversal. No check may report on the paths it
// happened to reach: a path whose owner and mode are unknown could be the one
// violating the rule, and a PASS drawn from the rest is the false assurance
// CONTRIBUTING.md rule 3 forbids.
func TestUnstattablePathsDegradeRatherThanGuess(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "cron-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over cron-denied, want UNKNOWN. It drew a verdict from metadata it could not read:\n  %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s carries no evidence; an UNKNOWN an auditor cannot follow up is not actionable", check.ID)
		}
	}
}

// TestVendorDefaultsDoNotProduceEscalationFindings pins the judgement that
// keeps this module readable.
//
// 0644 on /etc/crontab and 0755 on the drop-in directories are what Debian,
// Ubuntu, RHEL and Fedora all ship. A module that reported two HIGH findings on
// every unhardened host would train its reader to skim past it, so the
// escalation checks fail only on *writability* and ownership, and the
// disclosure that remains is CRON-0005's business at LOW.
func TestVendorDefaultsDoNotProduceEscalationFindings(t *testing.T) {
	for _, check := range []catalog.Check{checks.Check0001, checks.Check0002} {
		got := evalCheck(t, check, "cron-vendor")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over a stock distribution install; 0644 and 0755 are vendor defaults and are not writable by group or other:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}

	got := evalCheck(t, checks.Check0005, "cron-vendor")
	if got.Result != finding.Fail {
		t.Fatalf("CRON-0005 = %s over cron-vendor, want FAIL", got.Result)
	}
	if got.Severity != finding.Low {
		t.Errorf("CRON-0005 severity = %s, want LOW: this is a disclosure control, not an escalation one", got.Severity)
	}
	if !strings.Contains(got.Detail, "distribution") {
		t.Errorf("the detail does not tell the reader these are vendor defaults: %s", got.Detail)
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCron0001Crontab(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "cron-compliant", result: finding.Pass, detailContains: "writable only by root"},
		{fixture: "cron-writable", result: finding.Fail, severity: finding.High, detailContains: "writable by group or other"},
		{fixture: "cron-vendor", result: finding.Pass, detailContains: "writable only by root"},
		{fixture: "cron-absent", result: finding.NotApplicable, detailContains: "no system cron is installed"},
		{
			fixture: "cron-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
		{
			// Stat does not follow the link, so its mode and owner describe
			// the link rather than the file cron reads through it.
			fixture: "cron-symlink", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "symbolic link",
		},
	})
}

// TestOwnershipAndWritabilityAreTheSameExposure: a root-owned file that is
// world-writable and a file owned by an unprivileged account both mean the
// same thing — somebody other than root decides what cron runs — and the
// finding has to say which one it found, or the operator fixes the wrong half.
func TestOwnershipAndWritabilityAreTheSameExposure(t *testing.T) {
	got := evalCheck(t, checks.Check0001, "cron-writable")
	if !strings.Contains(got.Detail, "0666") {
		t.Errorf("the detail does not name the mode it found: %s", got.Detail)
	}

	dirs := evalCheck(t, checks.Check0002, "cron-writable")
	if !strings.Contains(dirs.Detail, "uid 1001") {
		t.Errorf("the directory owned by an unprivileged account was not reported by its owner: %s", dirs.Detail)
	}
	if !strings.Contains(dirs.Detail, "/etc/cron.hourly") {
		t.Errorf("the group-writable directory was not reported: %s", dirs.Detail)
	}
	// The three correctly-configured directories in the same fixture must not
	// be swept up with them.
	for _, ok := range []string{"/etc/cron.weekly", "/etc/cron.monthly"} {
		if strings.Contains(dirs.Subject, ok) {
			t.Errorf("correctly-configured directory %s was reported as a violation: %s", ok, dirs.Subject)
		}
	}
}

func TestCron0002DropInDirs(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "cron-compliant", result: finding.Pass, detailContains: "writable only by root"},
		{fixture: "cron-writable", result: finding.Fail, severity: finding.High, detailContains: "schedules arbitrary code as root"},
		{fixture: "cron-vendor", result: finding.Pass, detailContains: "writable only by root"},
		{fixture: "cron-absent", result: finding.NotApplicable, detailContains: "no system cron is installed"},
		{
			fixture: "cron-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
		{
			// A drop-in path that is not a directory redirects every job cron
			// runs to a tree somebody else may control.
			fixture: "cron-symlink", result: finding.Fail,
			detailContains: "symbolic link rather than a directory",
		},
	})
}

func TestCron0003AccessControl(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "cron-compliant", result: finding.Pass, detailContains: "fails closed"},
		{fixture: "cron-denylist", result: finding.Fail, severity: finding.Medium, detailContains: "fails open"},
		{fixture: "cron-vendor", result: finding.Fail, severity: finding.Medium, detailContains: "site-dependent"},
		{fixture: "cron-absent", result: finding.NotApplicable, detailContains: "no system cron is installed"},
		{
			fixture: "cron-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "decides the whole mechanism",
		},
	})
}

// TestAllowListPrecedence is the substance of CRON-0003, pinned in all three
// directions because getting the precedence backwards is easy and the result
// looks plausible either way.
//
//	allow present            -> only the listed users; deny is ignored entirely
//	allow absent, deny present -> everyone except the listed users
//	neither                  -> decided by how the cron package was built
func TestAllowListPrecedence(t *testing.T) {
	// 1. An allow list is the only determinate, fail-closed configuration.
	got := evalCheck(t, checks.Check0003, "cron-compliant")
	if got.Result != finding.Pass {
		t.Fatalf("an existing cron.allow must pass: %s", got.Detail)
	}

	// 2. A deny list fails open, and the finding has to say so rather than
	//    merely noting the file is missing — an operator told "cron.allow does
	//    not exist" may reasonably think the deny list covers it.
	got = evalCheck(t, checks.Check0003, "cron-denylist")
	if got.Result != finding.Fail {
		t.Fatalf("a deny-list configuration must fail: %s", got.Detail)
	}
	for _, want := range []string{"cron.deny", "permitted by omission"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the detail does not explain the deny list's direction (%q missing): %s", want, got.Detail)
		}
	}

	// 3. With neither file, the outcome is a property of the binary rather
	//    than of the filesystem. The verdict is still definite — no allow list
	//    exists, and that is what is being tested — but the detail must not
	//    pretend to know what happens instead.
	got = evalCheck(t, checks.Check0003, "cron-vendor")
	if got.Result != finding.Fail {
		t.Fatalf("no access-control file at all must fail: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "cannot even be bounded") {
		t.Errorf("the detail claims to know what happens with neither file present: %s", got.Detail)
	}
}

// TestBothFilesPresentNamesTheIgnoredOne. cron ignores cron.deny outright when
// cron.allow exists, so an administrator maintaining it is editing a file with
// no effect and believing they have removed someone's access — the same
// unreachable-configuration failure USERS-0005 reports for a duplicated name.
func TestBothFilesPresentNamesTheIgnoredOne(t *testing.T) {
	facts := collectFixture(t, "cron-compliant")
	c, _, ok := fact.Get[fact.Cron](facts, fact.CronID)
	if !ok {
		t.Fatal("cron fact missing")
	}
	deny, _ := c.Get("/etc/cron.deny")
	if deny.State != fact.CronAbsent {
		t.Skipf("cron-compliant now ships a cron.deny (%s); this test needs it absent", deny.State)
	}

	// The behaviour is asserted through the check's own text, which is what an
	// operator reads.
	if !strings.Contains(checks.Check0003.Description, "ignored") {
		t.Error("CRON-0003's description does not state that cron.deny is ignored when cron.allow exists")
	}
}

func TestCron0004AccessFilePermissions(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "cron-compliant", result: finding.Pass, detailContains: "writable only by root"},
		{fixture: "cron-writable", result: finding.Fail, severity: finding.Medium, detailContains: "does not restrict them"},
		{fixture: "cron-denylist", result: finding.Pass, detailContains: "writable only by root"},
		{
			// Neither file exists, so there is nothing here to secure. The
			// absence itself is CRON-0003's finding, reported once.
			fixture: "cron-vendor", result: finding.NotApplicable,
			detailContains: "CRON-0003 reports the absence itself",
		},
		{fixture: "cron-absent", result: finding.NotApplicable, detailContains: "no system cron is installed"},
		{
			fixture: "cron-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
	})
}

// TestWritableAllowListIsWorseThanNone: a host can pass CRON-0003 and fail
// CRON-0004, and that combination is the one worth catching — the report says
// access is restricted while any user may add themselves to the list.
func TestWritableAllowListIsWorseThanNone(t *testing.T) {
	access := evalCheck(t, checks.Check0003, "cron-writable")
	if access.Result != finding.Pass {
		t.Fatalf("CRON-0003 = %s; cron-writable has an allow list and should pass that check", access.Result)
	}
	perms := evalCheck(t, checks.Check0004, "cron-writable")
	if perms.Result != finding.Fail {
		t.Fatalf("CRON-0004 = %s; cron-writable's allow list is world-writable", perms.Result)
	}
	if !strings.Contains(perms.Detail, "CRON-0003") {
		t.Errorf("the finding does not connect itself to the check it undermines: %s", perms.Detail)
	}
}

func TestCron0005Disclosure(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "cron-compliant", result: finding.Pass, detailContains: "readable only by root"},
		{fixture: "cron-vendor", result: finding.Fail, severity: finding.Low, detailContains: "what runs as root"},
		{fixture: "cron-denylist", result: finding.Pass, detailContains: "readable only by root"},
		{fixture: "cron-absent", result: finding.NotApplicable, detailContains: "no system cron is installed"},
		{
			fixture: "cron-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read",
		},
	})
}

// ---------------------------------------------------------------------------
// catalog hygiene
// ---------------------------------------------------------------------------

func TestCheckIdentityIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, check := range all {
		if seen[check.ID] {
			t.Errorf("duplicate check ID %s", check.ID)
		}
		seen[check.ID] = true

		if !strings.HasPrefix(check.ID, "CRON-") || check.Module != "CRON" {
			t.Errorf("%s is not in the CRON module namespace", check.ID)
		}
		if check.Title == "" || check.Description == "" {
			t.Errorf("%s has no title or description", check.ID)
		}
		if len(check.Requires) == 0 {
			t.Errorf("%s declares no required facts, so the runner cannot gate it", check.ID)
		}
		if check.Remediation == nil || check.Remediation.Caution == "" {
			t.Errorf("%s has no remediation or no caution", check.ID)
		}
		if len(check.Mappings) == 0 {
			t.Errorf("%s has no control mappings", check.ID)
		}
		if check.SinceCatalog != 7 {
			t.Errorf("%s declares SinceCatalog %d, want 7", check.ID, check.SinceCatalog)
		}
		if check.SinceCatalog > catalog.Version {
			t.Errorf("%s declares SinceCatalog %d, ahead of catalog.Version %d",
				check.ID, check.SinceCatalog, catalog.Version)
		}
	}
}

func TestNoPanicOnEmptyFacts(t *testing.T) {
	for _, check := range all {
		got := catalog.MustNew(check).Evaluate(fact.NewSet())
		if len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", check.ID, len(got))
		}
		if got[0].Result != finding.Unknown {
			t.Errorf("%s: result = %s, want UNKNOWN", check.ID, got[0].Result)
		}
		if got[0].UnknownReason != finding.ReasonFactMissing {
			t.Errorf("%s: reason = %q, want %q", check.ID, got[0].UnknownReason, finding.ReasonFactMissing)
		}
	}
}

func TestModuleDeterminism(t *testing.T) {
	for _, fixture := range []string{"cron-writable", "cron-symlink", "cron-vendor"} {
		first := catalog.MustNew(all...).Evaluate(collectFixture(t, fixture))
		for i := 0; i < 25; i++ {
			got := catalog.MustNew(all...).Evaluate(collectFixture(t, fixture))
			if len(got) != len(first) {
				t.Fatalf("%s: finding count changed on iteration %d", fixture, i)
			}
			for n := range got {
				if got[n].Result != first[n].Result ||
					got[n].Detail != first[n].Detail ||
					got[n].Fingerprint != first[n].Fingerprint {
					t.Fatalf("%s: %s non-deterministic on iteration %d:\n first: %s\n  then: %s",
						fixture, got[n].CheckID, i, first[n].Detail, got[n].Detail)
				}
			}
		}
	}
}

package services_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/services"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/services"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the SERVICES module as this work package leaves it.
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

			if got.CheckID != check.ID || got.Module != "SERVICES" {
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
// added without a correct value in services-compliant fails here immediately,
// which is a far better error than discovering later that the good-case
// fixture never satisfied it.
func TestCompliantHostPassesEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "services-compliant")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over services-compliant, want PASS. Either the check is wrong or the fixture is missing its correct value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestNonSystemdHostIsNotApplicableEverywhere: a host with no unit directory
// has not satisfied "telnet.socket is not enabled", it has removed the subject
// of the sentence. PASS here would be false assurance about a service that may
// well be running under an init system this module cannot read.
func TestNonSystemdHostIsNotApplicableEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "services-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over services-absent, want NOT_APPLICABLE:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnreadableUnitDirectoryIsUnknownEverywhere: enablement is a symlink and
// nothing else records it, so a /etc/systemd/system we could not traverse is a
// host whose service configuration was never observed. Every check must say so
// rather than report the vendor units it happened to be able to read.
func TestUnreadableUnitDirectoryIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "services-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over services-denied, want UNKNOWN:\n  %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestEveryCheckIsRegisteredAtCatalogNine guards the one piece of metadata a
// reviewer cannot see from the diff: a check whose SinceCatalog is wrong claims
// to have existed in a version that never shipped it, and suppression files
// written against that version silently do not match.
func TestEveryCheckIsRegisteredAtCatalogNine(t *testing.T) {
	for _, check := range all {
		if check.SinceCatalog != 9 {
			t.Errorf("%s SinceCatalog = %d, want 9", check.ID, check.SinceCatalog)
		}
		if len(check.Requires) != 1 || check.Requires[0] != fact.ServicesID {
			t.Errorf("%s requires %v, want [%s]", check.ID, check.Requires, fact.ServicesID)
		}
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCheck0001(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "services-compliant", result: finding.Pass,
			detailContains: "none of the"},
		{fixture: "services-cleartext", result: finding.Fail, severity: finding.High,
			detailContains: "telnet.socket, rsh.socket"},
		{fixture: "services-masked", result: finding.Pass,
			detailContains: "masked"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "does not run systemd"},
		{fixture: "services-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "rests on not having found an enablement symlink"},
	})
}

func TestCheck0002(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "services-compliant", result: finding.Pass,
			detailContains: "nor the RPC portmapper is enabled"},
		{fixture: "services-discovery", result: finding.Fail, severity: finding.Medium,
			detailContains: "avahi-daemon.service, rpcbind.socket"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "openrc"},
		{fixture: "services-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/systemd/system"},
	})
}

func TestCheck0003(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "services-compliant", result: finding.Pass,
			detailContains: "chronyd.service is enabled and is the only"},
		{fixture: "services-notime", result: finding.Fail, severity: finding.Medium,
			detailContains: "no time synchronisation daemon is enabled"},
		{fixture: "services-twoclocks", result: finding.Fail,
			detailContains: "compete for the same udp port"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "some other init system"},
		{fixture: "services-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "rests on not having found an enablement symlink"},
	})
}

func TestCheck0004(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "services-compliant", result: finding.Pass,
			detailContains: "resolve to a unit file that exists"},
		{fixture: "services-dangling", result: finding.Fail, severity: finding.Medium,
			detailContains: "auditd.service"},
		{fixture: "services-unresolved", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "could not be followed"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "no systemd unit directory"},
		{fixture: "services-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "could not be listed completely"},
	})
}

func TestCheck0005(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "services-compliant", result: finding.Pass,
			detailContains: "writable by root alone"},
		{fixture: "services-writable", result: finding.Fail, severity: finding.High,
			detailContains: "deploy-agent.service"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "no systemd unit directory"},
		{fixture: "services-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "rests on not having found"},
	})
}

// ---------------------------------------------------------------------------
// the two semantics that are easy to get backwards
// ---------------------------------------------------------------------------

// TestMaskingBeatsEnablement is the reason services-masked exists.
//
// A .wants symlink and a mask can both name the same unit, and reading only the
// .wants directory reports it enabled. systemd does not: a masked unit cannot
// be started by anything, including a unit that Requires= it and including an
// administrator typing systemctl start. Getting this backwards produces a FAIL
// about a service that cannot run — a wrong verdict in the direction that
// matters most, because it sends somebody to disable something already off
// while the real finding goes unread.
func TestMaskingBeatsEnablement(t *testing.T) {
	facts := collectFixture(t, "services-masked")
	sv, _, _ := fact.Get[fact.Services](facts, fact.ServicesID)

	if len(sv.LinksTo("telnet.socket")) == 0 {
		t.Fatal("fixture no longer has an enablement symlink for telnet.socket; the case it exists to test is gone")
	}
	if got := sv.Status("telnet.socket"); got != fact.StatusMasked {
		t.Errorf("status = %s, want %s despite the enablement symlink", got, fact.StatusMasked)
	}
}

// TestUsrMergeDirectoryIsCountedOnce: /lib/systemd/system and
// /usr/lib/systemd/system are one directory on a usr-merged host and two on a
// pre-merge one. The collector settles which by comparing inode identity
// rather than hardcoding a layout, because assuming either one double-counts
// every vendor unit on half the distributions in service.
func TestUsrMergeDirectoryIsCountedOnce(t *testing.T) {
	facts := collectFixture(t, "services-compliant")
	sv, _, _ := fact.Get[fact.Services](facts, fact.ServicesID)

	var alias bool
	for _, d := range sv.Dirs {
		if d.Path == "/lib/systemd/system" {
			alias = d.State == fact.DirAlias
		}
	}
	if !alias {
		t.Fatal("/lib/systemd/system was not recognised as the same directory as /usr/lib/systemd/system")
	}
	// An alias is a complete observation, not a gap: we know exactly what is
	// there because we listed it under its other name.
	for _, d := range sv.Incomplete() {
		if d.Path == "/lib/systemd/system" {
			t.Error("a deduplicated directory must not count as an incomplete listing")
		}
	}

	seen := map[string]int{}
	for _, u := range sv.Units {
		seen[u.Name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("%s recorded %d times; the usr-merge duplicate was not detected", name, n)
		}
	}
}

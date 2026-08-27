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
	checks.Check0004, checks.Check0005, checks.Check0006,
}

// enablement is the five checks built on services.units. They share a gate and
// a fixture corpus; SERVICES-0006 shares neither, because it reads unit bodies
// out of a second fact and its fixtures are units rather than symlink trees.
var enablement = []catalog.Check{
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
	// Both collectors, because the module now reads two facts and a check
	// tested against only one of them is a check tested against a fact set no
	// scan ever produces.
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	if err := collector.NewSandbox().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect sandbox fixture %s: %v", name, err)
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
// host whose service configuration was never observed. Every check that reads
// enablement must say so rather than report the vendor units it happened to be
// able to read.
//
// SERVICES-0006 is deliberately not in this loop. Its subject is a unit's
// *body*, and a vendor unit that reads perfectly is a real answer about that
// unit whatever became of /etc — the gap that invalidates its verdict is an
// unreadable unit file or drop-in, which is
// TestAnUnreadableDropInIsNotAPass over services-sandbox-denied.
func TestUnreadableUnitDirectoryIsUnknownEverywhere(t *testing.T) {
	for _, check := range enablement {
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

// TestEveryCheckDeclaresItsVintageAndItsFact guards the one piece of metadata a
// reviewer cannot see from the diff: a check whose SinceCatalog is wrong claims
// to have existed in a version that never shipped it, and suppression files
// written against that version silently do not match.
//
// The module now has two vintages and two facts, which is why this is a table
// rather than one loop. SERVICES-0006 arrived at catalog 22 on a second fact,
// and a copy-paste that gave it catalog 9 would claim it had been in the
// v0.2.0 release.
func TestEveryCheckDeclaresItsVintageAndItsFact(t *testing.T) {
	for _, check := range enablement {
		if check.SinceCatalog != 9 {
			t.Errorf("%s SinceCatalog = %d, want 9", check.ID, check.SinceCatalog)
		}
		if len(check.Requires) != 1 || check.Requires[0] != fact.ServicesID {
			t.Errorf("%s requires %v, want [%s]", check.ID, check.Requires, fact.ServicesID)
		}
	}

	if checks.Check0006.SinceCatalog != 22 {
		t.Errorf("SERVICES-0006 SinceCatalog = %d, want 22", checks.Check0006.SinceCatalog)
	}
	if len(checks.Check0006.Requires) != 1 || checks.Check0006.Requires[0] != fact.ServiceHardeningID {
		t.Errorf("SERVICES-0006 requires %v, want [%s]", checks.Check0006.Requires, fact.ServiceHardeningID)
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

// ---------------------------------------------------------------------------
// SERVICES-0006, which reads unit bodies rather than symlinks
// ---------------------------------------------------------------------------

func TestCheck0006NoNewPrivileges(t *testing.T) {
	run(t, checks.Check0006, []tc{
		// All three audited units set it, in three different spellings.
		{fixture: "services-sandbox-hardened", result: finding.Pass,
			detailContains: "All 3 audited services set NoNewPrivileges"},

		// The ordinary host: journald ships hardened, cron does not, dbus is
		// not installed and is therefore skipped rather than failed.
		{fixture: "services-sandbox-stock", result: finding.Fail, severity: finding.Medium,
			detailContains: "cron.service does not set NoNewPrivileges"},

		// Written down and turned off, plus a value systemd rejects.
		{fixture: "services-sandbox-explicit-off", result: finding.Fail, severity: finding.Medium,
			detailContains: "written down and set to no"},

		// The answer is in a drop-in, and in the drop-in that wins.
		{fixture: "services-sandbox-dropin", result: finding.Pass,
			detailContains: "set NoNewPrivileges"},

		// A drop-in that could not be read could be carrying the no.
		{fixture: "services-sandbox-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "not every unit was read in full"},

		// A masked unit describes no process, so its unhardened vendor file is
		// not a finding.
		{fixture: "services-sandbox-masked", result: finding.Pass,
			detailContains: "masked"},

		// The gates.
		{fixture: "services-sandbox-none", result: finding.NotApplicable,
			detailContains: "None of the units this check audits is installed"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "does not run systemd"},
	})
}

// TestTheThreeWaysOfNotHavingTheBitAreDistinguished.
//
// All three leave the same posture — no_new_privs is off — and they are three
// different conversations to have with an operator. One never wrote the
// directive; one wrote it and chose no, for a reason worth hearing before it is
// changed; one wrote a value systemd rejects, so the file looks configured and
// the host is not. A report that rendered all three as "NoNewPrivileges is not
// set" would be wrong twice.
func TestTheThreeWaysOfNotHavingTheBitAreDistinguished(t *testing.T) {
	unset := evalCheck(t, checks.Check0006, "services-sandbox-stock")
	if !strings.Contains(unset.Detail, "does not set NoNewPrivileges") {
		t.Errorf("an unset directive does not read as unset: %s", unset.Detail)
	}
	if strings.Contains(unset.Detail, "written down") {
		t.Errorf("an unset directive was reported as a decision: %s", unset.Detail)
	}

	written := evalCheck(t, checks.Check0006, "services-sandbox-explicit-off")
	if !strings.Contains(written.Detail, "written down and set to no rather than absent") {
		t.Errorf("an explicit no does not read as a decision: %s", written.Detail)
	}
	if !strings.Contains(written.Detail, "systemd cannot parse") {
		t.Errorf("a value systemd rejects is not called out: %s", written.Detail)
	}

	// And the evidence keeps them apart per unit, which is where an operator
	// looks to find out which of their services is which.
	var excerpts []string
	for _, e := range written.Evidence {
		excerpts = append(excerpts, e.Excerpt)
	}
	joined := strings.Join(excerpts, " | ")
	for _, want := range []string{
		"cron.service: NoNewPrivileges=no (explicitly disabled)",
		"dbus.service: NoNewPrivileges set to a value systemd cannot parse",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence does not carry %q: %s", want, joined)
		}
	}
}

// TestAnAbsentUnitIsSkippedRatherThanFailed.
//
// cron.service is absent on a host running cronie under another name, and
// dbus.service on a container image with no message bus. Failing a host for
// not having installed something is a finding an operator cannot act on and
// would not want to.
func TestAnAbsentUnitIsSkippedRatherThanFailed(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-stock")

	if strings.Contains(got.Detail, "dbus.service") {
		t.Errorf("an uninstalled unit appears in the verdict: %s", got.Detail)
	}
	// And when every audited unit is absent there is nothing to judge at all.
	none := evalCheck(t, checks.Check0006, "services-sandbox-none")
	if none.Result != finding.NotApplicable {
		t.Errorf("a host with none of them installed = %s, want NOT_APPLICABLE: %s", none.Result, none.Detail)
	}
}

// TestAnUnreadableDropInIsNotAPass is ADR-0014 in the direction it points for
// this check.
//
// The unit file in services-sandbox-denied sets NoNewPrivileges=yes and the
// drop-in beside it cannot be read. A pass drawn from the file that was opened
// would be a verdict about a configuration this scan only partly saw — and a
// drop-in is exactly where a NoNewPrivileges=no would live.
func TestAnUnreadableDropInIsNotAPass(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-denied")

	if got.Result != finding.Unknown {
		t.Fatalf("= %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	if got.UnknownReason != finding.ReasonPermission {
		t.Errorf("reason = %q, want %q", got.UnknownReason, finding.ReasonPermission)
	}
	if !strings.Contains(got.Detail, "override.conf") {
		t.Errorf("the verdict does not name the file it could not read: %s", got.Detail)
	}
}

// TestAFoundFailureOutranksAnUnreadFile is the other half of ADR-0014: a unit
// that was read and does not set the bit is a finding whatever else went
// unread, because an incomplete examination invalidates a negative result and
// never a positive one. The verdict still says what it could not see.
func TestAFoundFailureOutranksAnUnreadFile(t *testing.T) {
	facts := collectFixture(t, "services-sandbox-denied")
	h, _, _ := fact.Get[fact.ServiceHardening](facts, fact.ServiceHardeningID)

	// Turn the passing unit into a failing one, leaving the denied drop-in
	// exactly where it is. Built by hand because the property is about the
	// interaction of two states that no single fixture can hold at once for
	// the same unit.
	for i := range h.Services {
		if h.Services[i].Unit == "cron.service" {
			h.Services[i].NoNewPrivileges = nil
		}
	}
	facts.Put(h)

	got := catalog.MustNew(checks.Check0006).Evaluate(facts)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Result != finding.Fail {
		t.Errorf("= %s, want FAIL; a found failure stands whatever else went unread: %s", got[0].Result, got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "could not be read in full") {
		t.Errorf("the FAIL does not admit what it could not see: %s", got[0].Detail)
	}
}

// TestTheVerdictNamesItsOwnLimits. The unit list is fixed and NoNewPrivileges
// is one directive of a dozen, so neither a pass nor a failure here is a
// statement about the host's services in general.
func TestTheVerdictNamesItsOwnLimits(t *testing.T) {
	for _, fixture := range []string{
		"services-sandbox-hardened",
		"services-sandbox-stock",
		"services-sandbox-explicit-off",
		"services-sandbox-dropin",
		"services-sandbox-denied",
		"services-sandbox-masked",
	} {
		got := evalCheck(t, checks.Check0006, fixture)
		if !strings.Contains(got.Detail, "fixed list of units") {
			t.Errorf("over %s the verdict does not say the list is fixed: %s", fixture, got.Detail)
		}
		if !strings.Contains(got.Detail, "other sandboxing directives") {
			t.Errorf("over %s the verdict claims more than one directive: %s", fixture, got.Detail)
		}
	}
}

// TestTheSandboxCheckIsIndependentOfEnablement.
//
// The two facts answer different questions and a check reading the wrong one
// would be hard to spot: services-sandbox-hardened has no enablement symlinks
// at all, and services-compliant has every symlink and hardened units. Each
// check must follow its own fact.
func TestTheSandboxCheckIsIndependentOfEnablement(t *testing.T) {
	// Units present and hardened, nothing enabled. SERVICES-0006 passes on the
	// bodies; the enablement checks have their own opinions and none of them
	// may be UNKNOWN for want of a fact this fixture does carry.
	if got := evalCheck(t, checks.Check0006, "services-sandbox-hardened"); got.Result != finding.Pass {
		t.Errorf("SERVICES-0006 over hardened units = %s: %s", got.Result, got.Detail)
	}

	// And the inverse: a fixture built for the enablement checks, whose two
	// audited units are hardened, passes SERVICES-0006 without any of the
	// enablement checks moving.
	for _, check := range enablement {
		if got := evalCheck(t, check, "services-sandbox-hardened"); got.Result == finding.Unknown {
			t.Errorf("%s = UNKNOWN over a fixture with no enablement problem: %s", check.ID, got.Detail)
		}
	}
}

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
	checks.Check0004, checks.Check0005, checks.Check0006, checks.Check0007,
	checks.Check0008,
}

// sandbox is the triad built on services.hardening. They share a gate, a
// fixture corpus, an exemption mechanism and — since partitionUnits — the
// ordering that decides which units are judged at all. They differ in the
// directive they read and the exemptions they carry, and in nothing else.
var sandbox = []catalog.Check{checks.Check0006, checks.Check0007, checks.Check0008}

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

	for _, c := range []struct {
		check catalog.Check
		since int
	}{{checks.Check0006, 22}, {checks.Check0007, 23}, {checks.Check0008, 24}} {
		if c.check.SinceCatalog != c.since {
			t.Errorf("%s SinceCatalog = %d, want %d", c.check.ID, c.check.SinceCatalog, c.since)
		}
		if len(c.check.Requires) != 1 || c.check.Requires[0] != fact.ServiceHardeningID {
			t.Errorf("%s requires %v, want [%s]", c.check.ID, c.check.Requires, fact.ServiceHardeningID)
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

// ---------------------------------------------------------------------------
// SERVICES-0006, which reads unit bodies rather than symlinks
// ---------------------------------------------------------------------------

func TestCheck0006NoNewPrivileges(t *testing.T) {
	run(t, checks.Check0006, []tc{
		// All three audited units set it, in three different spellings. Two of
		// them are exempt and set it anyway, which must be credited rather
		// than reported as skipped.
		{fixture: "services-sandbox-hardened", result: finding.Pass,
			detailContains: "3 of the 3 audited services installed here set NoNewPrivileges"},

		// The ordinary host: journald ships hardened, cron does not and is
		// exempt, dbus is not installed. A pass that names what it skipped.
		{fixture: "services-sandbox-stock", result: finding.Pass,
			detailContains: "Not held to this standard: cron.service"},

		// journald written down and turned off. Not exempt, so it fails.
		{fixture: "services-sandbox-explicit-off", result: finding.Fail, severity: finding.Medium,
			detailContains: "written down and set to no"},

		// A value systemd rejects, on a unit that is not exempt.
		{fixture: "services-sandbox-malformed", result: finding.Fail, severity: finding.Medium,
			detailContains: "systemd cannot parse"},

		// Every installed unit exempt: nothing was verified, so nothing may be
		// claimed.
		{fixture: "services-sandbox-all-exempt", result: finding.NotApplicable,
			detailContains: "nothing to examine"},

		// The answer is in a drop-in, and in the drop-in that wins. cron is
		// exempt and hardened anyway, so it is credited rather than skipped.
		{fixture: "services-sandbox-dropin", result: finding.Pass,
			detailContains: "sets NoNewPrivileges: cron.service"},

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
	// All three are on journald, because it is the one audited unit that is
	// not exempt — which is itself worth noticing about this check.
	unset := evalCheck(t, checks.Check0006, "services-sandbox-journald-bare")
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

	rejected := evalCheck(t, checks.Check0006, "services-sandbox-malformed")
	if !strings.Contains(rejected.Detail, "systemd cannot parse") {
		t.Errorf("a value systemd rejects is not called out: %s", rejected.Detail)
	}

	// And the evidence keeps them apart per unit, which is where an operator
	// looks to find out which of their services is which.
	for _, c := range []struct {
		got  finding.Finding
		want string
	}{
		{unset, "systemd-journald.service: NoNewPrivileges not set; the default is off"},
		{written, "systemd-journald.service: NoNewPrivileges=no (explicitly disabled)"},
		{rejected, "systemd-journald.service: NoNewPrivileges set to a value systemd cannot parse"},
	} {
		var excerpts []string
		for _, e := range c.got.Evidence {
			excerpts = append(excerpts, e.Excerpt)
		}
		if joined := strings.Join(excerpts, " | "); !strings.Contains(joined, c.want) {
			t.Errorf("evidence does not carry %q: %s", c.want, joined)
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

	// dbus.service is not installed here. It is also exempt, so this asserts
	// the two are not confused: an absent unit is not named at all, where an
	// exempt one is named with its reason.
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

	// Add a failing unit that is *not* exempt, leaving the denied drop-in on
	// cron.service exactly where it is. Built by hand because the property is
	// about the interaction of two states that no single fixture holds at
	// once, and because journald is the only audited unit that can fail.
	for i := range h.Services {
		if h.Services[i].Unit == "systemd-journald.service" {
			h.Services[i] = fact.ServiceSandbox{
				Unit:  "systemd-journald.service",
				State: fact.UnitPresent,
				Path:  "/usr/lib/systemd/system/systemd-journald.service",
			}
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
		"services-sandbox-malformed",
		"services-sandbox-all-exempt",
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

// TestAnExemptServiceIsSkippedAndSaidSo is the mechanism's headline property.
//
// cron.service does not set NoNewPrivileges in this fixture and setting it
// would break user cron jobs that call sudo. The check must not fail it — and
// must not go quiet about it either. A pass that silently omitted the unit
// would read as "the audited services are hardened" when it means "one of them
// is and one was not examined", and the operator who later finds cron running
// without no_new_privs would be right to say the tool told them otherwise.
func TestAnExemptServiceIsSkippedAndSaidSo(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-stock")

	if got.Result != finding.Pass {
		t.Fatalf("= %s, want PASS: an exempt service without the bit is not a finding\n  %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "Not held to this standard: cron.service") {
		t.Errorf("the verdict does not say cron.service was skipped: %s", got.Detail)
	}
	// The reason, not merely the fact of an exemption. The operator's next
	// question after "why was this skipped" is "what breaks if I do it
	// anyway", and the answer has to be in the same sentence.
	if !strings.Contains(got.Detail, "sudo") {
		t.Errorf("the verdict does not say what setting it would break: %s", got.Detail)
	}
	// And the distinction from a suppression, which is what stops this reading
	// as "somebody turned this finding off".
	if !strings.Contains(got.Detail, "not a finding that was suppressed") {
		t.Errorf("the verdict does not distinguish an exemption from a suppression: %s", got.Detail)
	}
	// The unit is still cited, so the evidence shows its actual state rather
	// than leaving the reader to trust the sentence.
	var sources []string
	for _, e := range got.Evidence {
		sources = append(sources, e.Excerpt)
	}
	if !strings.Contains(strings.Join(sources, " | "), "cron.service: NoNewPrivileges not set") {
		t.Errorf("an exempt unit is not cited: %v", sources)
	}
}

// TestAnExemptionNeverHidesAnUnreadableUnit.
//
// An exemption says "the standard does not apply here", which is a claim about
// a configuration that was seen. A unit whose drop-in was denied has no known
// configuration, and excusing it would turn "I could not look" into "it is
// fine" — the exact substitution the UNKNOWN result exists to prevent.
//
// cron.service is exempt *and* unreadable in this fixture. The verdict must be
// UNKNOWN, not a pass with an exemption note.
func TestAnExemptionNeverHidesAnUnreadableUnit(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-denied")

	if got.Result != finding.Unknown {
		t.Fatalf("= %s, want UNKNOWN; an exemption excused a file nobody opened\n  %s", got.Result, got.Detail)
	}
	if strings.Contains(got.Detail, "Not held to this standard") {
		t.Errorf("an unreadable unit was reported as exempt: %s", got.Detail)
	}
}

// TestAnExemptionNeverDowngradesAServiceThatComplies.
//
// The exemption is a floor rather than a ceiling. A host whose dbus.service
// does set NoNewPrivileges has a stronger posture than the exemption assumes,
// and reporting it as skipped would hide work somebody did — and would make
// the check unable to tell an improving fleet from a static one.
func TestAnExemptionNeverDowngradesAServiceThatComplies(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-hardened")

	if got.Result != finding.Pass {
		t.Fatalf("= %s, want PASS: %s", got.Result, got.Detail)
	}
	if strings.Contains(got.Detail, "Not held to this standard") {
		t.Errorf("a unit that satisfies the check was reported as exempt: %s", got.Detail)
	}
	for _, unit := range []string{"cron.service", "dbus.service", "systemd-journald.service"} {
		if !strings.Contains(got.Detail, unit) {
			t.Errorf("%s is not credited with setting the bit: %s", unit, got.Detail)
		}
	}
}

// TestExemptionsCannotMakeTheCheckVacuous is the guard on the mechanism
// itself, and the reason it is worth having a test rather than a convention.
//
// With cron and dbus exempt, journald is the only audited unit that can fail.
// An exemption list that grew until it covered every target would turn this
// check into a green tick that means nothing — and it would do so silently,
// one reasonable-looking entry at a time. So a host on which nothing was
// actually held to the standard is NOT_APPLICABLE: the check reports that it
// had nothing to examine rather than that the host satisfied it.
//
// The failure this prevents is the one CONTRIBUTING.md rule 3 is about.
// Reporting PASS for something never examined is worse than reporting nothing.
func TestExemptionsCannotMakeTheCheckVacuous(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-all-exempt")

	if got.Result == finding.Pass {
		t.Fatalf("a host where every audited unit is exempt reported PASS, which claims a standard nothing was held to:\n  %s", got.Detail)
	}
	if got.Result != finding.NotApplicable {
		t.Fatalf("= %s, want NOT_APPLICABLE: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "nothing to examine, not that the host satisfied it") {
		t.Errorf("the verdict does not say why it is silent: %s", got.Detail)
	}
	// Both exemptions are still named, so the reader can see what would have
	// been examined and decide whether they agree.
	for _, unit := range []string{"cron.service", "dbus.service"} {
		if !strings.Contains(got.Detail, unit) {
			t.Errorf("%s is not named: %s", unit, got.Detail)
		}
	}
}

// TestAFailureStillNamesTheExemptions. An operator reading a failure that
// lists journald and nothing else needs to know that cron and dbus were
// skipped on purpose, not that they were overlooked or that they passed.
func TestAFailureStillNamesTheExemptions(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "services-sandbox-explicit-off")

	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "systemd-journald.service") {
		t.Errorf("the failing unit is not named: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "Not held to this standard: cron.service") {
		t.Errorf("a failure does not name the exemptions: %s", got.Detail)
	}
}

// TestEveryExemptionSaysWhatBreaks. The bar for an exemption is that applying
// the setting breaks the service, so each reason has to name the thing that
// stops working — otherwise the list becomes a place to put services nobody
// got round to, which is a finding rather than an exemption.
func TestEveryExemptionSaysWhatBreaks(t *testing.T) {
	// Reached through the verdict rather than the variable, because the
	// property is about what an operator reads.
	got := evalCheck(t, checks.Check0006, "services-sandbox-all-exempt")

	for _, want := range []string{
		"sudo",                      // what breaks for cron
		"dbus-daemon-launch-helper", // what breaks for dbus
		"setuid",                    // why, in both cases
	} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("no exemption reason mentions %q: %s", want, got.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// SERVICES-0007, the same fact and a different directive
// ---------------------------------------------------------------------------

func TestCheck0007ProtectSystem(t *testing.T) {
	run(t, checks.Check0007, []tc{
		// The three enum levels, all of which pass: the bar is yes and upward,
		// not strict.
		{fixture: "services-sandbox-protect-levels", result: finding.Pass,
			detailContains: "3 of the 3 audited services installed here mount the system directories read-only"},

		// The boolean spellings the enum is a superset of.
		{fixture: "services-sandbox-protect-bool", result: finding.Pass,
			detailContains: "systemd-journald.service (yes)"},

		// Written down and turned off, and never written at all.
		{fixture: "services-sandbox-protect-off", result: finding.Fail, severity: finding.High,
			detailContains: "written down and turned off"},

		// A host where the only unit that could be judged is exempt.
		{fixture: "services-sandbox-dropin", result: finding.NotApplicable,
			detailContains: "nothing to examine"},

		// The gates, which are the module's.
		{fixture: "services-sandbox-none", result: finding.NotApplicable,
			detailContains: "None of the units this check audits is installed"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "does not run systemd"},
		{fixture: "services-sandbox-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "not every unit was read in full"},
	})
}

// TestProtectSystemAcceptsEveryLevelSystemdDoes.
//
// The value is a superset of the booleans and systemd tries parse_boolean
// *first*, so true, 1 and on are all "yes". A check that accepted only the four
// enum names would report a host that wrote ProtectSystem=true as having set
// nothing — a High finding against a service that is in fact protected, which
// is the worst kind of false positive this module can produce.
func TestProtectSystemAcceptsEveryLevelSystemdDoes(t *testing.T) {
	for _, c := range []struct {
		value string
		want  fact.ProtectSystemLevel
	}{
		{"yes", fact.ProtectYes}, {"true", fact.ProtectYes}, {"1", fact.ProtectYes},
		{"on", fact.ProtectYes}, {"y", fact.ProtectYes}, {"TRUE", fact.ProtectYes},
		{"full", fact.ProtectFull}, {"strict", fact.ProtectStrict},
		{"no", fact.ProtectNo}, {"false", fact.ProtectNo}, {"0", fact.ProtectNo}, {"off", fact.ProtectNo},
	} {
		got, ok := fact.ParseProtectSystem(c.value)
		if !ok || got != c.want {
			t.Errorf("ParseProtectSystem(%q) = %q/%v, want %q", c.value, got, ok, c.want)
		}
	}

	// **The two halves of the grammar disagree about case, and following that
	// is not pedantry.** parse_boolean compares its words with strcaseeq, so
	// "TRUE" above is accepted; the enum names go through a string table
	// looked up with streq, so "Full" is not — systemd logs it and ignores the
	// assignment, leaving /usr writable.
	//
	// Folding the enum half is the more dangerous mistake of the two: it would
	// report PASS for a service systemd left unprotected. Reporting it as
	// unparseable is correct, and is the safe direction even if this reading
	// of systemd is ever wrong, because the operator is told to look at the
	// line rather than being quietly passed.
	for _, v := range []string{"Full", "STRICT", "Strict"} {
		if _, ok := fact.ParseProtectSystem(v); ok {
			t.Errorf("ParseProtectSystem(%q) parsed; systemd's enum lookup is case sensitive", v)
		}
	}

	// Not values systemd would take at all. Emphatically not "no": systemd
	// logs and ignores the line, which the collector records as Malformed.
	for _, v := range []string{"readonly", "read-only", "partial", "2", "", "yes full"} {
		if _, ok := fact.ParseProtectSystem(v); ok {
			t.Errorf("ParseProtectSystem(%q) parsed", v)
		}
	}

	// And the bar the check applies: anything from yes upward protects.
	for _, c := range []struct {
		value     string
		protected bool
	}{
		{"", false}, {"no", false}, {"off", false}, {"0", false},
		{"yes", true}, {"true", true}, {"full", true}, {"strict", true},
	} {
		s := fact.ServiceSandbox{ProtectSystem: c.value}
		if s.Protected() != c.protected {
			t.Errorf("Protected(%q) = %v, want %v", c.value, s.Protected(), c.protected)
		}
	}
}

// TestEachSandboxCheckCarriesItsOwnExemptions is the property that makes
// exemptions per-check rather than a shared "awkward services" list, and with
// three checks it can finally be asserted as a matrix rather than a contrast.
//
// dbus.service is the unit that proves it: exempt from SERVICES-0006 because
// its launch helper is setuid, and audited by both -0007 and -0008 because
// that fact has nothing to say about where the daemon may write or read. On a
// systemd host dbus-activated services are started by systemd as their own
// units and do not inherit its mount namespace, so the namespace-based
// directives are safe there.
//
// A shared list would have excused dbus from all three and cost two checks
// half their subject to a reason that applied to neither.
func TestEachSandboxCheckCarriesItsOwnExemptions(t *testing.T) {
	// A host where dbus and journald set none of the three directives and
	// cron sets none either.
	const fixture = "services-sandbox-home-off"

	for _, c := range []struct {
		check      catalog.Check
		dbusExempt bool
		cronExempt bool
	}{
		{checks.Check0006, true, true},
		{checks.Check0007, false, true},
		{checks.Check0008, false, true},
	} {
		got := evalCheck(t, c.check, fixture)

		exemptedHere := strings.Contains(got.Detail, "Not held to this standard") &&
			strings.Contains(exemptionClause(got.Detail), "dbus.service")
		if exemptedHere != c.dbusExempt {
			t.Errorf("%s: dbus exempt = %v, want %v\n  %s", c.check.ID, exemptedHere, c.dbusExempt, got.Detail)
		}

		cronHere := strings.Contains(exemptionClause(got.Detail), "cron.service")
		if cronHere != c.cronExempt {
			t.Errorf("%s: cron exempt = %v, want %v\n  %s", c.check.ID, cronHere, c.cronExempt, got.Detail)
		}
	}

	// And the consequence, stated as a verdict rather than as bookkeeping:
	// the two namespace checks fail dbus on this host and the setuid one does
	// not, which is the whole reason the lists are separate.
	for _, check := range []catalog.Check{checks.Check0007, checks.Check0008} {
		got := evalCheck(t, check, fixture)
		if got.Result != finding.Fail {
			t.Errorf("%s over an unprotected dbus = %s, want FAIL: %s", check.ID, got.Result, got.Detail)
		}
		if !strings.Contains(got.Detail, "dbus.service") {
			t.Errorf("%s excused dbus, which is SERVICES-0006's exemption and not its own: %s", check.ID, got.Detail)
		}
	}

	// Each check's reason for exempting cron is its own text rather than a
	// copy, because the reasons genuinely differ: jobs that escalate, jobs
	// that write, jobs that live in a home directory.
	reasons := map[string]string{
		checks.Check0006.ID: "no_new_privs is inherited by every child",
		checks.Check0007.ID: "a read-only /usr or /etc becomes a restriction on code the packager never saw",
		checks.Check0008.ID: "execute scripts kept in a home directory",
	}
	for _, check := range sandbox {
		got := evalCheck(t, check, fixture)
		if !strings.Contains(got.Detail, reasons[check.ID]) {
			t.Errorf("%s does not give its own reason for exempting cron: %s", check.ID, got.Detail)
		}
	}
}

// exemptionClause returns the part of a detail string after the exemption
// sentence begins, so a test can ask which units were exempted without
// matching a unit named elsewhere in the same verdict.
func exemptionClause(detail string) string {
	const marker = "Not held to this standard:"
	i := strings.Index(detail, marker)
	if i < 0 {
		return ""
	}
	rest := detail[i+len(marker):]
	if j := strings.Index(rest, "An exemption is a documented reason"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestTheTwoWaysOfLeavingUsrWritableAreDistinguished. One operator considered
// the question and turned it off; the other never wrote the directive. Same
// posture, different conversation.
func TestTheTwoWaysOfLeavingUsrWritableAreDistinguished(t *testing.T) {
	got := evalCheck(t, checks.Check0007, "services-sandbox-protect-off")

	if !strings.Contains(got.Detail, "systemd-journald.service (no)") {
		t.Errorf("the explicit off does not show its value: %s", got.Detail)
	}
	var excerpts []string
	for _, e := range got.Evidence {
		excerpts = append(excerpts, e.Excerpt)
	}
	joined := strings.Join(excerpts, " | ")
	for _, want := range []string{
		"systemd-journald.service: ProtectSystem=no (no)",
		"dbus.service: ProtectSystem not set; the default is no",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence does not carry %q: %s", want, joined)
		}
	}
}

// TestTheLevelIsRenderedAlongsideTheText.
//
// "true" and "yes" are the same setting, and an operator comparing two hosts
// should not have to know that. The evidence carries both so a diff of two
// reports shows a real difference rather than a spelling one.
func TestTheLevelIsRenderedAlongsideTheText(t *testing.T) {
	got := evalCheck(t, checks.Check0007, "services-sandbox-protect-bool")

	var excerpts []string
	for _, e := range got.Evidence {
		excerpts = append(excerpts, e.Excerpt)
	}
	joined := strings.Join(excerpts, " | ")
	for _, want := range []string{
		"systemd-journald.service: ProtectSystem=true (yes)",
		"dbus.service: ProtectSystem=1 (yes)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence does not resolve the spelling: %s", joined)
		}
	}
}

// TestBothSandboxChecksRefuseToBeVacuous applies SERVICES-0006's guard to its
// neighbour, because the failure mode is the mechanism's rather than any one
// check's: an exemption list that grows until it covers every auditable unit
// turns a check into a green tick, silently.
func TestBothSandboxChecksRefuseToBeVacuous(t *testing.T) {
	// Only cron.service is installed here, and it is exempt from both.
	for _, check := range sandbox {
		got := evalCheck(t, check, "services-sandbox-dropin-bare")
		if got.Result == finding.Pass {
			t.Errorf("%s reported PASS on a host whose only audited unit is exempt:\n  %s", check.ID, got.Detail)
		}
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s, want NOT_APPLICABLE: %s", check.ID, got.Result, got.Detail)
		}
	}
}

// TestBothSandboxChecksNameTheirLimits. Each reads one directive from a fixed
// list of units, and neither may be read as a statement about the host's
// services in general.
func TestBothSandboxChecksNameTheirLimits(t *testing.T) {
	for _, check := range sandbox {
		for _, fixture := range []string{
			"services-sandbox-hardened",
			"services-sandbox-protect-levels",
			"services-sandbox-protect-off",
			"services-sandbox-all-exempt",
			"services-sandbox-denied",
		} {
			got := evalCheck(t, check, fixture)
			if !strings.Contains(got.Detail, "fixed list of units") {
				t.Errorf("%s over %s does not say the list is fixed: %s", check.ID, fixture, got.Detail)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SERVICES-0008, the third directive on the same fact
// ---------------------------------------------------------------------------

func TestCheck0008ProtectHome(t *testing.T) {
	run(t, checks.Check0008, []tc{
		// The three non-default levels, all passing.
		{fixture: "services-sandbox-home-levels", result: finding.Pass,
			detailContains: "3 of the 3 audited services installed here cannot reach user home directories"},

		// The boolean spellings, one in a case parse_boolean folds.
		{fixture: "services-sandbox-home-bool", result: finding.Pass,
			detailContains: "dbus.service (yes)"},

		// Written off, and never written.
		{fixture: "services-sandbox-home-off", result: finding.Fail, severity: finding.High,
			detailContains: "written down and turned off"},

		// The near-miss spellings systemd rejects.
		{fixture: "services-sandbox-home-malformed", result: finding.Fail, severity: finding.High,
			detailContains: "read-only is hyphenated and nothing else is accepted"},

		// The gates and the vacuity guard, which are the module's.
		{fixture: "services-sandbox-dropin-bare", result: finding.NotApplicable,
			detailContains: "nothing to examine"},
		{fixture: "services-sandbox-none", result: finding.NotApplicable,
			detailContains: "None of the units this check audits is installed"},
		{fixture: "services-absent", result: finding.NotApplicable,
			detailContains: "does not run systemd"},
		{fixture: "services-sandbox-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "not every unit was read in full"},
	})
}

// TestProtectHomeAcceptsEveryLevelSystemdDoes, and rejects the near-misses.
//
// The grammar is the same shape as ProtectSystem's and has the same asymmetry:
// parse_boolean first and case-insensitively, then a case-sensitive string
// table. **"read-only" is hyphenated and nothing else is accepted.**
func TestProtectHomeAcceptsEveryLevelSystemdDoes(t *testing.T) {
	for _, c := range []struct {
		value string
		want  fact.ProtectHomeLevel
	}{
		{"yes", fact.HomeInaccessible}, {"true", fact.HomeInaccessible},
		{"1", fact.HomeInaccessible}, {"ON", fact.HomeInaccessible},
		{"y", fact.HomeInaccessible}, {"True", fact.HomeInaccessible},
		{"read-only", fact.HomeReadOnly},
		{"tmpfs", fact.HomeTmpfs},
		{"no", fact.HomeUnprotected}, {"false", fact.HomeUnprotected},
		{"0", fact.HomeUnprotected}, {"OFF", fact.HomeUnprotected},
	} {
		got, ok := fact.ParseProtectHome(c.value)
		if !ok || got != c.want {
			t.Errorf("ParseProtectHome(%q) = %q/%v, want %q", c.value, got, ok, c.want)
		}
	}

	// The near-misses, and they are the point of having a parser rather than a
	// contains check. An operator who typed one of these believes the home
	// directories are protected; systemd rejected the line and left them open.
	for _, v := range []string{
		"readonly",  // missing hyphen
		"read_only", // wrong separator
		"Read-Only", // enum lookup is case sensitive, unlike the booleans
		"TMPFS",     // likewise
		"ro", "readonly-ish", "",
	} {
		if _, ok := fact.ParseProtectHome(v); ok {
			t.Errorf("ParseProtectHome(%q) parsed; systemd would reject it", v)
		}
	}

	// The bar the check applies.
	for _, c := range []struct {
		value     string
		protected bool
	}{
		{"", false}, {"no", false}, {"off", false},
		{"yes", true}, {"true", true}, {"read-only", true}, {"tmpfs", true},
	} {
		s := fact.ServiceSandbox{ProtectHome: c.value}
		if s.HomeProtected() != c.protected {
			t.Errorf("HomeProtected(%q) = %v, want %v", c.value, s.HomeProtected(), c.protected)
		}
	}
}

// TestReadOnlyPassesAndSaysWhatItDidNotBuy.
//
// read-only is the one passing level that leaves this check's own rationale
// half unaddressed: it stops a daemon planting an authorized_keys file and
// does not stop it reading a private key. A verdict that reported "home
// directories are protected" about such a service would be claiming most of
// what the check exists for without delivering it.
func TestReadOnlyPassesAndSaysWhatItDidNotBuy(t *testing.T) {
	got := evalCheck(t, checks.Check0008, "services-sandbox-home-levels")

	if got.Result != finding.Pass {
		t.Fatalf("= %s, want PASS: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "cron.service is read-only rather than inaccessible") {
		t.Errorf("the verdict does not single out the read-only unit: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "can still read a private key") {
		t.Errorf("the verdict does not say what read-only leaves open: %s", got.Detail)
	}
	// And the inverse: where nothing is merely read-only, the verdict makes
	// the stronger claim rather than hedging out of habit.
	strong := evalCheck(t, checks.Check0008, "services-sandbox-home-bool")
	if !strings.Contains(strong.Detail, "cannot read an SSH private key") {
		t.Errorf("a fully-protected host gets the hedged wording: %s", strong.Detail)
	}
	if strings.Contains(strong.Detail, "read-only rather than inaccessible") {
		t.Errorf("a host with no read-only unit is told about one: %s", strong.Detail)
	}
}

// TestANearMissSpellingIsAFailureNotAPass.
//
// "readonly" and "Read-Only" are the two ways an operator writes ProtectHome
// and gets nothing. systemd logs and ignores them, so the effective level is
// the default — and a build that lowercased the enum names, or matched on a
// substring, would report PASS for a host whose home directories are wide
// open. This is the fixture that catches it.
func TestANearMissSpellingIsAFailureNotAPass(t *testing.T) {
	got := evalCheck(t, checks.Check0008, "services-sandbox-home-malformed")

	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: a value systemd rejects leaves the default in force\n  %s", got.Result, got.Detail)
	}
	for _, unit := range []string{"systemd-journald.service", "dbus.service"} {
		if !strings.Contains(got.Detail, unit) {
			t.Errorf("%s is not reported: %s", unit, got.Detail)
		}
	}
	// The finding has to say *why*, because "ProtectHome is not set" about a
	// unit whose file plainly contains the line reads as a tool that cannot
	// see straight.
	if !strings.Contains(got.Detail, "systemd cannot parse") {
		t.Errorf("the verdict does not explain the rejection: %s", got.Detail)
	}
	var excerpts []string
	for _, e := range got.Evidence {
		excerpts = append(excerpts, e.Excerpt)
	}
	if !strings.Contains(strings.Join(excerpts, " | "), "value systemd cannot parse") {
		t.Errorf("evidence does not show the value was rejected: %v", excerpts)
	}
}

// TestAllThreeSandboxChecksOrderTheirUnitsIdentically.
//
// partitionUnits exists so that the rules about which units are judged at all
// — pass before exemption, unreadable before either, masked neither — hold for
// every check rather than being three copies of a loop. This asserts the
// consequence on the fixtures where each rule bites.
func TestAllThreeSandboxChecksOrderTheirUnitsIdentically(t *testing.T) {
	for _, check := range sandbox {
		// Unreadable outranks exemption: cron is exempt from all three and
		// unreadable here, and no check may excuse it.
		if got := evalCheck(t, check, "services-sandbox-denied"); got.Result != finding.Unknown {
			t.Errorf("%s excused an unreadable unit: %s", check.ID, got.Detail)
		}
		// Masked is neither a pass nor a failure nor an exemption.
		got := evalCheck(t, check, "services-sandbox-masked")
		if got.Result == finding.Unknown {
			t.Errorf("%s counted a masked unit as unread: %s", check.ID, got.Detail)
		}
		if !strings.Contains(got.Detail, "masked") {
			t.Errorf("%s does not say a unit was masked: %s", check.ID, got.Detail)
		}
		// The vacuity guard, on a host whose only audited unit is exempt from
		// all three.
		if got := evalCheck(t, check, "services-sandbox-dropin-bare"); got.Result != finding.NotApplicable {
			t.Errorf("%s = %s on a host with nothing to examine: %s", check.ID, got.Result, got.Detail)
		}
	}
}

package containers_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/containers"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/containers"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the CONTAINERS module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003, checks.Check0004,
	checks.Check0005, checks.Check0006,
}

// daemonChecks are the checks that read /etc/docker/daemon.json, which is
// every one of them except CONTAINERS-0006.
//
// The split exists because most of the invariants below are properties of
// *that file* — that a missing one is judged rather than excused, that an
// unreadable one produces no verdict, that every detail says it read only the
// file — and none of them is a property of a systemd unit. CONTAINERS-0006
// reads the unit and has the mirror image of each: a missing unit really is
// NOT_APPLICABLE, because systemd has no compiled-in docker.service to fall
// back on. Running the daemon invariants over it would assert the opposite of
// what it is for.
var daemonChecks = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003, checks.Check0004, checks.Check0005,
}

// defaultIsUnsafe is the subset of the module whose option the daemon leaves
// off, so that a host which says nothing is running the value the check
// objects to. CONTAINERS-0005 is deliberately not in it: experimental defaults
// to off, and silence there is the safe state rather than the permissive one.
// The split is the module's one real asymmetry and several invariants below
// turn on it.
var defaultIsUnsafe = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003, checks.Check0004,
}

func collectFixture(t *testing.T, name string) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	// Both collectors, because the module now reads two files and a check
	// tested against only one of them is a check tested against a fact set no
	// scan ever produces.
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	if err := collector.NewService().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect service fixture %s: %v", name, err)
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

			if got.CheckID != check.ID || got.Module != "CONTAINERS" {
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

func TestCheck0001UsernsRemap(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "containers-docker-hardened", result: finding.Pass, detailContains: "userns-remap is set"},
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Medium, detailContains: "uid 0 on the host"},
		// The case the module exists for: dockerd running, no daemon.json, so
		// the defaults are in force and the default is off.
		{fixture: "containers-docker-defaults", result: finding.Fail, severity: finding.Medium, detailContains: "compiled-in defaults"},
		// An explicitly empty string is what dockerd treats as disabled.
		{fixture: "containers-docker-explicit-off", result: finding.Fail, severity: finding.Medium, detailContains: "userns-remap is not set"},
		{fixture: "containers-docker-nnp-only", result: finding.Fail, severity: finding.Medium, detailContains: "userns-remap is not set"},
		{fixture: "containers-absent", result: finding.NotApplicable, detailContains: "no dockerd binary"},
		{fixture: "containers-docker-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "not valid json"},
	})
}

func TestCheck0002NoNewPrivileges(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "containers-docker-hardened", result: finding.Pass, detailContains: "no-new-privileges is enabled"},
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Medium, detailContains: "setuid binary"},
		{fixture: "containers-docker-defaults", result: finding.Fail, severity: finding.Medium, detailContains: "compiled-in defaults"},
		{fixture: "containers-docker-explicit-off", result: finding.Fail, severity: finding.Medium, detailContains: "not enabled"},
		{fixture: "containers-docker-nnp-only", result: finding.Pass, detailContains: "no-new-privileges is enabled"},
		{fixture: "containers-absent", result: finding.NotApplicable, detailContains: "no dockerd binary"},
		{fixture: "containers-docker-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "not valid json"},
	})
}

func TestCheck0003InterContainerCommunication(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "containers-docker-hardened", result: finding.Pass, detailContains: "icc is disabled"},
		// Explicitly true.
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Low, detailContains: "every port of every other"},
		{fixture: "containers-docker-icc-only", result: finding.Fail, severity: finding.Low, detailContains: "icc is not disabled"},
		// Absent from a file that exists. Docker's default is permissive, so a
		// key nobody wrote leaves the bridge open.
		{fixture: "containers-docker-nnp-only", result: finding.Fail, severity: finding.Low, detailContains: "icc is not disabled"},
		{fixture: "containers-docker-explicit-off", result: finding.Fail, severity: finding.Low, detailContains: "icc is not disabled"},
		// No file at all: the other flavour of absence, same verdict.
		{fixture: "containers-docker-defaults", result: finding.Fail, severity: finding.Low, detailContains: "compiled-in defaults"},
		{fixture: "containers-absent", result: finding.NotApplicable, detailContains: "no dockerd binary"},
		{fixture: "containers-docker-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
		// icc: "false" as a string. dockerd rejects the file, so nothing may be
		// read from it — the case a lenient parser would take as a set value.
		{fixture: "containers-docker-wrongtype", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "not valid json"},
	})
}

func TestCheck0004LiveRestore(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "containers-docker-hardened", result: finding.Pass, detailContains: "live-restore is enabled"},
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Medium, detailContains: "stops every container"},
		// The isolating case: a file whose author plainly did think about
		// hardening and skipped the one availability setting on the list.
		{fixture: "containers-docker-no-live-restore", result: finding.Fail, severity: finding.Medium, detailContains: "live-restore is not enabled"},
		{fixture: "containers-docker-icc-only", result: finding.Pass, detailContains: "live-restore is enabled"},
		// Key absent from a file that exists. The daemon default is off, so an
		// unwritten key is the failing state.
		{fixture: "containers-docker-nnp-only", result: finding.Fail, severity: finding.Medium, detailContains: "live-restore is not enabled"},
		{fixture: "containers-docker-explicit-off", result: finding.Fail, severity: finding.Medium, detailContains: "live-restore is not enabled"},
		{fixture: "containers-docker-defaults", result: finding.Fail, severity: finding.Medium, detailContains: "compiled-in defaults"},
		{fixture: "containers-absent", result: finding.NotApplicable, detailContains: "no dockerd binary"},
		{fixture: "containers-docker-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "not valid json"},
	})
}

// TestCheck0005Experimental. Note how much of this table is PASS where the
// other four are FAIL: this is the one option in the module the daemon leaves
// in the state the check wants, so every host that never mentioned it passes.
func TestCheck0005Experimental(t *testing.T) {
	run(t, checks.Check0005, []tc{
		// Explicitly false.
		{fixture: "containers-docker-hardened", result: finding.Pass, detailContains: "experimental is not enabled"},
		// The isolating case: one flag flipped on an otherwise hardened file.
		{fixture: "containers-docker-experimental-only", result: finding.Fail, severity: finding.Low, detailContains: "experimental is enabled"},
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Low, detailContains: "without stability or support guarantees"},
		// Key absent from a file that exists. Unlike every other check in this
		// module, that is a pass.
		{fixture: "containers-docker-icc-only", result: finding.Pass, detailContains: "experimental is not enabled"},
		{fixture: "containers-docker-nnp-only", result: finding.Pass, detailContains: "experimental is not enabled"},
		{fixture: "containers-docker-explicit-off", result: finding.Pass, detailContains: "experimental is not enabled"},
		// No file at all: still a pass, and the detail still has to say where
		// the setting came from.
		{fixture: "containers-docker-defaults", result: finding.Pass, detailContains: "compiled-in defaults"},
		{fixture: "containers-absent", result: finding.NotApplicable, detailContains: "no dockerd binary"},
		// An unreadable file is UNKNOWN and not PASS, even though a pass is
		// this check's default answer. The file may well enable experimental
		// mode, and a check that fell back to its own default would be
		// reporting a verdict drawn from a document nobody opened.
		{fixture: "containers-docker-denied", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "not valid json"},
		{fixture: "containers-docker-notobject", result: finding.Unknown, detailContains: "docker is installed"},
	})
}

// TestAbsentICCIsNeverReadAsDisabled is CONTAINERS-0003's reason for existing
// in the shape it has.
//
// Docker's icc defaults to *true*. A plain bool in the fact would decode an
// absent key as false and this check would report PASS — an open bridge
// described as a closed one, which is the single most misleading answer it
// could give and the one an operator would never think to question. The three
// permissive shapes are asserted together so none can drift alone.
func TestAbsentICCIsNeverReadAsDisabled(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-nnp-only",     // file present, icc key absent
		"containers-docker-explicit-off", // file present, icc key absent
		"containers-docker-defaults",     // no file at all
	} {
		got := evalCheck(t, checks.Check0003, fixture)
		if got.Result != finding.Fail {
			t.Errorf("%s over %s = %s, want FAIL; an unset icc is permissive: %s",
				checks.Check0003.ID, fixture, got.Result, got.Detail)
		}
	}

	// And the inverse, so the test cannot pass by always failing.
	if got := evalCheck(t, checks.Check0003, "containers-docker-hardened"); got.Result != finding.Pass {
		t.Errorf("an explicitly false icc = %s, want PASS: %s", got.Result, got.Detail)
	}
}

// ---------------------------------------------------------------------------
// module-wide invariants
// ---------------------------------------------------------------------------

// TestAMissingConfigIsJudgedNotExcused is the module's central property, and
// the one it would be easiest to get backwards.
//
// containers-docker-defaults and containers-absent both have no daemon.json.
// One has dockerd and one does not, and they must reach opposite verdicts. A
// daemon running on its compiled-in defaults has userns-remap off and
// no_new_privileges off — that is a real configuration and it is what most
// Docker hosts are running. Excusing it as NOT_APPLICABLE would leave the
// module silent on exactly the hosts it exists for, which is the same shape of
// mistake as reporting PASS for something never examined.
func TestAMissingConfigIsJudgedNotExcused(t *testing.T) {
	for _, check := range defaultIsUnsafe {
		running := evalCheck(t, check, "containers-docker-defaults")
		if running.Result != finding.Fail {
			t.Errorf("%s = %s on a host with dockerd and no daemon.json, want FAIL: %s",
				check.ID, running.Result, running.Detail)
		}
	}

	// Every check in the module has to reach a verdict on that host and say
	// where the setting came from, including the one whose verdict is PASS.
	// The remedy differs by whether a file exists at all — "create the file"
	// rather than "edit the line" — and a passing finding that hid the
	// distinction would be describing a file that is not there.
	for _, check := range daemonChecks {
		running := evalCheck(t, check, "containers-docker-defaults")
		if running.Result == finding.NotApplicable || running.Result == finding.Unknown {
			t.Errorf("%s = %s on a host with dockerd and no daemon.json; the defaults are a configuration: %s",
				check.ID, running.Result, running.Detail)
		}
		if !strings.Contains(running.Detail, "no /etc/docker/daemon.json") {
			t.Errorf("%s does not tell the operator there is no file: %s", check.ID, running.Detail)
		}

		none := evalCheck(t, check, "containers-absent")
		if none.Result != finding.NotApplicable {
			t.Errorf("%s = %s on a host with no dockerd, want NOT_APPLICABLE: %s",
				check.ID, none.Result, none.Detail)
		}
	}
}

// TestSilenceIsAPassOnlyWhereTheDefaultIsSafe is the property that separates
// CONTAINERS-0005 from the rest of the module, and the one a later check could
// most easily copy from the wrong neighbour.
//
// Four of these checks read a *bool and treat nil as a failure, because the
// daemon leaves their option off and an unwritten key means the permissive
// value is in force. CONTAINERS-0005 reads a *bool and treats nil as a pass,
// because experimental defaults to off and demanding it be written down would
// fail every correctly configured host for not having said something it did
// not need to say. Both are "nil means the daemon's default", and the default
// happens to point in opposite directions.
//
// The fixtures below are silent on both options in exactly the same way, which
// is what makes the divergence attributable to the checks rather than the file.
func TestSilenceIsAPassOnlyWhereTheDefaultIsSafe(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-nnp-only", // file present, neither key written
		"containers-docker-defaults", // no file at all
	} {
		if got := evalCheck(t, checks.Check0004, fixture); got.Result != finding.Fail {
			t.Errorf("%s over %s = %s, want FAIL; an unset live-restore leaves the daemon on its off default: %s",
				checks.Check0004.ID, fixture, got.Result, got.Detail)
		}
		if got := evalCheck(t, checks.Check0005, fixture); got.Result != finding.Pass {
			t.Errorf("%s over %s = %s, want PASS; an unset experimental leaves the daemon on its off default: %s",
				checks.Check0005.ID, fixture, got.Result, got.Detail)
		}
	}

	// And the inverses, so neither half can pass by always answering the same
	// way. Both fixtures write the option down; each check must follow it.
	if got := evalCheck(t, checks.Check0004, "containers-docker-hardened"); got.Result != finding.Pass {
		t.Errorf("an explicitly true live-restore = %s, want PASS: %s", got.Result, got.Detail)
	}
	if got := evalCheck(t, checks.Check0005, "containers-docker-experimental-only"); got.Result != finding.Fail {
		t.Errorf("an explicitly true experimental = %s, want FAIL: %s", got.Result, got.Detail)
	}
}

// TestUnreadableConfigNeverProducesAVerdict. The denied fixture holds the
// hardened configuration and refuses to let the scan read it. A FAIL there
// would be a finding about a document nobody opened, and a PASS would be worse.
func TestUnreadableConfigNeverProducesAVerdict(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-denied",
		"containers-docker-malformed",
		"containers-docker-wrongtype",
		"containers-docker-notobject",
	} {
		for _, check := range daemonChecks {
			got := evalCheck(t, check, fixture)
			if got.Result != finding.Unknown {
				t.Errorf("%s = %s over %s, want UNKNOWN: %s", check.ID, got.Result, fixture, got.Detail)
			}
			// Docker is installed in all four, so none may be excused as
			// NOT_APPLICABLE either.
			if got.Result == finding.NotApplicable {
				t.Errorf("%s excused %s as not applicable, though dockerd is present", check.ID, fixture)
			}
		}
	}
}

// TestChecksAreIndependent. Each of these fixtures sets one option and not the
// other, so each must move exactly one check. A check that responded to the
// option it does not own is reading the wrong field — the bug that turns two
// checks into one noisy one.
func TestChecksAreIndependent(t *testing.T) {
	cases := []struct {
		fixture string
		want    map[string]finding.Result
	}{
		{"containers-docker-nnp-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Fail, // userns-remap absent
			"CONTAINERS-0002": finding.Pass, // no-new-privileges true
			"CONTAINERS-0003": finding.Fail, // icc absent, so permissive
			"CONTAINERS-0004": finding.Fail, // live-restore absent, so off
			"CONTAINERS-0005": finding.Pass, // experimental absent, so off
		}},
		{"containers-docker-icc-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Fail, // the only thing wrong
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
		}},
		{"containers-docker-no-live-restore", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Fail, // the only thing wrong
			"CONTAINERS-0005": finding.Pass,
		}},
		{"containers-docker-experimental-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Fail, // the only thing wrong
		}},
		{"containers-docker-hardened", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
		}},
		{"containers-docker-permissive", map[string]finding.Result{
			"CONTAINERS-0001": finding.Fail,
			"CONTAINERS-0002": finding.Fail,
			"CONTAINERS-0003": finding.Fail,
			"CONTAINERS-0004": finding.Fail,
			"CONTAINERS-0005": finding.Fail,
		}},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			for _, check := range daemonChecks {
				got := evalCheck(t, check, c.fixture)
				if want := c.want[check.ID]; got.Result != want {
					t.Errorf("%s = %s, want %s: %s", check.ID, got.Result, want, got.Detail)
				}
			}
		})
	}
}

// TestExplicitlyDisabledIsDistinguishedFromNeverSet. Both produce FAIL and the
// operator's position is different: one wrote the option down and chose the
// other value, the other never considered it. A report that told the first
// person to "set the option" without noticing they already had would read as
// though nobody looked, so the evidence has to say which happened.
func TestExplicitlyDisabledIsDistinguishedFromNeverSet(t *testing.T) {
	explicit := evalCheck(t, checks.Check0002, "containers-docker-explicit-off")
	silent := evalCheck(t, checks.Check0002, "containers-docker-permissive")
	absent := evalCheck(t, checks.Check0002, "containers-docker-defaults")

	if explicit.Result != finding.Fail || silent.Result != finding.Fail || absent.Result != finding.Fail {
		t.Fatal("all three must FAIL; the comparison below proves nothing otherwise")
	}

	got := map[string]string{
		"explicit": explicit.Evidence[0].Excerpt,
		"silent":   silent.Evidence[0].Excerpt,
		"absent":   absent.Evidence[0].Excerpt,
	}
	if got["explicit"] == got["silent"] || got["silent"] == got["absent"] || got["explicit"] == got["absent"] {
		t.Errorf("the three ways of failing are indistinguishable in the evidence: %v", got)
	}
	if !strings.Contains(got["explicit"], "explicitly disabled") {
		t.Errorf("an explicitly disabled option is not described as one: %q", got["explicit"])
	}
}

// TestEveryVerdictCarriesTheReadingCaveat.
//
// dockerd takes the same options as command-line flags and the stock unit
// passes some, so an option this module calls absent may be set there instead.
// A verdict drawn from the file that did not say so would be claiming more than
// it checked. The NOT_APPLICABLE case is exempt: it is about the absence of
// dockerd, not about what any file says.
func TestEveryVerdictCarriesTheReadingCaveat(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-hardened",
		"containers-docker-permissive",
		"containers-docker-defaults",
		"containers-docker-nnp-only",
		"containers-docker-icc-only",
		"containers-docker-no-live-restore",
		"containers-docker-experimental-only",
	} {
		for _, check := range daemonChecks {
			got := evalCheck(t, check, fixture)
			if !strings.Contains(got.Detail, "daemon.json only") {
				t.Errorf("%s over %s does not say it read only the file: %s", check.ID, fixture, got.Detail)
			}
		}
	}
}

// TestEvidenceResolvesInTheEvidenceStore. daemon.json is read through the
// seam's ordinary ReadFile, so unlike a binary its bytes are kept and a cited
// digest can be followed. A finding citing a digest the store does not hold
// sends an auditor after something nobody kept.
func TestEvidenceResolvesInTheEvidenceStore(t *testing.T) {
	for _, check := range daemonChecks {
		withFile := evalCheck(t, check, "containers-docker-hardened")
		if len(withFile.Evidence) == 0 || withFile.Evidence[0].SHA256 == "" {
			t.Errorf("%s cites no digest for a file it read: %+v", check.ID, withFile.Evidence)
		}

		// And the honest inverse: no file, no digest. There is nothing stored
		// to verify against because there was nothing to read.
		noFile := evalCheck(t, check, "containers-docker-defaults")
		if len(noFile.Evidence) == 0 {
			t.Fatalf("%s cites no evidence at all", check.ID)
		}
		if noFile.Evidence[0].SHA256 != "" {
			t.Errorf("%s cites digest %q for a file that does not exist", check.ID, noFile.Evidence[0].SHA256)
		}
		if noFile.Evidence[0].Source != "/etc/docker/daemon.json" {
			t.Errorf("%s does not name where it looked: %q", check.ID, noFile.Evidence[0].Source)
		}
	}
}

// TestMissingFactResolvesToUnknown. The runner is what turns a missing required
// fact into UNKNOWN, and this asserts both checks declared the dependency that
// makes it happen. A check naming the wrong fact ID would evaluate against a
// zero value — Installed false — and quietly report NOT_APPLICABLE for every
// host in the fleet.
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

// ---------------------------------------------------------------------------
// CONTAINERS-0006, which reads the unit rather than the file
// ---------------------------------------------------------------------------

func TestCheck0006SocketBinding(t *testing.T) {
	run(t, checks.Check0006, []tc{
		// The unit every distribution ships. -H fd:// is the socket systemd
		// hands over, and nothing is on the network.
		{fixture: "containers-docker-service-stock", result: finding.Pass,
			detailContains: "no TCP socket"},

		// The exposure, and the reason drop-ins are read: the unit file itself
		// still says fd://.
		{fixture: "containers-docker-service-tcp", result: finding.Fail,
			severity: finding.Critical, detailContains: "tcp://0.0.0.0:2375"},

		// Not reachable from the network. Reachable by every local user, by
		// every --network=host container, and by anything that can be talked
		// into making a request from this host.
		{fixture: "containers-docker-service-loopback", result: finding.Fail,
			severity: finding.High, detailContains: "loopback"},

		// The supported way to put the API on the network.
		{fixture: "containers-docker-service-tls", result: finding.Pass,
			detailContains: "client-certificate verification"},

		// The same, with the flag and the certificates configured in
		// different files.
		{fixture: "containers-docker-service-tls-in-json", result: finding.Pass,
			detailContains: "/etc/docker/daemon.json"},

		// systemd applies the higher-precedence file of the two and ignores
		// the other, so the tcp:// in /lib is not in force.
		{fixture: "containers-docker-service-shadowed", result: finding.Pass,
			detailContains: "no TCP socket"},

		// A drop-in is the single most likely place for the flag that changes
		// the answer, so an unread one is not an absence.
		{fixture: "containers-docker-service-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "was not read"},

		// The flags are in /etc/default/docker, which this collector does not
		// read. The variable survives as a token and the check says so.
		{fixture: "containers-docker-service-envvar", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "$DOCKER_OPTS"},

		// A binding that was found outranks a file that was not read.
		{fixture: "containers-docker-service-tcp-denied", result: finding.Fail,
			severity: finding.Critical, detailContains: "tcp://0.0.0.0:2375"},

		// systemd refuses to start a masked unit, so its command line is not
		// in force and no verdict may be drawn from it.
		{fixture: "containers-docker-service-masked", result: finding.NotApplicable,
			detailContains: "masked"},

		// Docker installed, started some other way. Not a pass: this check
		// cannot see that command line and says so.
		{fixture: "containers-docker-hardened", result: finding.NotApplicable,
			detailContains: "started some other way"},

		// No Docker at all.
		{fixture: "containers-absent", result: finding.NotApplicable,
			detailContains: "no docker.service"},
	})
}

// TestTheVerdictComesFromTheEffectiveCommandLine is the property that
// separates this check from a grep of docker.service.
//
// Both fixtures ship the identical vendor unit, which binds -H fd:// and
// nothing else. The verdicts are opposite, and the whole of the difference is
// a file in a .d directory that systemd folds on top.
func TestTheVerdictComesFromTheEffectiveCommandLine(t *testing.T) {
	stock := evalCheck(t, checks.Check0006, "containers-docker-service-stock")
	exposed := evalCheck(t, checks.Check0006, "containers-docker-service-tcp")

	if stock.Result != finding.Pass || exposed.Result != finding.Fail {
		t.Fatalf("stock = %s, drop-in = %s; want PASS and FAIL", stock.Result, exposed.Result)
	}
	if !strings.Contains(exposed.Evidence[0].Source, "docker.service.d") {
		t.Errorf("the finding cites %q rather than the drop-in that caused it", exposed.Evidence[0].Source)
	}
	if exposed.Evidence[0].Line == 0 {
		t.Error("the finding cites no line; an operator has to be told where to look")
	}
}

// TestAShadowedDropInDoesNotCauseAFinding. The same tcp:// binding is present
// in both fixtures; in one of them systemd would never apply it. A check that
// read every .conf it found would report a critical exposure on a host
// somebody had deliberately fixed.
func TestAShadowedDropInDoesNotCauseAFinding(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "containers-docker-service-shadowed")
	if got.Result != finding.Pass {
		t.Errorf("= %s, want PASS: the /lib drop-in is shadowed by the /etc one and is not applied: %s", got.Result, got.Detail)
	}
}

// TestAFoundBindingOutranksAnUnreadFile is ADR-0014 applied to this check: an
// incomplete examination invalidates a negative result and never a positive
// one. The fixture has an unreadable drop-in *and* a binding in one that could
// be read, and answering UNKNOWN there would suppress a critical finding on
// the grounds that the host might have been worse.
func TestAFoundBindingOutranksAnUnreadFile(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "containers-docker-service-tcp-denied")
	if got.Result != finding.Fail {
		t.Errorf("= %s, want FAIL: a binding that was found is a finding whatever else went unread: %s", got.Result, got.Detail)
	}
}

// TestTLSVerifyIsHonouredFromEitherFile. -H lives in the unit and tlsverify
// may live in daemon.json; they are different options, so dockerd accepts the
// split. A check that read only the unit would call this host's mutually
// authenticated endpoint an open one.
func TestTLSVerifyIsHonouredFromEitherFile(t *testing.T) {
	inUnit := evalCheck(t, checks.Check0006, "containers-docker-service-tls")
	inJSON := evalCheck(t, checks.Check0006, "containers-docker-service-tls-in-json")

	if inUnit.Result != finding.Pass || inJSON.Result != finding.Pass {
		t.Fatalf("unit = %s, daemon.json = %s; want PASS from both", inUnit.Result, inJSON.Result)
	}
	if !strings.Contains(inJSON.Detail, "/etc/docker/daemon.json") {
		t.Errorf("the pass does not say where the verification was configured: %s", inJSON.Detail)
	}
	// A pass reached this way is still an API on the network, and the
	// certificates behind the flag were not examined. Saying so is what stops
	// it reading as more assurance than it is.
	for _, want := range []string{"on the network", "not examined here"} {
		if !strings.Contains(inUnit.Detail, want) {
			t.Errorf("the pass omits %q: %s", want, inUnit.Detail)
		}
	}
}

// TestEncryptionWithoutVerificationStillFails. --tls encrypts and asks nothing
// of the client, so anyone who can reach the port still gets a root shell over
// a nicely encrypted channel. An operator who set it believes the socket is
// protected, and a finding that said "no TLS" would be both wrong and
// unpersuasive.
func TestEncryptionWithoutVerificationStillFails(t *testing.T) {
	got := evalHandBuilt(t, []string{"/usr/bin/dockerd", "-H", "tcp://0.0.0.0:2376", "--tls"})
	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: --tls without --tlsverify authenticates nobody: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "--tls is set and --tlsverify is not") {
		t.Errorf("the finding does not address the flag the operator actually set: %s", got.Detail)
	}
}

// TestABareHostPortIsStillTCP. dockerd accepts "-H 0.0.0.0:2375" and binds it
// exactly as it binds the tcp:// form. Reading that as unrecognised would turn
// the shortest way to write the finding into the one spelling that escapes it.
func TestABareHostPortIsStillTCP(t *testing.T) {
	got := evalHandBuilt(t, []string{"/usr/bin/dockerd", "-H", "0.0.0.0:2375"})
	if got.Result != finding.Fail {
		t.Fatalf("= %s, want FAIL: a bare host:port is a TCP binding: %s", got.Result, got.Detail)
	}
	if got.Severity != finding.Critical {
		t.Errorf("severity = %s, want CRITICAL: 0.0.0.0 is every interface", got.Severity)
	}
}

// evalHandBuilt runs CONTAINERS-0006 over a command line written here rather
// than parsed out of a fixture.
//
// It is the exception to this file's rule of testing the vertical slice, and
// it earns it: the properties below are about one token in an argv, and a
// fixture per token would be eight directories of boilerplate to assert
// something the collector has already been shown to parse correctly.
func evalHandBuilt(t *testing.T, argv []string) finding.Finding {
	t.Helper()

	fs := fact.NewSet()
	fs.Put(fact.DockerDaemon{
		State: fact.DockerConfigAbsent, Path: "/etc/docker/daemon.json",
		Installed: true, DaemonPath: "/usr/bin/dockerd",
	})
	fs.Put(fact.DockerService{
		State: fact.DockerUnitPresent,
		Unit:  fact.DockerServiceUnit,
		Path:  "/lib/systemd/system/docker.service",
		Fragments: []fact.UnitFragment{
			{Path: "/lib/systemd/system/docker.service", Kind: fact.FragmentUnit, State: fact.DockerUnitPresent},
		},
		ExecStart: []fact.DockerExec{{
			Origin: "/lib/systemd/system/docker.service", Line: 9, Argv: argv,
		}},
	})

	got := catalog.MustNew(checks.Check0006).Evaluate(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// TestUnitVerdictsCarryTheirOwnCaveat is TestEveryVerdictCarriesTheReadingCaveat
// for the other half of the module, and it is the exact mirror.
//
// The daemon checks read daemon.json and have to say a flag in the unit is
// invisible to them. This one reads the unit and has to say a socket in
// daemon.json — or in docker.socket, which nothing here reads at all — is
// invisible to it. Neither file is the whole answer.
func TestUnitVerdictsCarryTheirOwnCaveat(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-service-stock",
		"containers-docker-service-tcp",
		"containers-docker-service-loopback",
		"containers-docker-service-tls",
		"containers-docker-service-shadowed",
		"containers-docker-service-denied",
		"containers-docker-service-envvar",
		"containers-docker-service-tcp-denied",
	} {
		got := evalCheck(t, checks.Check0006, fixture)
		if !strings.Contains(got.Detail, "docker.service and its drop-ins only") {
			t.Errorf("over %s the verdict does not say what it read: %s", fixture, got.Detail)
		}
		if !strings.Contains(got.Detail, "docker.socket") {
			t.Errorf("over %s the verdict does not name the socket unit it did not read: %s", fixture, got.Detail)
		}
	}
}

// TestTheUnitCheckIsSilentOnHostsWithoutOne. The daemon.json fixtures carry no
// systemd unit, and CONTAINERS-0006 must decline to judge them rather than
// report a daemon that binds nothing. The inverse also holds: the five daemon
// checks are unaffected by a unit that is there.
func TestTheUnitCheckIsSilentOnHostsWithoutOne(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-hardened",
		"containers-docker-permissive",
		"containers-docker-defaults",
		"containers-docker-denied",
	} {
		if got := evalCheck(t, checks.Check0006, fixture); got.Result != finding.NotApplicable {
			t.Errorf("CONTAINERS-0006 over %s = %s, want NOT_APPLICABLE: %s", fixture, got.Result, got.Detail)
		}
	}

	// containers-docker-service-tls-in-json is hardened in daemon.json as well
	// as in the unit, so every check in the module passes over it. A daemon
	// check that had started reading the unit would show up here.
	for _, check := range all {
		if got := evalCheck(t, check, "containers-docker-service-tls-in-json"); got.Result != finding.Pass {
			t.Errorf("%s over a host hardened in both files = %s: %s", check.ID, got.Result, got.Detail)
		}
	}
}

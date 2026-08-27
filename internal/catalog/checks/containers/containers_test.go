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
	checks.Check0005, checks.Check0006, checks.Check0007, checks.Check0008,
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

// configGated is daemonChecks plus CONTAINERS-0007 and -0008: every check
// whose verdict is drawn from daemon.json and which therefore shares
// applicable() as its gate.
//
// The last two are here and not in daemonChecks because of one sentence each
// has to say that the others do not. -0007's subject is the hosts key, but the
// question "is that socket protected" is answered by tlsverify, which may be
// set on dockerd's command line instead. -0008's subject is the log-driver
// key, and the driver itself may be set on that command line. Neither can
// claim to have read daemon.json *only*, and
// TestEveryVerdictCarriesTheReadingCaveat asserts exactly that phrase.
// Everything else the daemon invariants assert is as true of both as of the
// other five.
var configGated = append(append([]catalog.Check{}, daemonChecks...), checks.Check0007, checks.Check0008)

// defaultIsUnsafe is the subset of the module whose option the daemon leaves
// off, so that a host which says nothing is running the value the check
// objects to. CONTAINERS-0005 is deliberately not in it: experimental defaults
// to off, and silence there is the safe state rather than the permissive one.
// The split is the module's one real asymmetry and several invariants below
// turn on it.
var defaultIsUnsafe = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003, checks.Check0004, checks.Check0008,
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
	for _, check := range configGated {
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
		for _, check := range configGated {
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
			"CONTAINERS-0007": finding.Pass, // no hosts key, so this file binds nothing
			"CONTAINERS-0008": finding.Pass, // log-driver journald
		}},
		{"containers-docker-icc-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Fail, // the only thing wrong
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Pass,
		}},
		{"containers-docker-no-live-restore", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Fail, // the only thing wrong
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Pass,
		}},
		{"containers-docker-experimental-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Fail, // the only thing wrong
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Pass,
		}},
		{"containers-docker-hardened", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass, // hosts binds the unix socket only
			"CONTAINERS-0008": finding.Pass, // log-driver journald
		}},
		{"containers-docker-hosts-loopback", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Fail, // the only thing wrong
			"CONTAINERS-0008": finding.Pass,
		}},
		{"containers-docker-permissive", map[string]finding.Result{
			"CONTAINERS-0001": finding.Fail,
			"CONTAINERS-0002": finding.Fail,
			"CONTAINERS-0003": finding.Fail,
			"CONTAINERS-0004": finding.Fail,
			"CONTAINERS-0005": finding.Fail,
			"CONTAINERS-0007": finding.Fail, // hosts carries tcp://0.0.0.0:2375
			"CONTAINERS-0008": finding.Fail, // no log-driver, so json-file unbounded
		}},

		// The logging fixtures, each hardened everywhere else so that only
		// CONTAINERS-0008 moves. They are the other half of the same property:
		// a check that responded to an option it does not own would show up
		// here as a second verdict changing.
		{"containers-docker-log-rotated", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Pass, // json-file bounded by max-size
		}},
		{"containers-docker-log-unbounded", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Fail, // the only thing wrong
		}},
		{"containers-docker-log-none", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Fail, // the only thing wrong
		}},
		{"containers-docker-log-plugin", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Unknown, // a driver this build does not know
		}},
		{"containers-docker-log-in-unit", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
			"CONTAINERS-0004": finding.Pass,
			"CONTAINERS-0005": finding.Pass,
			"CONTAINERS-0007": finding.Pass,
			"CONTAINERS-0008": finding.Pass, // the driver is in the drop-in
		}},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			for _, check := range configGated {
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
	for _, check := range configGated {
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

// ---------------------------------------------------------------------------
// CONTAINERS-0007, the same exposure written in the other file
// ---------------------------------------------------------------------------

func TestCheck0007ConfiguredSocketBinding(t *testing.T) {
	run(t, checks.Check0007, []tc{
		// hosts binds the unix socket and nothing else.
		{fixture: "containers-docker-hardened", result: finding.Pass,
			detailContains: "local to the host"},

		// hosts written down and left empty: it binds nothing.
		{fixture: "containers-docker-hosts-empty", result: finding.Pass,
			detailContains: "binds no TCP socket"},

		// No hosts key. The sockets are the unit's business, and the check
		// that reads the unit is named rather than left implicit.
		{fixture: "containers-docker-nnp-only", result: finding.Pass,
			detailContains: "CONTAINERS-0006"},

		// No daemon.json at all, which is the same position by a different
		// route, and the operator is told the file is missing.
		{fixture: "containers-docker-defaults", result: finding.Pass,
			detailContains: "no /etc/docker/daemon.json"},

		// The exposure.
		{fixture: "containers-docker-permissive", result: finding.Fail,
			severity: finding.Critical, detailContains: "tcp://0.0.0.0:2375"},

		// Sockets in the file, unit stripped of its -H so dockerd will start.
		{fixture: "containers-docker-hosts-split", result: finding.Fail,
			severity: finding.Critical, detailContains: "tcp://0.0.0.0:2375"},

		// Reachable by every local user rather than by the network.
		{fixture: "containers-docker-hosts-loopback", result: finding.Fail,
			severity: finding.High, detailContains: "loopback"},

		// The supported way to put the API on the network, configured here.
		{fixture: "containers-docker-hosts-tls", result: finding.Pass,
			detailContains: "client-certificate verification"},

		// The module's ordinary gate, inherited unchanged.
		{fixture: "containers-docker-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "valid JSON"},
		{fixture: "containers-absent", result: finding.NotApplicable,
			detailContains: "no dockerd binary"},
	})
}

// TestTheTwoSocketChecksAreIndependent is the property the pair exists for,
// and the one a reader is most entitled to be sceptical about: two checks with
// the same title, the same severity and the same shared socket parsing, whose
// only difference is which file they read.
//
// Each fixture binds a TCP socket in exactly one of the two files. If either
// check were answering for the other — reading the wrong fact, or falling back
// to it when its own is silent — one of these four assertions fails.
func TestTheTwoSocketChecksAreIndependent(t *testing.T) {
	// The unit binds tcp://; this host has no daemon.json at all.
	inUnit := "containers-docker-service-tcp"
	if got := evalCheck(t, checks.Check0006, inUnit); got.Result != finding.Fail {
		t.Errorf("CONTAINERS-0006 over %s = %s, want FAIL: %s", inUnit, got.Result, got.Detail)
	}
	if got := evalCheck(t, checks.Check0007, inUnit); got.Result != finding.Pass {
		t.Errorf("CONTAINERS-0007 over %s = %s, want PASS: the binding is in the unit, not in this file: %s",
			inUnit, got.Result, got.Detail)
	}

	// daemon.json binds tcp://; the unit has been stripped of its -H, which is
	// what dockerd's refusal to take hosts from two places forces an operator
	// to do.
	inFile := "containers-docker-hosts-split"
	if got := evalCheck(t, checks.Check0006, inFile); got.Result != finding.Pass {
		t.Errorf("CONTAINERS-0006 over %s = %s, want PASS: the unit's command line binds nothing: %s",
			inFile, got.Result, got.Detail)
	}
	if got := evalCheck(t, checks.Check0007, inFile); got.Result != finding.Fail {
		t.Errorf("CONTAINERS-0007 over %s = %s, want FAIL: %s", inFile, got.Result, got.Detail)
	}
}

// TestNeitherSocketCheckClaimsToBeTheWholeAnswer. Each reads one file and each
// says so, naming the other's subject. A finding that implied it had covered
// both would be the one way this pair could mislead: an operator reading a
// PASS from either would believe the API is not on the network.
func TestNeitherSocketCheckClaimsToBeTheWholeAnswer(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-hardened",
		"containers-docker-permissive",
		"containers-docker-hosts-empty",
		"containers-docker-hosts-loopback",
		"containers-docker-hosts-tls",
		"containers-docker-hosts-split",
		"containers-docker-defaults",
	} {
		got := evalCheck(t, checks.Check0007, fixture)
		if !strings.Contains(got.Detail, "the hosts key in /etc/docker/daemon.json") {
			t.Errorf("over %s the verdict does not say what it read: %s", fixture, got.Detail)
		}
		// The two things it did not read, named so a reader can go and look.
		for _, want := range []string{"CONTAINERS-0006", "docker.socket"} {
			if !strings.Contains(got.Detail, want) {
				t.Errorf("over %s the verdict omits %q: %s", fixture, want, got.Detail)
			}
		}
	}
}

// TestSilenceMovesTheQuestionRatherThanAnsweringIt is the reasoning behind
// -0007's treatment of an absent hosts key, written down as a test because the
// verdict is a PASS and a PASS is the answer that gets copied without thought.
//
// An absent hosts does not mean the daemon listens on nothing. It means this
// file does not decide, and the systemd unit does. The pass is therefore only
// sound because CONTAINERS-0006 exists to read that unit — so the assertion is
// not just that -0007 passes, but that -0006 reaches a real verdict on the same
// host. A future in which -0006 were removed or narrowed and -0007 kept its
// pass would be a silent hole exactly where this module is most load-bearing.
func TestSilenceMovesTheQuestionRatherThanAnsweringIt(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-service-stock", // a unit, no daemon.json
		"containers-docker-service-tcp",   // a unit that binds tcp://
	} {
		quiet := evalCheck(t, checks.Check0007, fixture)
		if quiet.Result != finding.Pass {
			t.Errorf("CONTAINERS-0007 over %s = %s, want PASS: this file binds nothing: %s",
				fixture, quiet.Result, quiet.Detail)
		}
		if !strings.Contains(quiet.Evidence[0].Excerpt, "the sockets come from the unit") {
			t.Errorf("over %s the evidence does not record where the sockets actually come from: %q",
				fixture, quiet.Evidence[0].Excerpt)
		}

		// The half that makes the pass sound.
		covered := evalCheck(t, checks.Check0006, fixture)
		if covered.Result != finding.Pass && covered.Result != finding.Fail {
			t.Errorf("CONTAINERS-0007 passed %s by deferring to CONTAINERS-0006, which answered %s: %s",
				fixture, covered.Result, covered.Detail)
		}
	}
}

// TestTheThreeWaysOfBindingNothingAreDistinguishable. `hosts` is a []string on
// the fact, where nil and [] are one value, so the distinction survives only
// because Keys records which top-level keys the document set. Three operators
// are in three different positions — one asked for no sockets, one left it to
// the unit, one has no configuration file — and a report that rendered all
// three alike would be hiding the thing the evidence exists to show.
func TestTheThreeWaysOfBindingNothingAreDistinguishable(t *testing.T) {
	got := map[string]string{}
	for name, fixture := range map[string]string{
		"empty":  "containers-docker-hosts-empty", // "hosts": []
		"unset":  "containers-docker-nnp-only",    // no hosts key
		"nofile": "containers-docker-defaults",    // no daemon.json
	} {
		f := evalCheck(t, checks.Check0007, fixture)
		if f.Result != finding.Pass {
			t.Fatalf("%s: = %s, want PASS; the comparison below proves nothing otherwise", name, f.Result)
		}
		got[name] = f.Evidence[0].Excerpt
	}

	if got["empty"] == got["unset"] || got["unset"] == got["nofile"] || got["empty"] == got["nofile"] {
		t.Errorf("the three ways of binding nothing are indistinguishable in the evidence: %v", got)
	}
	if !strings.Contains(got["empty"], "explicitly empty") {
		t.Errorf("an explicitly empty hosts is not described as one: %q", got["empty"])
	}
}

// TestTLSVerifyIsHonouredFromEitherFileForBothChecks is the shared reading in
// sockets.go asserted from both sides.
//
// tlsverify and hosts are different options, so dockerd does not refuse the
// split and an operator may reasonably bind in one file and configure the
// certificates in the other. Either check reading only its own file would
// report a mutually authenticated endpoint as an open one — a critical false
// positive on a host that did the work.
func TestTLSVerifyIsHonouredFromEitherFileForBothChecks(t *testing.T) {
	// Socket in the unit, certificates in daemon.json.
	if got := evalCheck(t, checks.Check0006, "containers-docker-service-tls-in-json"); got.Result != finding.Pass {
		t.Errorf("CONTAINERS-0006 = %s over a unit socket verified from daemon.json: %s", got.Result, got.Detail)
	}
	// Socket and certificates both in daemon.json.
	if got := evalCheck(t, checks.Check0007, "containers-docker-hosts-tls"); got.Result != finding.Pass {
		t.Errorf("CONTAINERS-0007 = %s over a configured socket with tlsverify set: %s", got.Result, got.Detail)
	}
}

// TestTheTwoSocketChecksReadASpecTheSameWay. They share sockets.go so that one
// configuration cannot be Critical in one file and a pass in the other, and
// this is that property rather than the sharing that implements it: swapping
// the two for a second reading of dockerd's grammar would have to keep this
// passing.
func TestTheTwoSocketChecksReadASpecTheSameWay(t *testing.T) {
	cases := []struct {
		spec string
		fail bool
		sev  finding.Severity
	}{
		{"tcp://0.0.0.0:2375", true, finding.Critical},
		{"tcp://127.0.0.1:2375", true, finding.High},
		{"0.0.0.0:2375", true, finding.Critical}, // bare host:port is TCP
		{"unix:///var/run/docker.sock", false, ""},
		{"fd://", false, ""},
	}

	for _, c := range cases {
		viaUnit := evalHandBuilt(t, []string{"/usr/bin/dockerd", "-H", c.spec})
		viaFile := evalConfiguredHosts(t, []string{c.spec})

		if (viaUnit.Result == finding.Fail) != c.fail || (viaFile.Result == finding.Fail) != c.fail {
			t.Errorf("%s: unit = %s, daemon.json = %s, want fail=%v\n unit: %s\n file: %s",
				c.spec, viaUnit.Result, viaFile.Result, c.fail, viaUnit.Detail, viaFile.Detail)
			continue
		}
		if c.fail && (viaUnit.Severity != c.sev || viaFile.Severity != c.sev) {
			t.Errorf("%s: severity unit = %s, daemon.json = %s, want %s",
				c.spec, viaUnit.Severity, viaFile.Severity, c.sev)
		}
	}
}

// evalConfiguredHosts runs CONTAINERS-0007 over a hosts array written here.
// It is evalHandBuilt's counterpart, and it exists for the same reason: the
// property above is about one string, and a fixture per string would be five
// directories of boilerplate.
func evalConfiguredHosts(t *testing.T, hosts []string) finding.Finding {
	t.Helper()

	fs := fact.NewSet()
	fs.Put(fact.DockerDaemon{
		State: fact.DockerConfigPresent, Path: "/etc/docker/daemon.json",
		Digest:    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		Installed: true, DaemonPath: "/usr/bin/dockerd",
		Keys:  []string{"hosts"},
		Hosts: hosts,
	})
	fs.Put(fact.DockerService{
		State: fact.DockerUnitAbsent,
		Unit:  fact.DockerServiceUnit,
		Path:  "/usr/lib/systemd/system/docker.service",
	})

	got := catalog.MustNew(checks.Check0007).Evaluate(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

// ---------------------------------------------------------------------------
// CONTAINERS-0008, which reads both files for one option
// ---------------------------------------------------------------------------

func TestCheck0008LoggingDriver(t *testing.T) {
	run(t, checks.Check0008, []tc{
		// The driver named and safe. journald hands the output to the daemon
		// that already owns rotation on this host.
		{fixture: "containers-docker-hardened", result: finding.Pass,
			detailContains: "systemd journal"},

		// No daemon.json at all, and no unit to have set the flag either. The
		// compiled-in default is json-file with no size limit, and the default
		// is the finding.
		{fixture: "containers-docker-defaults", result: finding.Fail, severity: finding.Low,
			detailContains: "No logging driver is configured"},

		// The file exists and is silent on logging. Same verdict as a host
		// with no file at all, and the same sentence, because the position is
		// the same one: nothing named a driver, so the daemon's own default
		// is in force. What separates the two is defaultsNote, which says
		// whether there is a file to add the key to.
		{fixture: "containers-docker-permissive", result: finding.Fail, severity: finding.Low,
			detailContains: "No logging driver is configured"},

		// json-file written down and bounded, which is Docker's own advice for
		// keeping the default driver.
		{fixture: "containers-docker-log-rotated", result: finding.Pass,
			detailContains: "rotates at a fixed size"},

		// json-file written down, log-opts written down, and nothing in them
		// limits the size. The host somebody configured and still left
		// unbounded.
		{fixture: "containers-docker-log-unbounded", result: finding.Fail, severity: finding.Low,
			detailContains: "no max-size log option"},

		// Logging turned off outright.
		{fixture: "containers-docker-log-none", result: finding.Fail, severity: finding.Low,
			detailContains: "discarded as it is produced"},

		// A logging plugin. Not a pass, because this build cannot say what it
		// does; not a fail, because it is almost certainly the operator's own
		// answer to this check.
		{fixture: "containers-docker-log-plugin", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "not a driver this build recognises"},

		// The driver configured on dockerd's command line rather than in the
		// file. A check reading only daemon.json reports the default here.
		{fixture: "containers-docker-log-in-unit", result: finding.Pass,
			detailContains: "max-size log option is set"},

		// A log option of the wrong type must not cost the key names, and the
		// document still sets no bound.
		{fixture: "containers-docker-log-numeric-opt", result: finding.Fail, severity: finding.Low,
			detailContains: "no max-size log option"},

		// A drop-in that could not be read could be carrying the flag.
		{fixture: "containers-docker-service-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could be carrying a --log-driver flag"},

		// So could a $DOCKER_OPTS this scan does not expand.
		{fixture: "containers-docker-service-envvar", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "environment file this scan does not read"},

		// The gates, which are the module's and not this check's.
		{fixture: "containers-absent", result: finding.NotApplicable,
			detailContains: "No dockerd binary"},
		{fixture: "containers-docker-denied", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "could not be read"},
		{fixture: "containers-docker-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "not valid JSON"},
	})
}

// TestTheTwoUnboundedHostsAreToldApart.
//
// Both fail and the operators are in different positions. One host never named
// a driver, so the remedy is to choose one; the other named json-file and did
// not bound it, so the remedy is a log option on a line that already exists. A
// report that gave both the same sentence would send the second operator
// looking for a log-driver key they can already see.
func TestTheTwoUnboundedHostsAreToldApart(t *testing.T) {
	unset := evalCheck(t, checks.Check0008, "containers-docker-permissive")
	named := evalCheck(t, checks.Check0008, "containers-docker-log-unbounded")

	if unset.Result != finding.Fail || named.Result != finding.Fail {
		t.Fatalf("expected both to fail: %s / %s", unset.Result, named.Result)
	}
	if !strings.Contains(unset.Detail, "No logging driver is configured") {
		t.Errorf("a silent file does not say nothing named a driver: %s", unset.Detail)
	}
	if !strings.Contains(named.Detail, "The default logging driver is json-file with no max-size log option") {
		t.Errorf("a named json-file does not say the key is there and the bound is not: %s", named.Detail)
	}
	if unset.Detail == named.Detail {
		t.Errorf("an unset driver and an unbounded one read identically: %s", unset.Detail)
	}

	// And the evidence says which of the two the reader is looking at,
	// including the log-opts the second host did write.
	if !strings.Contains(unset.Evidence[0].Excerpt, "not set in this file") {
		t.Errorf("evidence does not show the key is unset: %q", unset.Evidence[0].Excerpt)
	}
	if !strings.Contains(named.Evidence[0].Excerpt, "log-opts keys: labels, tag") {
		t.Errorf("evidence does not show what was configured instead: %q", named.Evidence[0].Excerpt)
	}
}

// TestABoundIsWhatSeparatesTwoJsonFileHosts.
//
// containers-docker-log-rotated and containers-docker-log-unbounded both name
// json-file and both write log-opts. The only difference is max-size, and it
// has to be the whole difference: a check that passed on "log-opts is present"
// would pass the host whose options are a tag and a label set, which is the
// most common way of configuring json-file without bounding it.
func TestABoundIsWhatSeparatesTwoJsonFileHosts(t *testing.T) {
	if got := evalCheck(t, checks.Check0008, "containers-docker-log-rotated"); got.Result != finding.Pass {
		t.Errorf("json-file with max-size = %s, want PASS: %s", got.Result, got.Detail)
	}
	if got := evalCheck(t, checks.Check0008, "containers-docker-log-unbounded"); got.Result != finding.Fail {
		t.Errorf("json-file with log-opts that bound nothing = %s, want FAIL: %s", got.Result, got.Detail)
	}
}

// TestADriverInTheUnitIsNotTheDefault is this check's version of the reasoning
// CONTAINERS-0007 applies to sockets.
//
// dockerd takes --log-driver on its command line, and configuration management
// that owns the unit but not daemon.json puts it there. Reading only the file
// would report the compiled-in default on a host that configured the thing
// being asked for — a FAIL against somebody who did the work, which is the
// class of finding that teaches an operator to stop reading the report.
//
// The verdict also has to say where it looked, because the remedy is in the
// drop-in and an operator sent to daemon.json finds nothing there.
func TestADriverInTheUnitIsNotTheDefault(t *testing.T) {
	got := evalCheck(t, checks.Check0008, "containers-docker-log-in-unit")

	if got.Result != finding.Pass {
		t.Fatalf("a driver set in a drop-in = %s, want PASS: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "logging.conf") {
		t.Errorf("the verdict does not name the file that set it: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "rather than in /etc/docker/daemon.json") {
		t.Errorf("the verdict does not say the file it is filed against is not where the setting is: %s", got.Detail)
	}

	// Two evidence entries: the file this check is about, and the line that
	// actually decided it.
	if len(got.Evidence) != 2 {
		t.Fatalf("evidence = %d entries, want 2: %+v", len(got.Evidence), got.Evidence)
	}
	if got.Evidence[0].Source != "/etc/docker/daemon.json" {
		t.Errorf("first evidence is not the file the check is filed against: %q", got.Evidence[0].Source)
	}
	if !strings.HasSuffix(got.Evidence[1].Source, "logging.conf") || got.Evidence[1].Line == 0 {
		t.Errorf("second evidence does not point at the drop-in line: %+v", got.Evidence[1])
	}
	if !strings.Contains(got.Evidence[1].Excerpt, "--log-driver=json-file") {
		t.Errorf("second evidence does not carry the flag: %q", got.Evidence[1].Excerpt)
	}
}

// TestAnUnreadCommandLineIsNotADefault.
//
// The failure this check makes most often is an absence — nothing named a
// driver, so the default applies — and an absence is the one conclusion an
// incomplete reading can overturn (ADR-0014). A drop-in that could not be
// opened and a $DOCKER_OPTS that was not expanded are both places a
// --log-driver lives, and neither may be reported as a host running the
// default.
func TestAnUnreadCommandLineIsNotADefault(t *testing.T) {
	for _, c := range []struct {
		fixture string
		reason  finding.UnknownReason
	}{
		{"containers-docker-service-denied", finding.ReasonPermission},
		{"containers-docker-service-envvar", finding.ReasonAmbiguousState},
	} {
		got := evalCheck(t, checks.Check0008, c.fixture)
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s, want UNKNOWN: %s", c.fixture, got.Result, got.Detail)
		}
		if got.UnknownReason != c.reason {
			t.Errorf("%s reason = %q, want %q", c.fixture, got.UnknownReason, c.reason)
		}
	}

	// The inverse, so the check cannot pass this test by never reaching a
	// verdict on a unit at all: the stock unit reads completely, names no
	// driver, and is therefore a host running the unbounded default.
	stock := evalCheck(t, checks.Check0008, "containers-docker-service-stock")
	if stock.Result != finding.Fail {
		t.Errorf("a fully-read unit that names no driver = %s, want FAIL: %s", stock.Result, stock.Detail)
	}
}

// TestAnUnknownDriverIsNeitherAPassNorAFail.
//
// Docker supports third-party logging plugins. A name this build does not know
// is far more likely to be one somebody installed to ship logs — which is this
// check's own remedy — than a mistake, so failing it would report the answer as
// the finding. Passing it would be worse: it would be asserting a property of
// software this build has never heard of.
func TestAnUnknownDriverIsNeitherAPassNorAFail(t *testing.T) {
	got := evalCheck(t, checks.Check0008, "containers-docker-log-plugin")

	if got.Result != finding.Unknown {
		t.Fatalf("an unrecognised driver = %s, want UNKNOWN: %s", got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "loki") {
		t.Errorf("the verdict does not name the driver it did not recognise: %s", got.Detail)
	}
}

// TestNoLogOptionValueReachesAFinding is the collector's privacy trade carried
// through to the report.
//
// log-opts is where splunk-token and awslogs-credentials-endpoint live, so the
// fact records the key names and never the values. A finding renders the fact,
// and a check that had reached for a value would put it in a terminal, in
// --json output and in whatever an operator pastes into a ticket — which is
// the same disclosure the bundle was designed to avoid.
func TestNoLogOptionValueReachesAFinding(t *testing.T) {
	got := evalCheck(t, checks.Check0008, "containers-docker-log-plugin")

	const secret = "loki.example.internal"
	if strings.Contains(got.Detail, secret) {
		t.Errorf("a log-opt value reached the detail: %s", got.Detail)
	}
	for _, e := range got.Evidence {
		if strings.Contains(e.Excerpt, secret) {
			t.Errorf("a log-opt value reached an evidence excerpt: %q", e.Excerpt)
		}
	}
	// The key name is not a secret and is worth showing: it is how an operator
	// sees that they configured the driver and still did not bound it.
	if !strings.Contains(got.Evidence[0].Excerpt, "loki-url") {
		t.Errorf("evidence hides the key name as well as the value: %q", got.Evidence[0].Excerpt)
	}
}

// TestTheLoggingVerdictNamesItsOwnLimit.
//
// Every other caveat in this module is about which file was read. This one has
// a different limit to disclose: what it found is the daemon's *default*, and
// any container started with its own --log-driver, or with a logging block in
// a compose file, overrides it for itself. That is not in either file and is
// not in any fact this build collects, so a verdict that did not say so would
// be claiming to have audited the containers rather than the daemon.
func TestTheLoggingVerdictNamesItsOwnLimit(t *testing.T) {
	for _, fixture := range []string{
		"containers-docker-hardened",
		"containers-docker-defaults",
		"containers-docker-log-rotated",
		"containers-docker-log-unbounded",
		"containers-docker-log-none",
		"containers-docker-log-plugin",
		"containers-docker-log-in-unit",
		"containers-docker-service-denied",
	} {
		got := evalCheck(t, checks.Check0008, fixture)
		if !strings.Contains(got.Detail, "the daemon's default") {
			t.Errorf("over %s the verdict does not say it read a default: %s", fixture, got.Detail)
		}
		if !strings.Contains(got.Detail, "overrides it for itself") {
			t.Errorf("over %s the verdict does not name the per-container override: %s", fixture, got.Detail)
		}
	}
}

// TestTheLoggingCheckIsIndependentOfTheSocketChecks.
//
// All three read both files now, and all three could plausibly be written to
// share a gate they should not. containers-docker-log-none is hardened in
// every socket-related way and has no logging; containers-docker-service-tcp
// has the opposite shape. Each must move exactly its own check.
func TestTheLoggingCheckIsIndependentOfTheSocketChecks(t *testing.T) {
	logging := evalCheck(t, checks.Check0008, "containers-docker-log-none")
	if logging.Result != finding.Fail {
		t.Errorf("CONTAINERS-0008 over a host with logging off = %s, want FAIL: %s", logging.Result, logging.Detail)
	}
	if got := evalCheck(t, checks.Check0007, "containers-docker-log-none"); got.Result != finding.Pass {
		t.Errorf("CONTAINERS-0007 responded to the logging driver: %s", got.Detail)
	}

	// And the other way. The tcp fixture has no daemon.json, so its logging
	// verdict is the unbounded default — a FAIL that must be the default's and
	// not an echo of the socket finding beside it.
	if got := evalCheck(t, checks.Check0006, "containers-docker-service-tcp"); got.Result != finding.Fail {
		t.Errorf("CONTAINERS-0006 over the tcp fixture = %s, want FAIL: %s", got.Result, got.Detail)
	}
	sock := evalCheck(t, checks.Check0008, "containers-docker-service-tcp")
	if sock.Result != finding.Fail || sock.Severity != finding.Low {
		t.Errorf("CONTAINERS-0008 over the tcp fixture = %s/%s, want FAIL/LOW: %s", sock.Result, sock.Severity, sock.Detail)
	}
	if strings.Contains(sock.Detail, "tcp://") {
		t.Errorf("the logging verdict repeats the socket finding: %s", sock.Detail)
	}
}

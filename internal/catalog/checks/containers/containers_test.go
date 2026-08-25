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
var all = []catalog.Check{checks.Check0001, checks.Check0002, checks.Check0003}

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
	for _, check := range all {
		running := evalCheck(t, check, "containers-docker-defaults")
		if running.Result != finding.Fail {
			t.Errorf("%s = %s on a host with dockerd and no daemon.json, want FAIL: %s",
				check.ID, running.Result, running.Detail)
		}
		// And it has to say where the setting is coming from, because the
		// remedy is "create the file" rather than "edit the line".
		if !strings.Contains(running.Detail, "no /etc/docker/daemon.json") {
			t.Errorf("%s does not tell the operator there is no file to edit: %s", check.ID, running.Detail)
		}

		none := evalCheck(t, check, "containers-absent")
		if none.Result != finding.NotApplicable {
			t.Errorf("%s = %s on a host with no dockerd, want NOT_APPLICABLE: %s",
				check.ID, none.Result, none.Detail)
		}
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
		for _, check := range all {
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
		}},
		{"containers-docker-icc-only", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Fail, // the only thing wrong
		}},
		{"containers-docker-hardened", map[string]finding.Result{
			"CONTAINERS-0001": finding.Pass,
			"CONTAINERS-0002": finding.Pass,
			"CONTAINERS-0003": finding.Pass,
		}},
		{"containers-docker-permissive", map[string]finding.Result{
			"CONTAINERS-0001": finding.Fail,
			"CONTAINERS-0002": finding.Fail,
			"CONTAINERS-0003": finding.Fail,
		}},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			for _, check := range all {
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
	} {
		for _, check := range all {
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
	for _, check := range all {
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

package logging_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/logging"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/logging"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the LOGGING module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003,
	checks.Check0004, checks.Check0005,
}

// rsyslogChecks are the checks that cannot answer without an rsyslog
// configuration. Listed rather than derived so that adding a sixth without
// thinking about the journald-only host fails a test.
var rsyslogChecks = []catalog.Check{checks.Check0001, checks.Check0002, checks.Check0005}

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

			if got.CheckID != check.ID || got.Module != "LOGGING" {
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

// TestBothRsyslogSyntaxesReachTheSameVerdict is the property this whole module
// is built around, and it is the one worth asserting hardest.
//
// logging-compliant and logging-legacy describe the same host. One is written
// entirely in RainerScript — module(), global(), include(file=), omfwd — and
// the other entirely in the sysklogd and $-directive syntaxes rsyslog
// inherited: $ModLoad, $FileCreateMode, $IncludeConfig, `*.* @@host`. Both
// appear in the wild, frequently in the same file, and a parser that
// understood only one would report a correctly-forwarding host as not
// forwarding, or miss a permissive file mode entirely.
//
// Every check must reach the same verdict over both.
func TestBothRsyslogSyntaxesReachTheSameVerdict(t *testing.T) {
	for _, check := range all {
		rainer := evalCheck(t, check, "logging-compliant")
		legacy := evalCheck(t, check, "logging-legacy")

		if rainer.Result != legacy.Result {
			t.Errorf("%s: RainerScript gives %s, legacy syntax gives %s over the same configuration.\n  rainerscript: %s\n  legacy:       %s",
				check.ID, rainer.Result, legacy.Result, rainer.Detail, legacy.Detail)
		}
		if rainer.Result != finding.Pass {
			t.Errorf("%s = %s over logging-compliant, want PASS", check.ID, rainer.Result)
		}
	}
}

// TestAbsentDaemonsAreNotApplicable. A host with neither daemon has not failed
// to secure logging, it has removed the subject of the sentence — and PASS
// would inflate the posture score with controls never tested.
func TestAbsentDaemonsAreNotApplicable(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "logging-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over logging-absent, want NOT_APPLICABLE: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestModuleDegradesPerDaemon is the counterpart, and the reason there are two
// facts rather than one.
//
// A journald-only host is the common modern case. The three rsyslog checks
// must say so and step aside; the journald checks must still produce real
// verdicts. A single fact, or a collector that failed as a unit, would give
// five unknowns where three not-applicables and two verdicts belong.
func TestModuleDegradesPerDaemon(t *testing.T) {
	for _, check := range rsyslogChecks {
		got := evalCheck(t, check, "logging-rsyslog-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s on a journald-only host, want NOT_APPLICABLE: %s",
				check.ID, got.Result, got.Detail)
		}
	}

	// And the journald half still answers.
	got := evalCheck(t, checks.Check0003, "logging-rsyslog-absent")
	if got.Result != finding.Pass {
		t.Errorf("LOGGING-0003 = %s on a journald-only host with Storage=persistent, want PASS: %s",
			got.Result, got.Detail)
	}
}

// TestUnreadableConfigIsUnknownEverywhere covers the unprivileged path, which
// the runner's required-fact gate resolves rather than any check.
func TestUnreadableConfigIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "logging-unreadable")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over logging-unreadable, want UNKNOWN: %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestUnresolvedIncludeBlocksNegativeVerdicts.
//
// Every rsyslog check here rests on an absence — no mode is set, no
// destination is configured — and an include that matched nothing means the
// statement may be in a file this scan never read. The asymmetry is the same
// one ADR-0014 records: a positive result would still stand, a negative one
// cannot.
//
// Note that NOT_APPLICABLE is caught by this too. LOGGING-0005's "there is no
// transport to assess" is a claim about absence exactly as a PASS would be.
func TestUnresolvedIncludeBlocksNegativeVerdicts(t *testing.T) {
	for _, check := range rsyslogChecks {
		got := evalCheck(t, check, "logging-unresolved-include")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s with an unresolved include, want UNKNOWN. The statement it looked for may be in a file it never read:\n  %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonAmbiguousState {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonAmbiguousState)
		}
	}

	// journald is unaffected: its own files were read completely.
	for _, check := range []catalog.Check{checks.Check0003, checks.Check0004} {
		got := evalCheck(t, check, "logging-unresolved-include")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s; the journald configuration was read completely and an rsyslog include has no bearing on it: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestSystemdDropInsOverrideTheMainFile pins the precedence that is the
// opposite of sshd_config's.
//
// systemd applies the LAST occurrence: a drop-in overrides the main file. A
// check that took the first match — which is what the sshd module correctly
// does for its own format — would report the value the operator's drop-in was
// written to replace, and the operator would "fix" a file that was already
// being ignored.
func TestSystemdDropInsOverrideTheMainFile(t *testing.T) {
	got := evalCheck(t, checks.Check0003, "logging-dropin-override")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL: the main file says persistent and a drop-in overrides it to volatile\n detail: %s",
			got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "volatile") {
		t.Errorf("the detail reports a value other than the drop-in's: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "99-volatile.conf") {
		t.Errorf("the detail does not cite the file actually in force: %s", got.Detail)
	}

	// The overridden occurrence is cited too, so an operator who edited the
	// main file understands why their value is not the one reported.
	var sawOverridden bool
	for _, e := range got.Evidence {
		if strings.Contains(e.Excerpt, "overridden by a later drop-in") {
			sawOverridden = true
		}
	}
	if !sawOverridden {
		t.Errorf("the finding does not cite the overridden setting, so a reader who set persistent in the main file cannot see why it is not in force: %+v", got.Evidence)
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestLogging0001FileMode(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "logging-compliant", result: finding.Pass, detailContains: "reading group"},
		{fixture: "logging-legacy", result: finding.Pass, detailContains: "reading group"},
		{fixture: "logging-weak", result: finding.Fail, severity: finding.Medium, detailContains: "0644"},
		// Nothing sets it, so rsyslog's documented default of 0644 applies —
		// which other can read.
		{fixture: "logging-nodefault", result: finding.Fail, severity: finding.Medium, detailContains: "built-in default"},
		{fixture: "logging-rsyslog-absent", result: finding.NotApplicable, detailContains: "does not run rsyslog"},
		{
			fixture: "logging-unresolved-include", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "could not be resolved",
		},
		{
			fixture: "logging-unreadable", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "logging.rsyslog unavailable",
		},
	})
}

// TestGroupReadIsPermitted pins the judgement that keeps this check usable. An
// 'adm' or 'systemd-journal' group with read access is how an operations team
// reads logs without root, and failing 0640 would push hosts toward giving out
// root instead.
func TestGroupReadIsPermitted(t *testing.T) {
	got := evalCheck(t, checks.Check0001, "logging-compliant")
	if got.Result != finding.Pass {
		t.Fatalf("0640 should pass: %s", got.Detail)
	}
	if !strings.Contains(checks.Check0001.Description, "Group read is deliberately permitted") {
		t.Error("the description does not record that group read is intentional rather than an oversight")
	}
}

func TestLogging0002RemoteForwarding(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "logging-compliant", result: finding.Pass, detailContains: "logs.example.net"},
		{fixture: "logging-legacy", result: finding.Pass, detailContains: "logs.example.net"},
		// A UDP destination is still a destination: whether the transport is
		// adequate is LOGGING-0005's question, reported once.
		{fixture: "logging-weak", result: finding.Pass, detailContains: "over udp"},
		{fixture: "logging-nodefault", result: finding.Fail, severity: finding.Medium, detailContains: "exists only on this host"},
		{fixture: "logging-rsyslog-absent", result: finding.NotApplicable, detailContains: "does not run rsyslog"},
		{
			fixture: "logging-unresolved-include", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "never saw",
		},
	})
}

func TestLogging0003JournalStorage(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "logging-compliant", result: finding.Pass, detailContains: "survives a reboot"},
		{fixture: "logging-weak", result: finding.Fail, severity: finding.Medium, detailContains: "destroyed at the next boot"},
		// Storage is unset, so auto applies — and /var/log/journal does not
		// exist, which makes auto mean volatile.
		{fixture: "logging-nodefault", result: finding.Fail, detailContains: "does not exist"},
		{fixture: "logging-dropin-override", result: finding.Fail, detailContains: "99-volatile.conf"},
		{fixture: "logging-rsyslog-absent", result: finding.Pass, detailContains: "survives a reboot"},
		{fixture: "logging-absent", result: finding.NotApplicable, detailContains: "does not appear to run"},
		{
			fixture: "logging-unreadable", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "logging.journald unavailable",
		},
	})
}

// TestStorageAutoIsResolvedAgainstTheDirectory. auto is journald's default and
// its meaning is a property of the filesystem, not of the configuration. One
// stat is what turns an UNKNOWN nobody could act on into a verdict.
func TestStorageAutoIsResolvedAgainstTheDirectory(t *testing.T) {
	got := evalCheck(t, checks.Check0003, "logging-nodefault")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL: Storage is unset and /var/log/journal is absent\n detail: %s",
			got.Result, got.Detail)
	}
	for _, want := range []string{"auto", "/var/log/journal"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the detail does not explain how auto was resolved (%q missing): %s", want, got.Detail)
		}
	}

	// And the directory's state is cited, so the verdict is followable.
	var sawDir bool
	for _, e := range got.Evidence {
		if e.Source == "/var/log/journal" {
			sawDir = true
		}
	}
	if !sawDir {
		t.Errorf("the journal directory is not cited as evidence: %+v", got.Evidence)
	}
}

func TestLogging0004ForwardToSyslog(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "logging-compliant", result: finding.Pass, detailContains: "hands its records to rsyslog"},
		{fixture: "logging-weak", result: finding.Fail, severity: finding.Low, detailContains: "empty stream"},
		// Not configured at all. The proposition is that forwarding is
		// *explicitly* set, which the files decide — so this is a definite
		// FAIL rather than an UNKNOWN about a version-dependent default.
		{fixture: "logging-nodefault", result: finding.Fail, detailContains: "changed across systemd releases"},
		{fixture: "logging-rsyslog-absent", result: finding.NotApplicable, detailContains: "no syslog daemon for journald to forward to"},
		{fixture: "logging-absent", result: finding.NotApplicable, detailContains: "rsyslog is not configured"},
	})
}

// TestForwardToSyslogFailsOnAbsenceRatherThanGuessing. journald's default has
// already flipped once across systemd versions, and Plumbline does not read
// the version. Rather than report a default it cannot verify, the check tests
// a proposition the files do decide: that the value is explicitly set.
func TestForwardToSyslogFailsOnAbsenceRatherThanGuessing(t *testing.T) {
	got := evalCheck(t, checks.Check0004, "logging-nodefault")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL", got.Result)
	}
	if strings.Contains(strings.ToLower(got.Detail), "defaults to yes") ||
		strings.Contains(strings.ToLower(got.Detail), "defaults to no") {
		t.Errorf("the detail asserts a default the scan did not verify: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "version") && !strings.Contains(got.Detail, "releases") {
		t.Errorf("the detail does not explain why the default cannot be relied on: %s", got.Detail)
	}
}

func TestLogging0005Transport(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "logging-compliant", result: finding.Pass, detailContains: "reliable transport"},
		{fixture: "logging-legacy", result: finding.Pass, detailContains: "reliable transport"},
		{fixture: "logging-weak", result: finding.Fail, severity: finding.Medium, detailContains: "no error on either side"},
		// No destination at all: the absence is LOGGING-0002's finding, and
		// reporting it twice under two names would have the operator fix one
		// and see the other still open.
		{fixture: "logging-nodefault", result: finding.NotApplicable, detailContains: "LOGGING-0002 reports the absence"},
		{fixture: "logging-rsyslog-absent", result: finding.NotApplicable, detailContains: "does not run rsyslog"},
		{
			fixture: "logging-unresolved-include", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "cannot be established",
		},
	})
}

// TestUDPIsReportedWithItsConsequence: "uses UDP" without saying what that
// costs leaves an operator unable to judge whether to act, and the cost here
// is specific — the loss is silent and it is worst under the load that
// produces the records worth keeping.
func TestUDPIsReportedWithItsConsequence(t *testing.T) {
	got := evalCheck(t, checks.Check0005, "logging-weak")
	for _, want := range []string{"UDP", "no error on either side", "looks complete"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not mention %q: %s", want, got.Detail)
		}
	}
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

		if !strings.HasPrefix(check.ID, "LOGGING-") || check.Module != "LOGGING" {
			t.Errorf("%s is not in the LOGGING module namespace", check.ID)
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
		if check.SinceCatalog != 8 {
			t.Errorf("%s declares SinceCatalog %d, want 8", check.ID, check.SinceCatalog)
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
	for _, fixture := range []string{"logging-weak", "logging-compliant", "logging-dropin-override"} {
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

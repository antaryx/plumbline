package sshd_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// evalFixture runs the real collector against a fixture and then the real
// check against the resulting facts. Tests exercise the whole vertical slice,
// not the check in isolation, because most check bugs are actually collector
// bugs.
func evalFixture(t *testing.T, name string) finding.Finding {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}

	facts := fact.NewSet()
	cfg, ferr := collector.Collect(sys)
	if ferr != nil {
		facts.PutError(*ferr)
	} else {
		facts.Put(cfg)
	}

	cat := catalog.MustNew(checks.Check0002)
	got := cat.Evaluate(facts)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	return got[0]
}

func TestSSHD0002(t *testing.T) {
	cases := []struct {
		fixture  string
		result   finding.Result
		severity finding.Severity      // "" means: do not assert
		reason   finding.UnknownReason // "" means: do not assert
		// detailContains guards against a correct verdict with a misleading
		// explanation, which is its own class of bug.
		detailContains string
	}{
		{
			fixture:        "sshd-hardened",
			result:         finding.Pass,
			detailContains: "no",
		},
		{
			fixture:        "sshd-permit-yes",
			result:         finding.Fail,
			severity:       finding.High,
			detailContains: "may log in directly",
		},
		{
			fixture:        "sshd-default",
			result:         finding.Fail,
			severity:       finding.Medium,
			detailContains: "built-in default",
		},
		{
			// The drop-in is included on line 1, so its value is obtained
			// first and wins over the later "yes" in the main file. A tool
			// that reads only sshd_config gets this backwards.
			fixture:        "sshd-include",
			result:         finding.Pass,
			detailContains: "refused",
		},
		{
			// The only "no" is Match-scoped and must not count.
			fixture:        "sshd-match-trap",
			result:         finding.Fail,
			severity:       finding.High,
			detailContains: "may log in directly",
		},
		{
			fixture:        "sshd-absent",
			result:         finding.NotApplicable,
			detailContains: "not configured",
		},
		{
			fixture:        "sshd-unreadable",
			result:         finding.Unknown,
			reason:         finding.ReasonPermission,
			detailContains: "unavailable",
		},
		{
			fixture:        "sshd-unresolved-include",
			result:         finding.Unknown,
			reason:         finding.ReasonAmbiguousState,
			detailContains: "could not be resolved",
		},
		{
			fixture:        "sshd-bad-value",
			result:         finding.Unknown,
			reason:         finding.ReasonParse,
			detailContains: "unrecognised value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			got := evalFixture(t, tc.fixture)

			if got.Result != tc.result {
				t.Errorf("result = %s, want %s\ndetail: %s", got.Result, tc.result, got.Detail)
			}
			if tc.severity != "" && got.Severity != tc.severity {
				t.Errorf("severity = %s, want %s", got.Severity, tc.severity)
			}
			if tc.reason != "" && got.UnknownReason != tc.reason {
				t.Errorf("unknown reason = %q, want %q", got.UnknownReason, tc.reason)
			}
			if !strings.Contains(strings.ToLower(got.Detail), strings.ToLower(tc.detailContains)) {
				t.Errorf("detail %q does not contain %q", got.Detail, tc.detailContains)
			}

			// Invariants that hold for every check, asserted everywhere so
			// that a violation is caught by whichever test runs first.
			if got.CheckID != "SSHD-0002" || got.Module != "SSHD" {
				t.Errorf("identity wrong: %s / %s", got.CheckID, got.Module)
			}
			if got.BaseSeverity != finding.High {
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
		})
	}
}

// TestDeterminism asserts the property the whole architecture exists to
// provide: the same facts always produce the same findings.
func TestDeterminism(t *testing.T) {
	first := evalFixture(t, "sshd-include")
	for i := 0; i < 50; i++ {
		got := evalFixture(t, "sshd-include")
		if got.Result != first.Result || got.Detail != first.Detail || got.Fingerprint != first.Fingerprint {
			t.Fatalf("non-deterministic on iteration %d", i)
		}
	}
}

// TestFingerprintStability guards the suppression and SARIF baseline contract:
// a finding's identity must not change when its verdict does.
func TestFingerprintStability(t *testing.T) {
	pass := evalFixture(t, "sshd-hardened")
	fail := evalFixture(t, "sshd-permit-yes")
	if pass.Fingerprint != fail.Fingerprint {
		t.Errorf("fingerprint changed with verdict: %s vs %s", pass.Fingerprint, fail.Fingerprint)
	}
}

// TestNoPanicOnEmptyFacts asserts the runner's required-fact gate: a check
// must never see a missing fact, and must never crash the scan.
func TestNoPanicOnEmptyFacts(t *testing.T) {
	cat := catalog.MustNew(checks.Check0002)
	got := cat.Evaluate(fact.NewSet())
	if got[0].Result != finding.Unknown {
		t.Errorf("result = %s, want UNKNOWN", got[0].Result)
	}
	if got[0].UnknownReason != finding.ReasonFactMissing {
		t.Errorf("reason = %q, want %q", got[0].UnknownReason, finding.ReasonFactMissing)
	}
}

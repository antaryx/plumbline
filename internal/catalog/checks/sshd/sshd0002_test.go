package sshd_test

import (
	"strings"
	"testing"

	checks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"
	"github.com/antaryx/plumbline/internal/finding"
)

// SSHD-0002 keeps its own test file because it is the project's reference
// check: its table is the one docs/CHECK-AUTHORING.md points at. The shared
// helpers live in sshd_test.go, which every check in the module uses.

func TestSSHD0002(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "no"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "may log in directly"},
		{fixture: "sshd-default", result: finding.Fail, severity: finding.Medium, detailContains: "built-in default"},
		{
			// The drop-in is included on line 1, so its value is obtained
			// first and wins over the later "yes" in the main file. A tool
			// that reads only sshd_config gets this backwards.
			fixture: "sshd-include", result: finding.Pass, detailContains: "refused",
		},
		{
			// The only "no" is Match-scoped and must not count.
			fixture: "sshd-match-trap", result: finding.Fail,
			severity: finding.High, detailContains: "may log in directly",
		},
		{
			// The mirror image of sshd-match-trap: the global value is "no"
			// and the Match block re-enables root login, so the secure global
			// is not the whole story either.
			fixture: "sshd-match-loosened", result: finding.Fail,
			severity: finding.Medium, detailContains: "Match Address 0.0.0.0/0",
		},
		{fixture: "sshd-absent", result: finding.NotApplicable, detailContains: "not configured"},
		{fixture: "sshd-unreadable", result: finding.Unknown, reason: finding.ReasonPermission, detailContains: "unavailable"},
		{fixture: "sshd-unresolved-include", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "could not be resolved"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unrecognised value"},
	})
}

// TestFingerprintStability guards the suppression and SARIF baseline contract:
// a finding's identity must not change when its verdict does.
func TestFingerprintStability(t *testing.T) {
	pass := evalCheck(t, checks.Check0002, "sshd-hardened")
	fail := evalCheck(t, checks.Check0002, "sshd-permit-yes")
	if pass.Fingerprint != fail.Fingerprint {
		t.Errorf("fingerprint changed with verdict: %s vs %s", pass.Fingerprint, fail.Fingerprint)
	}
}

// TestMatchScopedValueDoesNotSetTheGlobal is the classic sshd-auditing bug,
// pinned in both directions. A tool that counted the Match-scoped "no" in
// sshd-match-trap would report a host permitting root login as compliant; a
// tool that ignored the Match-scoped "yes" in sshd-match-loosened would report
// a host that permits it from anywhere as compliant too.
func TestMatchScopedValueDoesNotSetTheGlobal(t *testing.T) {
	trap := evalCheck(t, checks.Check0002, "sshd-match-trap")
	if trap.Result != finding.Fail {
		t.Fatalf("sshd-match-trap = %s, want FAIL: the only \"no\" is inside a Match block", trap.Result)
	}
	var sawScopedEvidence bool
	for _, e := range trap.Evidence {
		if strings.Contains(e.Excerpt, "does not set the global value") {
			sawScopedEvidence = true
		}
	}
	if !sawScopedEvidence {
		t.Errorf("the Match-scoped directive is not cited, so the report contradicts what the operator can see in the file: %+v", trap.Evidence)
	}

	loosened := evalCheck(t, checks.Check0002, "sshd-match-loosened")
	if loosened.Result != finding.Fail {
		t.Fatalf("sshd-match-loosened = %s, want FAIL: the global \"no\" is overridden for every address", loosened.Result)
	}
	if loosened.Severity != finding.Medium {
		t.Errorf("severity = %s, want MEDIUM: a conditional exposure steps down one class from the HIGH base", loosened.Severity)
	}
}

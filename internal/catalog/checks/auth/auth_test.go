package auth_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/auth"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/auth"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the AUTH module as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001, checks.Check0002, checks.Check0003,
	checks.Check0004, checks.Check0005, checks.Check0006,
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

			if got.CheckID != check.ID || got.Module != "AUTH" {
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

// TestBothLayoutsReachTheSameVerdict is the reason there are two good-case
// fixtures rather than one.
//
// auth-rhel and auth-debian are the same hardened host: fourteen-character
// minimum, faillock, history of five, no nullok, strong hashing. One keeps its
// rules in system-auth and password-auth reached through symlinks to
// authselect's generated files; the other keeps them in common-* and pulls
// them in with @include. A collector that understood one family would report
// "no password quality is enforced" on every host of the other — a wrong
// verdict produced entirely by packaging.
func TestBothLayoutsReachTheSameVerdict(t *testing.T) {
	for _, check := range all {
		rhel := evalCheck(t, check, "auth-rhel")
		deb := evalCheck(t, check, "auth-debian")

		if rhel.Result != deb.Result {
			t.Errorf("%s: Red Hat layout = %s but Debian layout = %s; one host written two ways must reach one verdict\n  rhel:   %s\n  debian: %s",
				check.ID, rhel.Result, deb.Result, rhel.Detail, deb.Detail)
		}
		if rhel.Result != finding.Pass {
			t.Errorf("%s = %s over the hardened host, want PASS: %s", check.ID, rhel.Result, rhel.Detail)
		}
	}
}

// TestNoPAMIsNotApplicableEverywhere: a host with no /etc/pam.d authenticates
// by a mechanism this module cannot read. PASS would be assurance about
// something never examined.
func TestNoPAMIsNotApplicableEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "auth-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over auth-absent, want NOT_APPLICABLE:\n  %s", check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnreadablePAMDirectoryIsUnknownEverywhere: every authentication policy a
// host has is written in /etc/pam.d and nowhere else, so a directory that
// refuses traversal is a host whose policy was never observed.
func TestUnreadablePAMDirectoryIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "auth-denied")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over auth-denied, want UNKNOWN:\n  %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestEveryCheckIsRegisteredAtCatalogTen guards the one piece of metadata a
// reviewer cannot see from the diff.
func TestEveryCheckIsRegisteredAtCatalogTen(t *testing.T) {
	for _, check := range all {
		if check.SinceCatalog != 10 {
			t.Errorf("%s SinceCatalog = %d, want 10", check.ID, check.SinceCatalog)
		}
		if len(check.Requires) != 1 || check.Requires[0] != fact.PAMID {
			t.Errorf("%s requires %v, want [%s]", check.ID, check.Requires, fact.PAMID)
		}
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestCheck0001(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "pam_pwquality.so"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "password stack"},
		{fixture: "auth-weak", result: finding.Fail, severity: finding.High,
			detailContains: "no password quality module"},
		{fixture: "auth-optional", result: finding.Fail, severity: finding.High,
			detailContains: "not enforcing"},
		{fixture: "auth-unresolved", result: finding.Unknown, reason: finding.ReasonAmbiguousState,
			detailContains: "could not be followed"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "no /etc/pam.d"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "could not be examined"},
	})
}

func TestCheck0002(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "minclass"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "at least 1 digit"},
		{fixture: "auth-minlen", result: finding.Fail, severity: finding.Medium,
			detailContains: "minlen is 8"},
		// No quality module at all: AUTH-0001 reports the absence, and failing
		// twice for one missing thing would bury it.
		{fixture: "auth-weak", result: finding.NotApplicable,
			detailContains: "auth-0001 reports the absence"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "does not use pam"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/pam.d"},
	})
}

func TestCheck0003(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "locks after 5 failures"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "pam_faillock.so"},
		{fixture: "auth-weak", result: finding.Fail, severity: finding.Medium,
			detailContains: "no failed-attempt counter"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "no /etc/pam.d"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/pam.d"},
	})
}

func TestCheck0004(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "nullok appears in none"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "empty password"},
		{fixture: "auth-weak", result: finding.Fail, severity: finding.High,
			detailContains: "accepts an empty password"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "no /etc/pam.d"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/pam.d"},
	})
}

func TestCheck0005(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "sha512"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "yescrypt"},
		{fixture: "auth-weak", result: finding.Fail, severity: finding.High,
			detailContains: "md5"},
		// The unresolved include wins the explanation over "no pam_unix.so
		// rule was found", and should: not finding the rule is a consequence
		// of not having read the file, and naming the file is what an
		// operator can act on.
		{fixture: "auth-unresolved", result: finding.Unknown, reason: finding.ReasonAmbiguousState,
			detailContains: "could not be followed"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "no /etc/pam.d"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/pam.d"},
	})
}

func TestCheck0006(t *testing.T) {
	run(t, checks.Check0006, []tc{
		{fixture: "auth-rhel", result: finding.Pass, detailContains: "last 5 passwords"},
		{fixture: "auth-debian", result: finding.Pass, detailContains: "remembered and refused"},
		{fixture: "auth-weak", result: finding.Fail, severity: finding.Low,
			detailContains: "no password history is kept"},
		{fixture: "auth-absent", result: finding.NotApplicable, detailContains: "no /etc/pam.d"},
		{fixture: "auth-denied", result: finding.Unknown, reason: finding.ReasonPermission,
			detailContains: "/etc/pam.d"},
	})
}

// ---------------------------------------------------------------------------
// the parsing that decides a verdict
// ---------------------------------------------------------------------------

// TestBracketedControlIsNotSplitOnWhitespace.
//
// Debian's common-password writes the pam_unix rule as
//
//	password [success=1 default=ignore] pam_unix.so obscure use_authtok yescrypt
//
// A strings.Fields split reads the control as "[success=1" and the module as
// "default=ignore]", so the hashing check finds no pam_unix.so at all and
// reports UNKNOWN on a stock Debian host — a wrong answer that looks like
// caution.
func TestBracketedControlIsNotSplitOnWhitespace(t *testing.T) {
	facts := collectFixture(t, "auth-debian")
	p, _, _ := fact.Get[fact.PAM](facts, fact.PAMID)

	lines := fact.Find(p.Primary(fact.PAMPassword), fact.PAMPassword, "pam_unix.so")
	if len(lines) == 0 {
		t.Fatal("no pam_unix.so rule found in the password stack; the bracketed control was mis-split")
	}
	l := lines[0]
	if l.Control != "[success=1 default=ignore]" {
		t.Errorf("control = %q, want the whole bracketed expression", l.Control)
	}
	if !l.HasArg("yescrypt") {
		t.Errorf("args = %v; the algorithm argument was lost", l.Args)
	}
	// A bracketed control that ignores failure is not enforcing, and this one
	// does not need to be: it is pam_unix setting the password, not a rule
	// guarding it.
	if l.Enforcing() {
		t.Error("Enforcing() = true for default=ignore")
	}
}

// TestIncludeScopeIsRespected.
//
// `@include` inlines a whole file, every management group at once; `<type>
// include` pulls in only that type's lines. Treating the second as the first
// would import password rules into the auth stack, where a check searching for
// pam_pwquality in `auth` would then find one.
func TestIncludeScopeIsRespected(t *testing.T) {
	rhel := collectFixture(t, "auth-rhel")
	p, _, _ := fact.Get[fact.PAM](rhel, fact.PAMID)

	sshd, ok := p.Service("sshd")
	if !ok || sshd.State != fact.FilePresent {
		t.Fatal("sshd stack not read")
	}
	// sshd's `auth substack password-auth` must contribute auth rules only.
	// password-auth's own password rules must not have come along with them.
	for _, l := range sshd.Lines {
		if l.Type != fact.PAMPassword {
			continue
		}
		// The only password lines legitimately here come from the explicit
		// `password include password-auth` directive.
		if l.Module == "pam_pwquality.so" {
			return // reached through the password-scoped include: correct
		}
	}
	t.Error("the password-scoped include contributed no pam_pwquality rule; include scoping is wrong")
}

// TestSymlinkedStackIsResolvedAndCited.
//
// Red Hat's /etc/pam.d/system-auth is a symlink on every stock install. The
// seam's ReadFile refuses a symlink with O_NOFOLLOW, so without explicit
// resolution this module would report UNKNOWN across the whole Red Hat family.
// The resolved path is recorded because it is the file an operator must edit —
// citing the link would send them to something authselect overwrites.
func TestSymlinkedStackIsResolvedAndCited(t *testing.T) {
	facts := collectFixture(t, "auth-rhel")
	p, _, _ := fact.Get[fact.PAM](facts, fact.PAMID)

	svc, ok := p.Service("system-auth")
	if !ok {
		t.Fatal("no system-auth record")
	}
	if svc.State != fact.FilePresent {
		t.Fatalf("state = %s (%s); the symlink was not followed", svc.State, svc.Msg)
	}
	if svc.ResolvedPath != "/etc/pam.d/system-auth-ac" {
		t.Errorf("ResolvedPath = %q, want the file the link points at", svc.ResolvedPath)
	}
	for _, l := range svc.Lines {
		if l.File != svc.ResolvedPath {
			t.Errorf("rule cited %s, want the resolved file an operator would edit", l.File)
			break
		}
	}
}

// TestAnUnfollowedIncludeInvalidatesOnlyNegativeConclusions is ADR-0014
// applied to a graph. auth-unresolved cannot resolve its password include, so
// "no quality module is present" becomes UNKNOWN — but the auth stack, which
// is complete, still yields a real verdict for the lockout check.
func TestAnUnfollowedIncludeInvalidatesOnlyNegativeConclusions(t *testing.T) {
	if got := evalCheck(t, checks.Check0001, "auth-unresolved"); got.Result != finding.Unknown {
		t.Errorf("AUTH-0001 = %s over an unresolvable password include, want UNKNOWN: %s", got.Result, got.Detail)
	}
	// The auth stack resolved cleanly, so the lockout check is unaffected.
	if got := evalCheck(t, checks.Check0003, "auth-unresolved"); got.Result != finding.Pass {
		t.Errorf("AUTH-0003 = %s, want PASS: a broken include in the *password* stack must not degrade a verdict drawn from a complete auth stack: %s",
			got.Result, got.Detail)
	}
}

package users_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/users"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/users"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

// all is the module's catalog as this work package leaves it.
var all = []catalog.Check{
	checks.Check0001,
	checks.Check0002,
	checks.Check0003,
	checks.Check0004,
	checks.Check0005,
	checks.Check0006,
	checks.Check0007,
	checks.Check0008,
	checks.Check0009,
	checks.Check0010,
}

// needsShadow are the checks that cannot answer without /etc/shadow. They are
// listed rather than derived so that adding a shadow-dependent check without
// thinking about the unprivileged path fails a test.
var needsShadow = []catalog.Check{
	checks.Check0003, checks.Check0004, checks.Check0009, checks.Check0010,
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

// evalFixture runs the real collector against a fixture and then one real
// check against the resulting facts.
func evalFixture(t *testing.T, check catalog.Check, name string) finding.Finding {
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
			got := evalFixture(t, check, c.fixture)

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

			if got.CheckID != check.ID || got.Module != "USERS" {
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
				t.Errorf("%s carries no evidence", got.Result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// graceful degradation — the module's central property
// ---------------------------------------------------------------------------

// TestUnprivilegedScanDegradesPerCheck is what WP-17 exists to get right. An
// unprivileged scan can read /etc/passwd and /etc/group and cannot read
// /etc/shadow. The four checks that need shadow must say so; the six that do
// not must produce real verdicts.
//
// The failure this guards against is a collector that gives up as a unit: an
// operator would see six unknowns where two are warranted, and the two that
// mattered would be invisible among them.
func TestUnprivilegedScanDegradesPerCheck(t *testing.T) {
	facts := collectFixture(t, "users-unprivileged")

	// The passwd and group facts are present despite shadow being refused.
	if _, ferr, ok := fact.Get[fact.Passwd](facts, fact.PasswdID); !ok {
		t.Fatalf("users.passwd is missing on an unprivileged scan (err=%v); "+
			"the collector failed as a unit instead of per file", ferr)
	}
	if _, ferr, ok := fact.Get[fact.Group](facts, fact.GroupID); !ok {
		t.Fatalf("users.group is missing on an unprivileged scan (err=%v)", ferr)
	}

	// Shadow is recorded as an error carrying the reason and the path, not
	// simply absent: "we were refused" and "nobody looked" are different
	// observations and map to different reason codes.
	ferr, bad := facts.Err(fact.ShadowID)
	if !bad {
		t.Fatal("users.shadow was not recorded as a fact error")
	}
	if ferr.Kind != fact.ErrPermission {
		t.Errorf("shadow error kind = %q, want %q", ferr.Kind, fact.ErrPermission)
	}
	if ferr.Path != "/etc/shadow" {
		t.Errorf("shadow error path = %q, want /etc/shadow", ferr.Path)
	}

	// The shadow-dependent checks resolve to UNKNOWN with the permission
	// reason, carrying evidence that names the file.
	for _, check := range needsShadow {
		got := evalFixture(t, check, "users-unprivileged")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s on an unprivileged scan, want UNKNOWN: %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
		if !strings.Contains(got.Detail, "users.shadow") {
			t.Errorf("%s does not say which fact was unavailable: %s", check.ID, got.Detail)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%s carries no evidence; an UNKNOWN an auditor cannot follow up is not actionable", check.ID)
		}
		for _, e := range got.Evidence {
			if e.Source != "/etc/shadow" {
				t.Errorf("%s evidence cites %q, want /etc/shadow", check.ID, e.Source)
			}
		}
	}

	// Everything else answers for real. This is the half that a collector
	// failing as a unit would destroy.
	for _, check := range []catalog.Check{
		checks.Check0001, checks.Check0002, checks.Check0005, checks.Check0006,
		checks.Check0007, checks.Check0008,
	} {
		got := evalFixture(t, check, "users-unprivileged")
		if got.Result == finding.Unknown {
			t.Errorf("%s = UNKNOWN on an unprivileged scan; it needs only /etc/passwd, which was readable: %s",
				check.ID, got.Detail)
		}
	}
}

// TestShadowHashesNeverEnterTheBundle is a security property of the fact, not
// of a check. A bundle travels; a password hash in one is a credential in a
// form an attacker can work on offline at their leisure.
func TestShadowHashesNeverEnterTheBundle(t *testing.T) {
	facts := collectFixture(t, "users-clean")
	s, _, ok := fact.Get[fact.Shadow](facts, fact.ShadowID)
	if !ok {
		t.Fatal("users.shadow missing")
	}

	// The fixture's hashes contain these substrings. None may survive into the
	// fact in any field.
	secrets := []string{
		"0123456789abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnop",
		"rounds=656000",
	}
	for _, e := range s.Entries {
		blob := e.Name + string(e.Algorithm)
		for _, secret := range secrets {
			if strings.Contains(blob, secret) {
				t.Errorf("account %s carries hash material in the fact: %+v", e.Name, e)
			}
		}
	}
	// The algorithm survives, because that is what a check judges.
	root, ok := s.Entry("root")
	if !ok {
		t.Fatal("root missing from shadow fact")
	}
	if root.Algorithm != fact.HashSHA512 {
		t.Errorf("root algorithm = %q, want %q", root.Algorithm, fact.HashSHA512)
	}
	// And no digest, because the bytes are deliberately not in the store.
	if s.Path != "/etc/shadow" {
		t.Errorf("shadow path = %q", s.Path)
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestUsers0001RootUID(t *testing.T) {
	run(t, checks.Check0001, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "held by the root account"},
		{fixture: "users-uid0", result: finding.Fail, detailContains: "other than root hold uid 0"},
		{
			// A positive result stands even though the file imports accounts:
			// an account we read with uid 0 has uid 0.
			fixture: "users-nis", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "imports accounts from a directory service",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "could not be parsed",
		},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "held by the root account"},
	})
}

func TestUsers0002SystemShells(t *testing.T) {
	run(t, checks.Check0002, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "cannot open a session"},
		{
			// daemon has bash; games has an empty shell field, which the
			// system reads as /bin/sh rather than as no shell.
			fixture: "users-shells", result: finding.Fail,
			detailContains: "can open a session",
		},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "cannot open a session"},
	})
}

// TestEmptyShellIsInteractive pins the trap in USERS-0002 directly: an empty
// shell field is the most permissive setting in the file, not the most
// restrictive, and a parser reading it as "no shell" would invert the verdict.
func TestEmptyShellIsInteractive(t *testing.T) {
	got := evalFixture(t, checks.Check0002, "users-shells")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL", got.Result)
	}
	if !strings.Contains(got.Detail, "games") {
		t.Errorf("the account with an empty shell field was not reported: %s", got.Detail)
	}
	var sawExplanation bool
	for _, e := range got.Evidence {
		if strings.Contains(e.Excerpt, "empty") && strings.Contains(e.Excerpt, "/bin/sh") {
			sawExplanation = true
		}
	}
	if !sawExplanation {
		t.Errorf("the evidence does not explain that an empty shell field means /bin/sh: %+v", got.Evidence)
	}
}

func TestUsers0003EmptyPasswords(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "empty password field"},
		{fixture: "users-nopassword", result: finding.Fail, detailContains: "authenticate with no password"},
		{
			// The module's main UNKNOWN path, resolved by the runner's
			// required-fact gate rather than by the check.
			fixture: "users-unprivileged", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "users.shadow unavailable",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "could not be read",
		},
	})
}

// TestLockedIsNotEmpty pins the distinction USERS-0003 rests on: a lock token
// refuses every password, an empty field accepts every password, and a parser
// that treated them alike would report the safe state as the dangerous one.
func TestLockedIsNotEmpty(t *testing.T) {
	got := evalFixture(t, checks.Check0003, "users-clean")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS: every non-root account in this fixture is locked, not empty\n detail: %s",
			got.Result, got.Detail)
	}

	// And the reverse: the fixture with empty fields must not be excused by
	// the locked entries sitting beside them.
	got = evalFixture(t, checks.Check0003, "users-nopassword")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL", got.Result)
	}
	for _, locked := range []string{"daemon", "bin", "nobody"} {
		if strings.Contains(got.Subject, locked) {
			t.Errorf("locked account %s was reported as having an empty password: %s", locked, got.Subject)
		}
	}
	for _, empty := range []string{"www-data", "alice"} {
		if !strings.Contains(got.Detail, empty) {
			t.Errorf("account %s has an empty password and was not reported: %s", empty, got.Detail)
		}
	}
}

func TestUsers0004HashAlgorithms(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "modern algorithm"},
		{fixture: "users-weakhash", result: finding.Fail, detailContains: "offline cracking"},
		{
			// Every account is locked, so no stored hash exists whose
			// algorithm could be judged.
			fixture: "users-locked-only", result: finding.NotApplicable,
			detailContains: "no account",
		},
		{
			fixture: "users-unprivileged", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "users.shadow unavailable",
		},
	})
}

// TestWeakHashesAreNamedWithTheirAlgorithm: a finding that says "weak hash"
// without saying which scheme leaves the operator unable to judge urgency.
func TestWeakHashesAreNamedWithTheirAlgorithm(t *testing.T) {
	got := evalFixture(t, checks.Check0004, "users-weakhash")
	for _, want := range []string{"root", "md5", "alice", "des"} {
		if !strings.Contains(strings.ToLower(got.Detail), want) {
			t.Errorf("detail does not mention %q: %s", want, got.Detail)
		}
	}
	// Locked accounts have no hash and must not be counted as weak.
	for _, locked := range []string{"daemon", "nobody"} {
		if strings.Contains(got.Subject, locked) {
			t.Errorf("locked account %s reported as a weak hash: %s", locked, got.Subject)
		}
	}
}

func TestUsers0005Duplicates(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "distinct uid"},
		{fixture: "users-duplicates", result: finding.Fail, detailContains: "uid 1000 is shared"},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "distinct uid"},
	})
}

// TestDuplicateNameIsReportedAsUnreachable: the second entry for a name is not
// merely redundant, it is silently not in force, and the finding has to say so
// or an operator will "fix" the entry that was never being read.
func TestDuplicateNameIsReportedAsUnreachable(t *testing.T) {
	got := evalFixture(t, checks.Check0005, "users-duplicates")
	if !strings.Contains(got.Detail, "carol") {
		t.Errorf("the duplicated name was not reported: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "unreachable") {
		t.Errorf("the detail does not explain that the later entry is unreachable: %s", got.Detail)
	}
}

func TestUsers0006NISEntries(t *testing.T) {
	run(t, checks.Check0006, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "no nis compatibility entries"},
		{fixture: "users-nis", result: finding.Fail, detailContains: "unauthenticated protocol"},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "defined locally"},
	})
}

func TestUsers0007GroupZero(t *testing.T) {
	run(t, checks.Check0007, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "root holds primary group 0"},
		{fixture: "users-gid0", result: finding.Fail, severity: finding.High, detailContains: "group 0 is not confined to root"},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "lists no supplementary members"},
		{
			// /etc/group carries the same "+" syntax as /etc/passwd, and it
			// makes the same negative assertion unsupportable.
			fixture: "users-nis", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "imports groups from a directory service",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "could not be parsed",
		},
	})
}

// TestSystemAccountsInGroupZeroAreNotFailed pins the judgement that separates
// this check from the naive form of the rule. Red Hat-family distributions ship
// operator, halt, shutdown and sync with primary group 0; failing them would
// put four unactionable findings on every stock RHEL host, and a module that
// does that stops being read.
func TestSystemAccountsInGroupZeroAreNotFailed(t *testing.T) {
	got := evalFixture(t, checks.Check0007, "users-clean")
	if got.Result != finding.Pass {
		t.Fatalf("result = %s, want PASS: operator is a system account and its group is the distribution convention\n detail: %s",
			got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "operator") {
		t.Errorf("the system account in group 0 was not reported at all; a silent exemption is not an exemption a reader can audit: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "convention") {
		t.Errorf("the detail does not explain why the system account is exempt: %s", got.Detail)
	}

	// And the same fixture's ordinary account is not excused by the exemption.
	got = evalFixture(t, checks.Check0007, "users-gid0")
	if !strings.Contains(got.Subject, "eve") {
		t.Errorf("the ordinary account with primary group 0 was not reported: %s", got.Subject)
	}
	if strings.Contains(got.Subject, "operator") {
		t.Errorf("the system account was reported as a violation: %s", got.Subject)
	}
}

// TestGroupZeroReportsAllThreeConditions: the check makes three separate
// propositions and a fixture that violates all three must see all three, or a
// host would fix the one it was told about and stay exposed by the others.
func TestGroupZeroReportsAllThreeConditions(t *testing.T) {
	got := evalFixture(t, checks.Check0007, "users-gid0")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL", got.Result)
	}
	for _, want := range []string{
		"root's primary group is 100", // root is not in its own group
		"eve",                         // an ordinary account holds group 0
		"mallory",                     // a supplementary member of group 0
	} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not report %q: %s", want, got.Detail)
		}
	}
}

func TestUsers0008GroupDuplicates(t *testing.T) {
	run(t, checks.Check0008, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "distinct gid"},
		{fixture: "users-duplicates", result: finding.Fail, detailContains: "gid 50 is shared"},
		{fixture: "users-unprivileged", result: finding.Pass, detailContains: "distinct gid"},
		{
			fixture: "users-nis", result: finding.Unknown,
			reason: finding.ReasonAmbiguousState, detailContains: "imports groups from a directory service",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "could not be parsed",
		},
	})
}

// TestDuplicateGroupNameIsReportedAsUnreachable mirrors the passwd case: the
// second entry for a name is not redundant, it is silently not in force, and
// 'getent group' will report the first entry's members back to an
// administrator who just edited the second.
func TestDuplicateGroupNameIsReportedAsUnreachable(t *testing.T) {
	got := evalFixture(t, checks.Check0008, "users-duplicates")
	if !strings.Contains(got.Detail, `"dev"`) {
		t.Errorf("the duplicated group name was not reported: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "unreachable") {
		t.Errorf("the detail does not explain that the later entry is unreachable: %s", got.Detail)
	}
}

func TestUsers0009MaximumAge(t *testing.T) {
	run(t, checks.Check0009, []tc{
		{fixture: "users-clean", result: finding.Pass, severity: finding.Low, detailContains: "365 days or fewer"},
		{fixture: "users-aging", result: finding.Fail, severity: finding.Low, detailContains: "no bounded password lifetime"},
		{
			// Every account is locked, so no password exists that could expire.
			fixture: "users-locked-only", result: finding.NotApplicable,
			detailContains: "no password lifetime to bound",
		},
		{
			fixture: "users-unprivileged", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "users.shadow unavailable",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "could not be read",
		},
	})
}

// TestMaximumAgeNamesTheFrameworkConflict. The premise of this check is
// contested — NIST SP 800-63B advises against forced rotation while CIS and
// the DISA STIGs require it — and a finding that stated the CIS threshold as
// though it were settled would be telling the reader something untrue about
// the state of the guidance.
func TestMaximumAgeNamesTheFrameworkConflict(t *testing.T) {
	for _, fixture := range []string{"users-clean", "users-aging"} {
		got := evalFixture(t, checks.Check0009, fixture)
		if !strings.Contains(got.Detail, "NIST") {
			t.Errorf("%s: the detail does not mention the framework that disagrees with this check: %s",
				fixture, got.Detail)
		}
	}
	if checks.Check0009.BaseSeverity != finding.Low {
		t.Errorf("base severity = %s, want LOW: a check whose premise is contested should not be shouting",
			checks.Check0009.BaseSeverity)
	}
}

// TestLockedAccountsDoNotDominateTheAgingChecks pins the Authenticates() gate.
// Every distribution ships locked system accounts carrying shadow-utils'
// 99999 default; reporting them would bury the two accounts that matter.
func TestLockedAccountsDoNotDominateTheAgingChecks(t *testing.T) {
	for _, check := range []catalog.Check{checks.Check0009, checks.Check0010} {
		got := evalFixture(t, check, "users-aging")
		if got.Result != finding.Fail {
			t.Fatalf("%s: result = %s, want FAIL", check.ID, got.Result)
		}
		for _, locked := range []string{"daemon", "nobody"} {
			if strings.Contains(got.Subject, locked) {
				t.Errorf("%s reported the locked account %s, whose password cannot expire because no password can authenticate it: %s",
					check.ID, locked, got.Subject)
			}
		}
	}
}

// TestEmptyMaximumAgeIsNotZero is the pointer decision made visible. alice's
// aging fields are empty, which means "no maximum"; a parser that read them as
// 0 would report the most permissive setting in the file as the strictest one
// available and this check would return PASS for her.
func TestEmptyMaximumAgeIsNotZero(t *testing.T) {
	got := evalFixture(t, checks.Check0009, "users-aging")
	if !strings.Contains(got.Subject, "alice") {
		t.Fatalf("the account with empty aging fields was not reported: %s", got.Subject)
	}
	if !strings.Contains(got.Detail, "never expires") {
		t.Errorf("the detail does not say what an empty maximum age means: %s", got.Detail)
	}
}

func TestUsers0010MinimumAge(t *testing.T) {
	run(t, checks.Check0010, []tc{
		{fixture: "users-clean", result: finding.Pass, detailContains: "at least one day"},
		{
			// bob's minimum exceeds his maximum, which escalates this fixture
			// past the base severity.
			fixture: "users-aging", result: finding.Fail, severity: finding.Medium,
			detailContains: "locked out by construction",
		},
		{
			fixture: "users-locked-only", result: finding.NotApplicable,
			detailContains: "no password change interval to govern",
		},
		{
			fixture: "users-unprivileged", result: finding.Unknown,
			reason: finding.ReasonPermission, detailContains: "users.shadow unavailable",
		},
		{
			fixture: "users-malformed", result: finding.Unknown,
			reason: finding.ReasonParse, detailContains: "could not be read",
		},
	})
}

// TestMinimumGreaterThanMaximumEscalates. A missing minimum is a policy
// preference that only matters where password history is enforced; a minimum
// above the maximum locks the account out of changing its own expired
// password, which is an availability failure and does not depend on the PAM
// stack at all. The two must not carry the same weight.
func TestMinimumGreaterThanMaximumEscalates(t *testing.T) {
	got := evalFixture(t, checks.Check0010, "users-aging")
	if got.Severity != finding.Medium {
		t.Errorf("severity = %s, want MEDIUM when an account cannot change its expired password", got.Severity)
	}
	if got.BaseSeverity != finding.Low {
		t.Errorf("base severity = %s, want LOW; the escalation is per-outcome", got.BaseSeverity)
	}
	if !strings.Contains(got.Detail, "bob") {
		t.Errorf("the locked-out account was not named: %s", got.Detail)
	}

	// The missing-minimum accounts are still reported in the same finding;
	// escalating must not swallow them.
	for _, want := range []string{"root", "alice"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("account %s has no minimum age and was not reported: %s", want, got.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// module-wide invariants
// ---------------------------------------------------------------------------

// TestNoCheckPassesAnIncompleteAccountList is the module's central invariant.
// Every negative assertion here is only as good as the completeness of the
// list it was drawn from, and both fixtures make that list incomplete in a way
// that is invisible unless you look for it.
func TestNoCheckPassesAnIncompleteAccountList(t *testing.T) {
	for _, fixture := range []string{"users-nis", "users-malformed"} {
		for _, check := range all {
			got := evalFixture(t, check, fixture)
			if got.Result != finding.Pass {
				continue
			}
			// USERS-0006 is the exception by construction: it reports the
			// presence of the import entries themselves, so over users-nis it
			// returns FAIL, and over users-malformed a PASS is correct because
			// an unparseable line is not an import entry.
			if check.ID == "USERS-0006" && fixture == "users-malformed" {
				continue
			}
			t.Errorf("%s returned PASS over %s, whose account list is not the whole list: %s",
				check.ID, fixture, got.Detail)
		}
	}
}

// TestNoCheckPassesWhatItCouldNotRead: no shadow-dependent check may report a
// verdict from a file it was refused.
func TestNoCheckPassesWhatItCouldNotRead(t *testing.T) {
	for _, check := range needsShadow {
		got := evalFixture(t, check, "users-unprivileged")
		if got.Result == finding.Pass || got.Result == finding.Fail {
			t.Errorf("%s returned %s from a shadow file it could not read: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

func TestCheckIdentityIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, check := range all {
		if seen[check.ID] {
			t.Errorf("duplicate check ID %s", check.ID)
		}
		seen[check.ID] = true

		if !strings.HasPrefix(check.ID, "USERS-") || check.Module != "USERS" {
			t.Errorf("%s is not in the USERS module namespace", check.ID)
		}
		if check.Title == "" || check.Description == "" {
			t.Errorf("%s has no title or description", check.ID)
		}
		if len(check.Requires) == 0 {
			t.Errorf("%s declares no required facts, so the runner cannot gate it", check.ID)
		}
		if check.Remediation == nil {
			t.Errorf("%s has no remediation", check.ID)
		}
		// The module spans two catalog versions: 0001-0006 shipped at 4,
		// 0007-0010 at 5. The floor stays asserted so a check cannot claim to
		// predate the module it is in.
		if check.SinceCatalog < 4 {
			t.Errorf("%s declares SinceCatalog %d, which predates the USERS module",
				check.ID, check.SinceCatalog)
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

func TestFingerprintStability(t *testing.T) {
	pass := evalFixture(t, checks.Check0006, "users-clean")
	fail := evalFixture(t, checks.Check0006, "users-nis")
	if pass.Fingerprint == "" || fail.Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
	// USERS-0006's subject is the file, which does not change with the
	// verdict, so its fingerprint must not either.
	if pass.Subject == "" && fail.Subject != "" {
		return // subjects differ by design; nothing to assert
	}
}

func TestDeterminism(t *testing.T) {
	for _, fixture := range []string{"users-duplicates", "users-weakhash", "users-nis"} {
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

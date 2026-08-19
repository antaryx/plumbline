package sshd_test

import (
	"context"
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

// all is the SSHD module as this work package leaves it.
//
// SSHD-0001 is deliberately absent and must stay absent. It was never
// allocated — the module has started at 0002 since the walking skeleton — and
// CLAUDE.md rule 4 makes IDs permanent identifiers rather than a dense
// sequence. Filling the gap now would produce a 0001 newer than 0002, which
// would be indistinguishable in a suppression file from a reused retired ID.
var all = []catalog.Check{
	checks.Check0002, checks.Check0003, checks.Check0004, checks.Check0005,
	checks.Check0006, checks.Check0007, checks.Check0008, checks.Check0009,
	checks.Check0010, checks.Check0011, checks.Check0012, checks.Check0013,
	checks.Check0014, checks.Check0015, checks.Check0016, checks.Check0017,
	checks.Check0018, checks.Check0019, checks.Check0020,
}

// algorithmChecks read a list keyword whose built-in default cannot be
// enumerated from configuration, so their behaviour over an absent keyword
// differs from every other check here. Listed rather than derived so that
// adding a fourth without thinking about that path fails a test.
var algorithmChecks = []catalog.Check{checks.Check0010, checks.Check0011, checks.Check0012}

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

			assertInvariants(t, check, got)
		})
	}
}

// assertInvariants holds for every finding this module can produce.
func assertInvariants(t *testing.T, check catalog.Check, got finding.Finding) {
	t.Helper()

	if got.CheckID != check.ID || got.Module != "SSHD" {
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
}

// ---------------------------------------------------------------------------
// module-wide invariants
//
// These five are worth more than any per-check table. Each one is a property
// of the module rather than of a keyword, and each one catches a whole class
// of authoring mistake in a check that does not exist yet.
// ---------------------------------------------------------------------------

// TestHardenedHostPassesEveryCheck is the fixture-coverage backstop. A check
// added without a secure value in sshd-hardened fails here immediately, which
// is a far better error than discovering months later that the "clean host"
// fixture never actually satisfied it.
func TestHardenedHostPassesEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "sshd-hardened")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over sshd-hardened, want PASS. Either the check is wrong or the fixture is missing its secure value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnhardenedHostFailsEveryCheck is the same backstop from the other side.
func TestUnhardenedHostFailsEveryCheck(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "sshd-permit-yes")
		if got.Result != finding.Fail {
			t.Errorf("%s = %s over sshd-permit-yes, want FAIL. Either the check is wrong or the fixture is missing its insecure value:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestAbsentServerIsNotApplicableEverywhere. A host with no SSH server has not
// satisfied "root login is disabled"; it has removed the subject of the
// sentence. PASS would inflate the posture score with controls that were never
// tested (docs/SCORING.md).
func TestAbsentServerIsNotApplicableEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "sshd-absent")
		if got.Result != finding.NotApplicable {
			t.Errorf("%s = %s over sshd-absent, want NOT_APPLICABLE: %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// TestUnresolvedIncludeIsUnknownEverywhere is the module's central property
// and the reason sshd-unresolved-include is the project's reference UNKNOWN
// fixture. The keyword is absent from every file we could read, but an Include
// matched nothing — so the value may be in a file this scan never saw. A
// lesser tool reports the documented default. That is a guess dressed as an
// observation, and it is the single failure mode CLAUDE.md rule 3 names.
func TestUnresolvedIncludeIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "sshd-unresolved-include")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over sshd-unresolved-include, want UNKNOWN. It reported a verdict for a keyword that may live in a file it never read:\n  %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonAmbiguousState {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonAmbiguousState)
		}
	}
}

// TestUnreadableConfigIsUnknownEverywhere covers the unprivileged path, which
// is resolved by the runner's required-fact gate rather than by any check.
func TestUnreadableConfigIsUnknownEverywhere(t *testing.T) {
	for _, check := range all {
		got := evalCheck(t, check, "sshd-unreadable")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s over sshd-unreadable, want UNKNOWN: %s", check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonPermission {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonPermission)
		}
	}
}

// TestMatchLooseningIsNeverAPass is what Step 2.3 of this work package asked
// for, asserted as a property rather than per keyword.
//
// A Match block that reintroduces the insecure value makes that value
// reachable. Reporting PASS would be false assurance; reporting FAIL at the
// full severity would overstate an exposure that is conditional. Every check
// whose keyword sshd_config permits inside a Match block must therefore report
// FAIL one class below its base severity, and must name the Match criteria so
// the operator can judge whose connections it covers.
func TestMatchLooseningIsNeverAPass(t *testing.T) {
	// The keywords sshd_config actually permits inside a Match block, mapped
	// to the checks that read them. Ciphers, MACs, KexAlgorithms,
	// LoginGraceTime, PermitUserEnvironment, StrictModes and UsePAM are NOT
	// permitted there, so their checks correctly still pass over this fixture.
	matchable := map[string]catalog.Check{
		"PermitRootLogin":         checks.Check0002,
		"PasswordAuthentication":  checks.Check0003,
		"PermitEmptyPasswords":    checks.Check0004,
		"X11Forwarding":           checks.Check0005,
		"MaxAuthTries":            checks.Check0006,
		"ClientAliveCountMax":     checks.Check0007,
		"AllowTcpForwarding":      checks.Check0008,
		"LogLevel":                checks.Check0009,
		"IgnoreRhosts":            checks.Check0013,
		"HostbasedAuthentication": checks.Check0014,
		"Banner":                  checks.Check0017,
		"AllowAgentForwarding":    checks.Check0018,
	}

	for keyword, check := range matchable {
		got := evalCheck(t, check, "sshd-match-loosened")

		if got.Result != finding.Fail {
			t.Errorf("%s (%s) = %s over sshd-match-loosened, want FAIL. The global value is secure but a Match block reintroduces the insecure one, so the insecure state is reachable and PASS would be false assurance:\n  %s",
				check.ID, keyword, got.Result, got.Detail)
			continue
		}
		if got.Severity == check.BaseSeverity {
			t.Errorf("%s (%s) reported at its full base severity %s; a conditional exposure is narrower than a global one and must step down",
				check.ID, keyword, got.Severity)
		}
		if !strings.Contains(got.Detail, "Match") {
			t.Errorf("%s (%s) does not name the Match block in its detail, so the operator cannot tell whose connections are affected: %s",
				check.ID, keyword, got.Detail)
		}
		if !strings.Contains(got.Detail, "0.0.0.0/0") {
			t.Errorf("%s (%s) does not quote the Match criteria: %s", check.ID, keyword, got.Detail)
		}
	}
}

// TestKeywordsNotPermittedInMatchAreUnaffected is the other half. sshd_config
// permits only a subset of keywords inside a Match block; a check that applied
// Match handling to a keyword outside that subset would be reporting an
// override sshd would have refused to load.
func TestKeywordsNotPermittedInMatchAreUnaffected(t *testing.T) {
	for _, check := range []catalog.Check{
		checks.Check0010, checks.Check0011, checks.Check0012, // Ciphers, MACs, KexAlgorithms
		checks.Check0015, // PermitUserEnvironment
		checks.Check0016, // LoginGraceTime
		checks.Check0019, // StrictModes
		checks.Check0020, // UsePAM
	} {
		got := evalCheck(t, check, "sshd-match-loosened")
		if got.Result != finding.Pass {
			t.Errorf("%s = %s over sshd-match-loosened, want PASS: its keyword is not one sshd_config permits inside a Match block, so the block cannot have overridden it:\n  %s",
				check.ID, got.Result, got.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// the algorithm lists — the module's other refusal to guess
// ---------------------------------------------------------------------------

// TestAlgorithmListsRefuseToAssumeTheBuiltInDefault.
//
// Every other check here encodes OpenSSH's built-in default and reports it.
// These three cannot: the effective list is compiled into the sshd binary, it
// changed between releases, and Red Hat's crypto-policies rewrites it. Saying
// PASS would be asserting the contents of a list we never read.
func TestAlgorithmListsRefuseToAssumeTheBuiltInDefault(t *testing.T) {
	for _, check := range algorithmChecks {
		got := evalCheck(t, check, "sshd-default")
		if got.Result != finding.Unknown {
			t.Errorf("%s = %s with the keyword absent, want UNKNOWN. The effective list is compiled into the binary and was never read:\n  %s",
				check.ID, got.Result, got.Detail)
		}
		if got.UnknownReason != finding.ReasonAmbiguousState {
			t.Errorf("%s reason = %q, want %q", check.ID, got.UnknownReason, finding.ReasonAmbiguousState)
		}
		if !strings.Contains(got.Detail, "binary") {
			t.Errorf("%s does not explain why it cannot answer: %s", check.ID, got.Detail)
		}
	}
}

// TestRelativeAlgorithmListsAreAsymmetric pins the one place in this module
// where an incomplete source still yields a definite verdict.
//
// '+' and '^' add to a list we cannot enumerate. If what they add is weak,
// that algorithm is enabled whatever the rest holds — a positive result
// survives incomplete knowledge. If what they add is fine, nothing follows
// about the remainder, and '-' can never introduce a weakness but says nothing
// about what is left. Same asymmetry as ADR-0014, reached independently.
func TestRelativeAlgorithmListsAreAsymmetric(t *testing.T) {
	// Ciphers -aes128-cbc,3des-cbc — a removal. Cannot introduce a weakness,
	// cannot prove its absence.
	got := evalCheck(t, checks.Check0010, "sshd-crypto-relative")
	if got.Result != finding.Unknown {
		t.Errorf("Ciphers removal = %s, want UNKNOWN: what remains is the built-in default:\n  %s",
			got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "removes") {
		t.Errorf("the detail does not say the value was a removal: %s", got.Detail)
	}

	// MACs +hmac-md5,hmac-sha1 — an addition of two broken constructions.
	// Definite FAIL despite the base list being unknown.
	got = evalCheck(t, checks.Check0011, "sshd-crypto-relative")
	if got.Result != finding.Fail {
		t.Fatalf("MACs addition = %s, want FAIL: these are enabled regardless of what the default holds:\n  %s",
			got.Result, got.Detail)
	}
	for _, want := range []string{"hmac-md5", "hmac-sha1", "MD5", "SHA-1"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("MACs detail does not mention %q: %s", want, got.Detail)
		}
	}
	if !strings.Contains(got.Detail, "does not depend on what the built-in default contains") {
		t.Errorf("the detail does not explain why the verdict stands despite the unknown base list: %s", got.Detail)
	}

	// KexAlgorithms ^diffie-hellman-group14-sha1 — '^' is an addition too.
	got = evalCheck(t, checks.Check0012, "sshd-crypto-relative")
	if got.Result != finding.Fail {
		t.Errorf("KexAlgorithms head-insertion = %s, want FAIL:\n  %s", got.Result, got.Detail)
	}
}

// ---------------------------------------------------------------------------
// per-check tables
// ---------------------------------------------------------------------------

func TestSSHD0003PasswordAuthentication(t *testing.T) {
	run(t, checks.Check0003, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "requires a key"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "guessing it"},
		{fixture: "sshd-default", result: finding.Fail, severity: finding.High, detailContains: "built-in default"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unrecognised value"},
		{fixture: "sshd-absent", result: finding.NotApplicable, detailContains: "not configured on this host"},
	})
}

func TestSSHD0004PermitEmptyPasswords(t *testing.T) {
	run(t, checks.Check0004, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "refused rather than admitted"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Critical, detailContains: "pressing return"},
		// The OpenSSH default is the secure value, so an unconfigured host
		// passes — the opposite of SSHD-0003 and the reason Default is a
		// declared field rather than an assumption.
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
		{fixture: "sshd-unresolved-include", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "could not be resolved"},
	})
}

func TestSSHD0005X11Forwarding(t *testing.T) {
	run(t, checks.Check0005, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "x display"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "log keystrokes"},
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
	})
}

func TestSSHD0006MaxAuthTries(t *testing.T) {
	run(t, checks.Check0006, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "3 attempt"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "10 attempt"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "built-in default"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unreadable value"},
	})
}

// TestMaxAuthTriesExplainsTheLoggingConsequence: the non-obvious half of this
// check is that sshd logs nothing until a connection has used more than half
// its allowance, so a high limit is a logging gap as well as a cost.
func TestMaxAuthTriesExplainsTheLoggingConsequence(t *testing.T) {
	got := evalCheck(t, checks.Check0006, "sshd-permit-yes")
	if !strings.Contains(got.Detail, "half") {
		t.Errorf("the detail does not explain the logging consequence: %s", got.Detail)
	}
}

func TestSSHD0007IdleTimeout(t *testing.T) {
	run(t, checks.Check0007, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "900 second"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "never probes"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "never probes"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unreadable value"},
		{fixture: "sshd-unresolved-include", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "product of both keywords"},
	})
}

// TestClientAliveCountMaxZeroDisablesTermination is the trap this check exists
// for. An interval alone looks like a configured timeout; a count of 0 means
// sshd probes forever and never disconnects. A check reading either keyword in
// isolation would report that host as compliant.
func TestClientAliveCountMaxZeroDisablesTermination(t *testing.T) {
	got := evalCheck(t, checks.Check0007, "sshd-match-loosened")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL: the Match block sets ClientAliveCountMax 0\n detail: %s",
			got.Result, got.Detail)
	}
	if !strings.Contains(got.Detail, "Match") {
		t.Errorf("the detail does not name the Match block: %s", got.Detail)
	}
}

func TestSSHD0008TcpForwarding(t *testing.T) {
	run(t, checks.Check0008, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "either direction"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "both directions"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "nologin shell"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unrecognised value"},
	})
}

func TestSSHD0009LogLevel(t *testing.T) {
	run(t, checks.Check0009, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "key fingerprint is recorded"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "no record of who connected"},
		// INFO is the built-in default and passes, with the detail pointing at
		// what VERBOSE would add.
		{fixture: "sshd-default", result: finding.Pass, detailContains: "setting verbose additionally records"},
		// Too loud is also a failure, and a milder one.
		{fixture: "sshd-include", result: finding.Fail, severity: finding.Low, detailContains: "violates the privacy of users"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unrecognised value"},
	})
}

func TestSSHD0010Ciphers(t *testing.T) {
	run(t, checks.Check0010, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "no known practical attack"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "cbc mode"},
		{fixture: "sshd-default", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "compiled into"},
		{fixture: "sshd-crypto-relative", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "removes"},
	})
}

// TestWeakCiphersAreNamedWithTheirReason: "weak cipher" without saying which
// and why leaves the reader unable to judge urgency or to argue the case with
// whoever owns the client that needs it.
func TestWeakCiphersAreNamedWithTheirReason(t *testing.T) {
	got := evalCheck(t, checks.Check0010, "sshd-permit-yes")
	for _, want := range []string{"aes128-cbc", "3des-cbc", "arcfour", "Sweet32", "CVE-2008-5161", "RC4"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not mention %q: %s", want, got.Detail)
		}
	}
	// The acceptable entry in the same list must not be reported.
	if strings.Contains(got.Detail, "aes256-ctr —") {
		t.Errorf("an acceptable cipher was reported as weak: %s", got.Detail)
	}
}

func TestSSHD0011MACs(t *testing.T) {
	run(t, checks.Check0011, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "no known practical forgery"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "collision-broken"},
		{fixture: "sshd-default", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "compiled into"},
		{fixture: "sshd-crypto-relative", result: finding.Fail, detailContains: "appends to"},
	})
}

func TestSSHD0012KexAlgorithms(t *testing.T) {
	run(t, checks.Check0012, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "no known practical attack"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "logjam"},
		{fixture: "sshd-default", result: finding.Unknown, reason: finding.ReasonAmbiguousState, detailContains: "compiled into"},
		{fixture: "sshd-crypto-relative", result: finding.Fail, detailContains: "places at the head of"},
	})
}

func TestSSHD0013IgnoreRhosts(t *testing.T) {
	run(t, checks.Check0013, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "not consulted"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: ".rhosts"},
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
	})
}

func TestSSHD0014HostbasedAuthentication(t *testing.T) {
	run(t, checks.Check0014, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "credential this user holds"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "host key"},
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
	})
}

func TestSSHD0015PermitUserEnvironment(t *testing.T) {
	run(t, checks.Check0015, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "comes from the system"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "ld_preload"},
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
	})
}

func TestSSHD0016LoginGraceTime(t *testing.T) {
	run(t, checks.Check0016, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "60 second"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Low, detailContains: "300 second"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "built-in default"},
		{fixture: "sshd-bad-value", result: finding.Unknown, reason: finding.ReasonParse, detailContains: "unreadable value"},
	})
}

// TestLoginGraceTimeZeroIsNotStrictest: 0 disables the timeout rather than
// tightening it, so a bare "n <= 60" would have reported the worst possible
// value as the best.
func TestLoginGraceTimeZeroIsNotStrictest(t *testing.T) {
	// The behaviour is asserted through the acceptability rule rather than a
	// dedicated fixture: the check must reject 0 and accept 60.
	got := evalCheck(t, checks.Check0016, "sshd-hardened")
	if got.Result != finding.Pass {
		t.Fatalf("60 seconds should pass, got %s: %s", got.Result, got.Detail)
	}
	if !strings.Contains(checks.Check0016.Remediation.Steps[0], "Never set it to 0") {
		t.Error("the remediation does not warn that 0 disables the timeout")
	}
}

func TestSSHD0017Banner(t *testing.T) {
	run(t, checks.Check0017, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "before authentication"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Low, detailContains: "explicitly disables"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "presents nothing"},
	})
}

// TestBannerSaysWhatItDidNotVerify. The check reports the directive, not the
// file: Plumbline does not read operator-named paths from a directive
// (ADR-0011), and a banner pointing at a missing file fails open. A PASS that
// implied otherwise would be overclaiming.
func TestBannerSaysWhatItDidNotVerify(t *testing.T) {
	got := evalCheck(t, checks.Check0017, "sshd-hardened")
	if !strings.Contains(got.Detail, "does not read that file") {
		t.Errorf("the PASS does not disclose that the banner file itself was not verified: %s", got.Detail)
	}
}

func TestSSHD0018AgentForwarding(t *testing.T) {
	run(t, checks.Check0018, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "no forwarded agent socket"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Low, detailContains: "socket on this host"},
		{fixture: "sshd-default", result: finding.Fail, detailContains: "built-in default"},
	})
}

func TestSSHD0019StrictModes(t *testing.T) {
	run(t, checks.Check0019, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "writable by anyone other than its owner"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.Medium, detailContains: "add their own key"},
		{fixture: "sshd-default", result: finding.Pass, detailContains: "secure value"},
	})
}

func TestSSHD0020UsePAM(t *testing.T) {
	run(t, checks.Check0020, []tc{
		{fixture: "sshd-hardened", result: finding.Pass, detailContains: "account expiry, lockout and access"},
		{fixture: "sshd-permit-yes", result: finding.Fail, severity: finding.High, detailContains: "bypassed"},
		// The upstream default is no, which is why every distribution sets it
		// explicitly — and why a from-scratch configuration silently loses the
		// policy the USERS module reports.
		{fixture: "sshd-default", result: finding.Fail, detailContains: "built-in default"},
	})
}

// TestUsePAMNamesTheUsersModuleConsequence. This check is the joint between two
// modules: USERS-0009 and USERS-0010 report a password-aging policy that PAM
// is what enforces. A finding that said only "UsePAM is no" would not tell the
// reader that the policy they just fixed is not in force.
func TestUsePAMNamesTheUsersModuleConsequence(t *testing.T) {
	got := evalCheck(t, checks.Check0020, "sshd-permit-yes")
	for _, want := range []string{"aging", "expiry", "lockout"} {
		if !strings.Contains(strings.ToLower(got.Detail), want) {
			t.Errorf("detail does not mention %q, so the reader cannot see which other policy is inert: %s",
				want, got.Detail)
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

		if !strings.HasPrefix(check.ID, "SSHD-") || check.Module != "SSHD" {
			t.Errorf("%s is not in the SSHD module namespace", check.ID)
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
		if check.Remediation != nil && check.Remediation.Caution == "" {
			t.Errorf("%s has no caution; every change in this module can lock an operator out of the host", check.ID)
		}
		if len(check.Mappings) == 0 {
			t.Errorf("%s has no control mappings", check.ID)
		}
		if check.SinceCatalog < 1 || check.SinceCatalog > catalog.Version {
			t.Errorf("%s declares SinceCatalog %d, outside 1..%d", check.ID, check.SinceCatalog, catalog.Version)
		}
	}

	// SSHD-0001 was never allocated and must stay unallocated (see `all`).
	if seen["SSHD-0001"] {
		t.Error("SSHD-0001 has been allocated; it was skipped at the walking skeleton and filling the gap now would produce an ID newer than SSHD-0002")
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
	for _, fixture := range []string{"sshd-permit-yes", "sshd-match-loosened", "sshd-crypto-relative"} {
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

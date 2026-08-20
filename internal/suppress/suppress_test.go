package suppress_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/suppress"
)

// scanTime is the moment every Apply in this file is measured against. It is a
// fixed literal rather than time.Now for the same reason the production code
// takes the scan's start time: a test whose result depends on the day it runs
// is a test that will fail one morning for no reason anybody can reproduce.
var scanTime = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func fp(checkID, subject string) string { return finding.Fingerprint(checkID, subject) }

func file(t *testing.T, rules ...map[string]any) []byte {
	t.Helper()
	doc := map[string]any{"schema": suppress.Schema, "suppressions": rules}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling the fixture: %v", err)
	}
	return b
}

func parse(t *testing.T, data []byte) *suppress.Set {
	t.Helper()
	set, err := suppress.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return set
}

// findings returns a small set covering every result state, so a test can
// assert not only what suppression changes but what it leaves alone.
func findings() []finding.Finding {
	return []finding.Finding{
		{
			CheckID: "CRON-0001", Module: "CRON", Title: "crontab is root-owned",
			Result: finding.Fail, Severity: finding.High, BaseSeverity: finding.High,
			Subject: "/etc/crontab", Fingerprint: fp("CRON-0001", "/etc/crontab"),
		},
		{
			CheckID: "FILESYS-0010", Module: "FILESYS", Title: "every owner resolves",
			Result: finding.Unknown, UnknownReason: finding.ReasonAmbiguousState,
			Severity: finding.Medium, BaseSeverity: finding.Medium,
			Fingerprint: fp("FILESYS-0010", ""),
		},
		{
			CheckID: "SSHD-0002", Module: "SSHD", Title: "root may not log in",
			Result: finding.Pass, Severity: finding.High, BaseSeverity: finding.High,
			Fingerprint: fp("SSHD-0002", ""),
		},
	}
}

func byID(t *testing.T, in []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range in {
		if f.CheckID == id {
			return f
		}
	}
	t.Fatalf("%s is missing from the findings entirely — suppression must never drop a row", id)
	return finding.Finding{}
}

// ---------------------------------------------------------------------------
// the three cases WP-29 names
// ---------------------------------------------------------------------------

// TestAMatchingFingerprintTurnsFailIntoSkipped is the feature in one test, and
// the assertions past the first one are the point: a suppression that merely
// changed the result would be a suppression that hid the finding.
func TestAMatchingFingerprintTurnsFailIntoSkipped(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("CRON-0001", "/etc/crontab"),
		"justification": "deploy account owns cron by design; tracked in SEC-4471",
	}))

	out := set.Apply(findings(), scanTime)

	got := byID(t, out.Findings, "CRON-0001")
	if got.Result != finding.Skipped {
		t.Fatalf("result = %s, want SKIPPED", got.Result)
	}
	if got.Suppression == nil {
		t.Fatal("the finding is SKIPPED but carries no suppression, so nothing says why")
	}
	if got.Suppression.OriginalResult != finding.Fail {
		t.Errorf("original_result = %s, want FAIL — the document must still say what it would have been",
			got.Suppression.OriginalResult)
	}
	if !strings.Contains(got.Suppression.Justification, "SEC-4471") {
		t.Errorf("justification = %q, want the operator's reason carried through", got.Suppression.Justification)
	}
	// Everything else about the finding survives. A suppressed finding that
	// lost its severity or its detail would be unreviewable.
	if got.Severity != finding.High || got.Title == "" || got.Fingerprint == "" {
		t.Errorf("suppression damaged the finding: %+v", got)
	}
	if len(out.Findings) != len(findings()) {
		t.Errorf("findings went from %d to %d; suppression must never drop a row",
			len(findings()), len(out.Findings))
	}
	if out.Suppressed() != 1 || len(out.Applied) != 1 {
		t.Errorf("outcome does not report the rule as applied: %+v", out)
	}
}

// TestAnExpiredRuleDoesNotSuppress. An expiry that does not expire is a
// comment. This is the test that makes it a mechanism.
func TestAnExpiredRuleDoesNotSuppress(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("CRON-0001", "/etc/crontab"),
		"justification": "temporary, pending the Q2 maintenance window",
		"expires_at":    "2026-06-30T00:00:00Z", // before scanTime
	}))

	out := set.Apply(findings(), scanTime)

	got := byID(t, out.Findings, "CRON-0001")
	if got.Result != finding.Fail {
		t.Fatalf("result = %s, want FAIL — a lapsed acceptance must stop protecting the finding", got.Result)
	}
	if got.Suppression != nil {
		t.Error("an expired rule still attached a suppression")
	}
	if len(out.Expired) != 1 {
		t.Errorf("the lapse is not reported: %+v", out)
	}
	if out.Suppressed() != 0 {
		t.Errorf("Suppressed() = %d, want 0", out.Suppressed())
	}
}

// TestExpiryIsInclusiveOfTheInstantItNames. A rule expiring at T is spent at
// T, not one nanosecond later. The boundary is asserted because "expires
// 2027-01-01" meaning "still live throughout 2027-01-01" is exactly the kind
// of off-by-one nobody notices until an audit.
func TestExpiryIsInclusiveOfTheInstantItNames(t *testing.T) {
	expiry := scanTime
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("CRON-0001", "/etc/crontab"),
		"justification": "expires exactly now",
		"expires_at":    expiry.Format(time.RFC3339),
	}))

	if got := byID(t, set.Apply(findings(), expiry).Findings, "CRON-0001"); got.Result != finding.Fail {
		t.Errorf("at the expiry instant the rule still applied; result = %s, want FAIL", got.Result)
	}
	one := expiry.Add(-time.Nanosecond)
	if got := byID(t, set.Apply(findings(), one).Findings, "CRON-0001"); got.Result != finding.Skipped {
		t.Errorf("one nanosecond before expiry the rule did not apply; result = %s, want SKIPPED", got.Result)
	}
}

// TestANonMatchingFingerprintChangesNothing, and says so. A rule that matches
// nothing is either a finding that got fixed or a suppression that has quietly
// stopped covering what its author thought it covered.
func TestANonMatchingFingerprintChangesNothing(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("KERNEL-0001", "/proc/sys/kernel/randomize_va_space"),
		"justification": "not a finding on this host",
	}))

	before := findings()
	out := set.Apply(before, scanTime)

	for i := range before {
		if out.Findings[i].Result != before[i].Result || out.Findings[i].Suppression != nil {
			t.Fatalf("a non-matching rule changed %s", out.Findings[i].CheckID)
		}
	}
	if len(out.Unmatched) != 1 {
		t.Errorf("a rule that matched nothing is not reported as unmatched: %+v", out)
	}
}

// TestAPassIsNeverSuppressed. There is nothing to accept about a check that
// passed, and rewriting one to SKIPPED would delete good news and quietly
// lower coverage.
func TestAPassIsNeverSuppressed(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("SSHD-0002", ""),
		"justification": "this one passes, so this rule should do nothing",
	}))

	out := set.Apply(findings(), scanTime)

	got := byID(t, out.Findings, "SSHD-0002")
	if got.Result != finding.Pass || got.Suppression != nil {
		t.Errorf("a PASS was suppressed: %+v", got)
	}
	if len(out.Unmatched) != 1 {
		t.Errorf("the rule should be reported as unmatched so the operator can delete it: %+v", out)
	}
}

// TestUnknownIsSuppressibleToo. An UNKNOWN is a finding in this project, so it
// has to be acceptable in the same way a FAIL is — otherwise a host with an
// unresolvable check can never reach a quiet report however carefully it is
// reviewed.
func TestUnknownIsSuppressibleToo(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("FILESYS-0010", ""),
		"justification": "identities come from LDAP; reviewed 2026-08 by platform-sec",
	}))

	got := byID(t, set.Apply(findings(), scanTime).Findings, "FILESYS-0010")
	if got.Result != finding.Skipped {
		t.Fatalf("result = %s, want SKIPPED", got.Result)
	}
	if got.Suppression.OriginalResult != finding.Unknown {
		t.Errorf("original_result = %s, want UNKNOWN", got.Suppression.OriginalResult)
	}
}

// TestNilSetIsANoOp. "No --suppress" is the overwhelmingly common case and it
// must not need a branch at every call site.
func TestNilSetIsANoOp(t *testing.T) {
	var set *suppress.Set
	out := set.Apply(findings(), scanTime)
	if len(out.Findings) != 3 || out.Suppressed() != 0 || set.Len() != 0 {
		t.Errorf("a nil set was not a no-op: %+v", out)
	}
}

// TestApplyDoesNotMutateItsInput. The caller keeps the pre-suppression
// findings in scope; writing through the backing array would rewrite history
// underneath them.
func TestApplyDoesNotMutateItsInput(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("CRON-0001", "/etc/crontab"),
		"justification": "accepted",
	}))

	in := findings()
	_ = set.Apply(in, scanTime)

	if in[0].Result != finding.Fail || in[0].Suppression != nil {
		t.Errorf("Apply mutated the caller's slice: %+v", in[0])
	}
}

// ---------------------------------------------------------------------------
// what the parser refuses
// ---------------------------------------------------------------------------

// TestTheParserRefusesAnythingItCannotAccountFor. Every case here is a way a
// suppression could end up applying without anybody being able to say why, and
// each one is a hard parse error rather than a warning: a warning on stderr in
// CI is a warning nobody reads.
func TestTheParserRefusesAnythingItCannotAccountFor(t *testing.T) {
	good := fp("CRON-0001", "/etc/crontab")

	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{
			"a blank justification",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q,"justification":"   "}]}`,
				suppress.Schema, good),
			"justification is required",
		},
		{
			"a missing justification",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q}]}`, suppress.Schema, good),
			"justification is required",
		},
		{
			"a fingerprint that is not one",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":"CRON-0001","justification":"x"}]}`,
				suppress.Schema),
			"32 lowercase hex",
		},
		{
			"an unparseable expiry",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q,"justification":"x","expires_at":"next tuesday"}]}`,
				suppress.Schema, good),
			"RFC 3339",
		},
		{
			"the wrong schema",
			fmt.Sprintf(`{"schema":"suppressions/v9","suppressions":[{"fingerprint":%q,"justification":"x"}]}`, good),
			"this build understands",
		},
		{
			"no schema at all",
			fmt.Sprintf(`{"suppressions":[{"fingerprint":%q,"justification":"x"}]}`, good),
			"this build understands",
		},
		{
			"the same finding twice",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q,"justification":"a"},{"fingerprint":%q,"justification":"b"}]}`,
				suppress.Schema, good, good),
			"more than once",
		},
		{
			// The typo that silently disarms the requirement the whole format
			// exists to enforce.
			"a misspelled key",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q,"justifcation":"oops"}]}`,
				suppress.Schema, good),
			"unknown field",
		},
		{
			"a label that describes a different finding",
			fmt.Sprintf(`{"schema":%q,"suppressions":[{"fingerprint":%q,"justification":"x","check_id":"SSHD-0002","subject":"/etc/ssh/sshd_config"}]}`,
				suppress.Schema, good),
			"describe different findings",
		},
		{
			"not JSON at all",
			`{"schema":`,
			"not valid JSON",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := suppress.Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem (%q)", err, tc.want)
			}
		})
	}
}

// TestAnAccurateLabelIsAccepted. The advisory fields are verified rather than
// trusted, so the verification has to accept a correct one.
func TestAnAccurateLabelIsAccepted(t *testing.T) {
	set := parse(t, file(t, map[string]any{
		"fingerprint":   fp("CRON-0001", "/etc/crontab"),
		"justification": "accepted",
		"check_id":      "CRON-0001",
		"subject":       "/etc/crontab",
	}))
	if got := byID(t, set.Apply(findings(), scanTime).Findings, "CRON-0001"); got.Result != finding.Skipped {
		t.Errorf("a correctly labelled rule did not apply; result = %s", got.Result)
	}
}

// TestAnEmptyFileParses. Zero rules is a legitimate state — a team that has
// fixed everything they once accepted — and it must not be an error.
func TestAnEmptyFileParses(t *testing.T) {
	set := parse(t, []byte(fmt.Sprintf(`{"schema":%q,"suppressions":[]}`, suppress.Schema)))
	if set.Len() != 0 {
		t.Errorf("Len = %d, want 0", set.Len())
	}
	if got := set.Apply(findings(), scanTime); got.Suppressed() != 0 {
		t.Errorf("an empty file suppressed something: %+v", got)
	}
}

// TestOutcomeIsDeterministic. Two runs over the same input must report the
// same rules in the same order, or the stderr lines churn between runs.
func TestOutcomeIsDeterministic(t *testing.T) {
	set := parse(t, file(t,
		map[string]any{"fingerprint": fp("CRON-0001", "/etc/crontab"), "justification": "a"},
		map[string]any{"fingerprint": fp("KERNEL-0001", ""), "justification": "b"},
		map[string]any{"fingerprint": fp("FILESYS-0010", ""), "justification": "c", "expires_at": "2026-01-01T00:00:00Z"},
	))

	first := set.Apply(findings(), scanTime)
	for i := 0; i < 20; i++ {
		got := set.Apply(findings(), scanTime)
		if fmt.Sprint(got.Applied) != fmt.Sprint(first.Applied) ||
			fmt.Sprint(got.Expired) != fmt.Sprint(first.Expired) ||
			fmt.Sprint(got.Unmatched) != fmt.Sprint(first.Unmatched) {
			t.Fatalf("run %d differs from the first", i)
		}
	}
	if len(first.Applied) != 1 || len(first.Expired) != 1 || len(first.Unmatched) != 1 {
		t.Errorf("expected one of each outcome, got %+v", first)
	}
}

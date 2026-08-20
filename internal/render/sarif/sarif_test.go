package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	rendersarif "github.com/antaryx/plumbline/internal/render/sarif"
	"github.com/antaryx/plumbline/internal/score"
)

var (
	started  = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	finished = time.Date(2026, 8, 20, 9, 0, 2, 0, time.UTC)
)

func f(checkID, subject string, r finding.Result, sev finding.Severity) finding.Finding {
	return finding.Finding{
		CheckID: checkID, Module: strings.SplitN(checkID, "-", 2)[0],
		Title: checkID + " title", Detail: checkID + " detail",
		Result: r, Severity: sev, BaseSeverity: sev,
		Subject: subject, Fingerprint: finding.Fingerprint(checkID, subject),
		Remediation: &finding.Remediation{Summary: checkID + " remedy"},
	}
}

// sample carries one of every result state, which is what the ADR specifies
// the mapping for.
func sample() rendersarif.Input {
	findings := []finding.Finding{
		f("SSHD-0002", "/etc/ssh/sshd_config", finding.Fail, finding.Critical),
		f("CRON-0003", "/etc/cron.deny", finding.Fail, finding.Low),
		unknown(f("FILESYS-0010", "", finding.Unknown, finding.Medium), finding.ReasonAmbiguousState),
		accepted(f("USERS-0001", "root", finding.Fail, finding.High), "break-glass, SEC-4471"),
		f("KERNEL-0001", "", finding.Pass, finding.High),
		f("NETWORK-0001", "", finding.NotApplicable, finding.Medium),
		f("AUTH-0001", "", finding.Skipped, finding.Medium), // skipped, not suppressed
	}
	return rendersarif.Input{
		Tool: rendersarif.Tool{Name: "plumbline", Version: "0.5.0-dev"},
		Scan: rendersarif.Scan{
			Started: started, Finished: finished, Root: "", EUID: 0,
			Profile: "default", Hostname: "auditbox",
		},
		Score:    score.Compute(findings, 13),
		Findings: findings,
	}
}

func unknown(in finding.Finding, reason finding.UnknownReason) finding.Finding {
	in.UnknownReason = reason
	return in
}

func accepted(in finding.Finding, why string) finding.Finding {
	in.Suppression = &finding.Suppression{Justification: why, OriginalResult: in.Result}
	in.Result = finding.Skipped
	return in
}

// doc is the parsed SARIF, addressed loosely so a test asserts the wire shape
// rather than the Go types that produced it.
type doc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string `json:"name"`
				Version         string `json:"version"`
				SemanticVersion string `json:"semanticVersion"`
				InformationURI  string `json:"informationUri"`
				Rules           []struct {
					ID                   string                  `json:"id"`
					ShortDescription     *struct{ Text string }  `json:"shortDescription"`
					Help                 *struct{ Text string }  `json:"help"`
					DefaultConfiguration *struct{ Level string } `json:"defaultConfiguration"`
					Properties           map[string]any          `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool           `json:"executionSuccessful"`
			StartTimeUTC        string         `json:"startTimeUtc"`
			Properties          map[string]any `json:"properties"`
		} `json:"invocations"`
		Results []struct {
			RuleID              string                `json:"ruleId"`
			RuleIndex           int                   `json:"ruleIndex"`
			Level               string                `json:"level"`
			Message             struct{ Text string } `json:"message"`
			PartialFingerprints map[string]string     `json:"partialFingerprints"`
			Locations           []struct {
				PhysicalLocation struct {
					ArtifactLocation struct{ URI string } `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Suppressions []struct {
				Kind          string `json:"kind"`
				Justification string `json:"justification"`
			} `json:"suppressions"`
			Properties map[string]any `json:"properties"`
		} `json:"results"`
		ColumnKind string `json:"columnKind"`
	} `json:"runs"`
}

func render(t *testing.T, in rendersarif.Input) (doc, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := rendersarif.Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var d doc
	if err := json.Unmarshal(buf.Bytes(), &d); err != nil {
		t.Fatalf("rendered output is not JSON: %v\n%s", err, buf.String())
	}
	return d, buf.Bytes()
}

func resultFor(t *testing.T, d doc, checkID string) int {
	t.Helper()
	for i, r := range d.Runs[0].Results {
		if r.RuleID == checkID {
			return i
		}
	}
	t.Fatalf("%s is not among the results", checkID)
	return -1
}

// ---------------------------------------------------------------------------
// the mapping ADR-0018 specifies
// ---------------------------------------------------------------------------

// TestOnlyActionableFindingsBecomeResults. PASS, NOT_APPLICABLE and a SKIPPED
// carrying no suppression are counted, never emitted. Seventy-four passing
// checks in a security tab bury the three that matter.
func TestOnlyActionableFindingsBecomeResults(t *testing.T) {
	d, _ := render(t, sample())
	got := map[string]bool{}
	for _, r := range d.Runs[0].Results {
		got[r.RuleID] = true
	}

	for _, want := range []string{"SSHD-0002", "CRON-0003", "FILESYS-0010", "USERS-0001"} {
		if !got[want] {
			t.Errorf("%s should be a result", want)
		}
	}
	for _, mustNot := range []string{"KERNEL-0001", "NETWORK-0001", "AUTH-0001"} {
		if got[mustNot] {
			t.Errorf("%s is a PASS, NOT_APPLICABLE or unsuppressed SKIPPED and must not be a result", mustNot)
		}
	}
	if n := len(d.Runs[0].Results); n != 4 {
		t.Errorf("results = %d, want 4", n)
	}
}

// TestFailLevelsFollowSeverity.
func TestFailLevelsFollowSeverity(t *testing.T) {
	d, _ := render(t, sample())
	for _, tc := range []struct{ id, want string }{
		{"SSHD-0002", "error"},   // CRITICAL
		{"CRON-0003", "warning"}, // LOW
	} {
		if got := d.Runs[0].Results[resultFor(t, d, tc.id)].Level; got != tc.want {
			t.Errorf("%s level = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// TestUnknownIsAWarningAndSaysWhatItIs. This is the load-bearing decision of
// the whole mapping. `none` would file an unknown as informational, which
// reports a cleaner host than the scan found; `error` would claim a failure
// nobody observed.
func TestUnknownIsAWarningAndSaysWhatItIs(t *testing.T) {
	d, _ := render(t, sample())
	r := d.Runs[0].Results[resultFor(t, d, "FILESYS-0010")]

	if r.Level != "warning" {
		t.Errorf("UNKNOWN level = %q, want warning", r.Level)
	}
	if !strings.HasPrefix(r.Message.Text, "Could not determine") {
		t.Errorf("the message does not open by saying it could not tell: %q", r.Message.Text)
	}
	if got := r.Properties["plumbline/result"]; got != "UNKNOWN" {
		t.Errorf("plumbline/result = %v, want UNKNOWN", got)
	}
	if got := r.Properties["plumbline/unknown_reason"]; got != string(finding.ReasonAmbiguousState) {
		t.Errorf("plumbline/unknown_reason = %v, want %s", got, finding.ReasonAmbiguousState)
	}
}

// TestASuppressedFindingUsesTheSuppressionsArray. SARIF models suppression
// natively with a justification field; it is the one place the two models line
// up exactly, and using it means an accepted risk shows as dismissed with a
// reason rather than as absent.
func TestASuppressedFindingUsesTheSuppressionsArray(t *testing.T) {
	d, _ := render(t, sample())
	r := d.Runs[0].Results[resultFor(t, d, "USERS-0001")]

	if len(r.Suppressions) != 1 {
		t.Fatalf("suppressions = %d, want 1", len(r.Suppressions))
	}
	if r.Suppressions[0].Kind != "external" {
		t.Errorf("kind = %q, want external", r.Suppressions[0].Kind)
	}
	if !strings.Contains(r.Suppressions[0].Justification, "SEC-4471") {
		t.Errorf("the justification did not survive: %q", r.Suppressions[0].Justification)
	}
	// It keeps the level its original verdict earned: a suppressed finding is
	// still a finding and only its standing changed.
	if r.Level != "error" {
		t.Errorf("level = %q, want error (the finding was HIGH before it was accepted)", r.Level)
	}
	if got := r.Properties["plumbline/original_result"]; got != "FAIL" {
		t.Errorf("plumbline/original_result = %v, want FAIL", got)
	}
}

// TestEveryResultCarriesAPartialFingerprint. This is what lets GitHub track a
// finding across commits, and ADR-0018 records why the key is versioned.
func TestEveryResultCarriesAPartialFingerprint(t *testing.T) {
	d, _ := render(t, sample())
	for _, r := range d.Runs[0].Results {
		fp, ok := r.PartialFingerprints["plumblineFingerprint/v1"]
		if !ok {
			t.Errorf("%s carries no plumblineFingerprint/v1", r.RuleID)
			continue
		}
		if len(fp) != 32 {
			t.Errorf("%s fingerprint %q is not 32 hex characters", r.RuleID, fp)
		}
	}
}

// TestFingerprintsMatchTheFindingsDocument. The SARIF fingerprint and the one a
// suppression file matches on must be the same string, or a team's dismissals
// and their suppressions drift apart.
func TestFingerprintsMatchTheFindingsDocument(t *testing.T) {
	in := sample()
	d, _ := render(t, in)
	want := map[string]string{}
	for _, fnd := range in.Findings {
		want[fnd.CheckID] = fnd.Fingerprint
	}
	for _, r := range d.Runs[0].Results {
		if got := r.PartialFingerprints["plumblineFingerprint/v1"]; got != want[r.RuleID] {
			t.Errorf("%s: SARIF fingerprint %q != finding fingerprint %q", r.RuleID, got, want[r.RuleID])
		}
	}
}

// TestPassesAreCountedInTheInvocation. They are not results, but they are not
// lost either — the denominator has to be recoverable or posture means nothing.
func TestPassesAreCountedInTheInvocation(t *testing.T) {
	d, _ := render(t, sample())
	props := d.Runs[0].Invocations[0].Properties

	counts, ok := props["plumbline/counts"].(map[string]any)
	if !ok {
		t.Fatalf("no counts in the invocation: %v", props)
	}
	if counts["pass"] != float64(1) || counts["total"] != float64(7) {
		t.Errorf("counts = %v, want pass 1 of total 7", counts)
	}
	// Posture is never emitted without coverage beside it — the same invariant
	// the other two renderers enforce.
	_, hasPosture := props["plumbline/posture"]
	_, hasCoverage := props["plumbline/coverage"]
	if hasPosture != hasCoverage {
		t.Errorf("posture and coverage must appear together: posture=%v coverage=%v", hasPosture, hasCoverage)
	}
	if !hasPosture {
		t.Error("neither posture nor coverage was emitted for a run that evaluated checks")
	}
}

// TestADegradedRunSaysSo. SARIF has a field for exactly this, and claiming
// success would tell a consumer the scan saw the whole host when it did not.
func TestADegradedRunSaysSo(t *testing.T) {
	in := sample()
	in.Degraded = true
	d, _ := render(t, in)
	if d.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("a degraded run reported executionSuccessful: true")
	}

	clean, _ := render(t, sample())
	if !clean.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("a clean run reported executionSuccessful: false")
	}
}

// TestRulesCarryWhatGitHubRanksBy. Without security-severity every alert
// renders as "medium" in the UI whatever its real severity.
func TestRulesCarryWhatGitHubRanksBy(t *testing.T) {
	d, _ := render(t, sample())
	rules := d.Runs[0].Tool.Driver.Rules
	if len(rules) != 4 {
		t.Fatalf("rules = %d, want 4 (one per check that produced a result)", len(rules))
	}
	for _, r := range rules {
		sev, ok := r.Properties["security-severity"].(string)
		if !ok || sev == "" {
			t.Errorf("%s carries no security-severity", r.ID)
		}
		tags, ok := r.Properties["tags"].([]any)
		if !ok || len(tags) == 0 {
			t.Errorf("%s carries no tags", r.ID)
		}
		if r.ShortDescription == nil || r.ShortDescription.Text == "" {
			t.Errorf("%s has no shortDescription", r.ID)
		}
		if r.Help == nil || r.Help.Text == "" {
			t.Errorf("%s has no help text", r.ID)
		}
	}
}

// TestRuleIndexPointsAtTheRightRule. A wrong index is silent: the consumer
// shows one check's title over another's finding.
func TestRuleIndexPointsAtTheRightRule(t *testing.T) {
	d, _ := render(t, sample())
	rules := d.Runs[0].Tool.Driver.Rules
	for _, r := range d.Runs[0].Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) {
			t.Fatalf("%s has ruleIndex %d, out of range", r.RuleID, r.RuleIndex)
		}
		if rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("%s points at rule %q", r.RuleID, rules[r.RuleIndex].ID)
		}
	}
}

// TestLocationsNeverInventARegion. Plumbline knows which file is wrong, not
// which line, and a fabricated startLine is a claim about evidence that does
// not exist.
func TestLocationsNeverInventARegion(t *testing.T) {
	_, raw := render(t, sample())
	if bytes.Contains(raw, []byte(`"region"`)) || bytes.Contains(raw, []byte(`"startLine"`)) {
		t.Errorf("a region was invented:\n%s", raw)
	}

	d, _ := render(t, sample())
	r := d.Runs[0].Results[resultFor(t, d, "SSHD-0002")]
	if got := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "file:///etc/ssh/sshd_config" {
		t.Errorf("location = %q, want the subject path", got)
	}
	// A subject that is not a path still gets a location, because most
	// consumers will not surface a result without one.
	u := d.Runs[0].Results[resultFor(t, d, "FILESYS-0010")]
	if u.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Error("a host-wide finding has no location at all")
	}
}

// TestTheDocumentIdentifiesItself. A consumer branches on version and $schema
// before parsing anything else.
func TestTheDocumentIdentifiesItself(t *testing.T) {
	d, _ := render(t, sample())
	if d.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", d.Version)
	}
	if !strings.Contains(d.Schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema = %q", d.Schema)
	}
	if len(d.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(d.Runs))
	}
	dr := d.Runs[0].Tool.Driver
	if dr.Name != "plumbline" || dr.InformationURI == "" {
		t.Errorf("driver is not identified: %+v", dr)
	}
	if d.Runs[0].ColumnKind == "" {
		t.Error("columnKind is unset; consumers disagree about the default")
	}
	if d.Runs[0].Invocations[0].StartTimeUTC != "2026-08-20T09:00:00Z" {
		t.Errorf("startTimeUtc = %q", d.Runs[0].Invocations[0].StartTimeUTC)
	}
}

// TestRenderIsDeterministic. Two runs of an unchanged host must produce
// byte-identical SARIF, or a consumer diffing uploads sees churn.
func TestRenderIsDeterministic(t *testing.T) {
	_, first := render(t, sample())
	for i := 0; i < 20; i++ {
		if _, got := render(t, sample()); !bytes.Equal(got, first) {
			t.Fatalf("render %d differs from the first", i)
		}
	}
}

// TestHostileTextIsNeutralised. This document is rendered by somebody else's
// UI, and a control character from a filename on the audited host must not
// reach it.
func TestHostileTextIsNeutralised(t *testing.T) {
	in := sample()
	in.Findings = append(in.Findings, f("SSHD-0099", "/tmp/\x1b[31mred\x07", finding.Fail, finding.High))
	in.Score = score.Compute(in.Findings, 13)

	_, raw := render(t, in)
	for _, b := range []byte{0x1b, 0x07} {
		if bytes.IndexByte(raw, b) >= 0 {
			t.Errorf("a raw control byte %#x reached the document", b)
		}
	}
}

// TestAnEmptyRunStillRenders. A host with nothing to report is a real state and
// must produce a valid document rather than a null results array.
func TestAnEmptyRunStillRenders(t *testing.T) {
	d, raw := render(t, rendersarif.Input{
		Tool:  rendersarif.Tool{Name: "plumbline", Version: "0.5.0-dev"},
		Score: score.Compute(nil, 13),
	})
	if d.Runs[0].Results == nil {
		t.Error("results is null rather than an empty array")
	}
	if bytes.Contains(raw, []byte("null")) {
		t.Errorf("a null leaked into the document:\n%s", raw)
	}
}

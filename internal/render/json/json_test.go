package json_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/antaryx/plumbline/internal/catalog"
	checks "github.com/antaryx/plumbline/internal/catalog/checks/sshd"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	render "github.com/antaryx/plumbline/internal/render/json"
	"github.com/antaryx/plumbline/internal/score"
	"github.com/antaryx/plumbline/internal/suppress"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const (
	fixtureRoot = "../../../testdata/fixtures"
	schemaPath  = "../../../schema/findings-v1.schema.json"
)

var (
	started  = time.Date(2026, 3, 14, 9, 26, 51, 0, time.UTC)
	finished = time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
)

// compileSchema loads the published schema. Format assertions are switched on:
// a date-time field carrying something that is not a date-time is exactly the
// kind of drift this test exists to catch.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	s, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaPath, err)
	}
	return s
}

// validate asserts a rendered document satisfies findings-v1.
func validate(t *testing.T, sch *jsonschema.Schema, doc []byte) {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("rendered output is not JSON: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("rendered output violates findings-v1:\n%v\n\ndocument:\n%s", err, doc)
	}
}

// evaluateFixture runs the real collector and the real check over a fixture,
// which is what a scan does. Rendering synthetic findings would prove the
// renderer serialises structs, not that the pipeline emits a valid document.
func evaluateFixture(t *testing.T, name string) ([]finding.Finding, []fact.Error) {
	t.Helper()
	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect %s: %v", name, err)
	}
	return catalog.MustNew(checks.Check0002).Evaluate(facts), facts.Errors()
}

func inputFor(findings []finding.Finding, errs []fact.Error) render.Input {
	return render.Input{
		Tool: render.Tool{Name: "plumbline", Version: "0.1.0"},
		Scan: render.Scan{
			Started: started, Finished: finished, Root: "", EUID: 0, Profile: "default",
		},
		Score:      score.Compute(findings, catalog.Version),
		Findings:   findings,
		FactErrors: errs,
		Degraded:   len(errs) > 0,
	}
}

func render1(t *testing.T, in render.Input) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := render.Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.Bytes()
}

// fixtures is the whole corpus. Every one of them must render to a valid
// document, including the ones whose verdicts are UNKNOWN and NOT_APPLICABLE —
// those are the shapes a renderer is most likely to get wrong.
var fixtures = []string{
	"sshd-hardened", "sshd-permit-yes", "sshd-default", "sshd-include",
	"sshd-match-trap", "sshd-absent", "sshd-unreadable",
	"sshd-unresolved-include", "sshd-bad-value",
}

// TestEveryFixtureRendersValidly is the acceptance criterion. The schema is
// the public API (ADR-0007), so a document that violates it is a broken
// release, not a cosmetic problem.
func TestEveryFixtureRendersValidly(t *testing.T) {
	sch := compileSchema(t)
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			findings, errs := evaluateFixture(t, name)
			validate(t, sch, render1(t, inputFor(findings, errs)))
		})
	}
}

// TestSchemaCatchesInvariantViolations proves the validator is doing work.
// A test that only ever validates correct documents cannot distinguish a
// schema that enforces the finding invariants from one that enforces nothing,
// so each invariant is broken deliberately and asserted to fail.
func TestSchemaCatchesInvariantViolations(t *testing.T) {
	sch := compileSchema(t)

	base := map[string]any{
		"schema":          "findings/v1",
		"tool":            map[string]any{"name": "plumbline", "version": "0.1.0"},
		"catalog_version": 1,
		"scan": map[string]any{
			"started": "2026-03-14T09:26:51Z", "finished": "2026-03-14T09:26:53Z",
			"root": "", "euid": 0,
		},
		"summary": map[string]any{
			"counts":   map[string]any{"pass": 0, "fail": 0, "not_applicable": 0, "skipped": 0, "unknown": 0, "total": 1},
			"posture":  nil,
			"coverage": 0,
		},
		"findings": []any{},
	}

	newFinding := func(over map[string]any) map[string]any {
		f := map[string]any{
			"check_id": "SSHD-0002", "module": "SSHD", "title": "t",
			"result": "PASS", "severity": "HIGH", "base_severity": "HIGH",
			"detail": "d", "fingerprint": "0123456789abcdef0123456789abcdef",
		}
		for k, v := range over {
			if v == nil {
				delete(f, k)
				continue
			}
			f[k] = v
		}
		return f
	}

	cases := []struct {
		name string
		doc  func() map[string]any
	}{
		{"UNKNOWN without a reason", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{"result": "UNKNOWN"})}
			return d
		}},
		{"FAIL without remediation", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{
				"result":   "FAIL",
				"evidence": []any{map[string]any{"source": "/etc/ssh/sshd_config", "excerpt": "x"}},
			})}
			return d
		}},
		{"FAIL without evidence", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{
				"result":      "FAIL",
				"remediation": map[string]any{"summary": "s", "effort": "LOW"},
			})}
			return d
		}},
		{"PASS carrying remediation", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{
				"remediation": map[string]any{"summary": "s", "effort": "LOW"},
			})}
			return d
		}},
		{"a result outside the closed set", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{"result": "PROBABLY_FINE"})}
			return d
		}},
		{"a finding with no fingerprint", func() map[string]any {
			d := clone(base)
			d["findings"] = []any{newFinding(map[string]any{"fingerprint": nil})}
			return d
		}},
		{"an unknown top-level key", func() map[string]any {
			d := clone(base)
			d["risk_score"] = 42 // the score the audit removed
			return d
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.doc())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var v any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := sch.Validate(v); err == nil {
				t.Errorf("the schema accepted a document it must reject:\n%s", raw)
			}
		})
	}

	// And the base document, unbroken, must pass — otherwise the cases above
	// prove nothing about the invariants.
	raw, _ := json.Marshal(base)
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("the control document is itself invalid, so the negative cases prove nothing: %v", err)
	}
}

func clone(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestRenderingIsDeterministic is the acceptance criterion. Two scans of one
// unchanged host must diff to nothing, or every diff is noise and nobody reads
// them.
func TestRenderingIsDeterministic(t *testing.T) {
	findings, errs := evaluateFixture(t, "sshd-include")
	in := inputFor(findings, errs)

	first := render1(t, in)
	for i := 0; i < 25; i++ {
		if got := render1(t, in); !bytes.Equal(first, got) {
			t.Fatalf("render %d differs from the first:\n%s\n---\n%s", i, first, got)
		}
	}

	// Determinism must not depend on the caller's slice order either: a runner
	// that evaluated checks concurrently would hand them over in any order.
	shuffled := append([]finding.Finding(nil), findings...)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	in2 := inputFor(shuffled, errs)
	if got := render1(t, in2); !bytes.Equal(first, got) {
		t.Error("output depends on the order findings arrived in")
	}
}

// TestSchemaIsTheFirstKey: a consumer branches on schema before parsing
// anything else, which it can only do cheaply if the key comes first.
func TestSchemaIsTheFirstKey(t *testing.T) {
	findings, errs := evaluateFixture(t, "sshd-hardened")
	out := string(render1(t, inputFor(findings, errs)))
	if !strings.HasPrefix(out, "{\n  \"schema\": \"findings/v1\",") {
		t.Errorf("document does not open with the schema key:\n%.120s", out)
	}
}

// TestFindingsAreSortedByCheckID: the order is part of the contract, not an
// accident of evaluation.
func TestFindingsAreSortedByCheckID(t *testing.T) {
	in := inputFor([]finding.Finding{
		{CheckID: "SSHD-0009", Module: "SSHD", Title: "c", Result: finding.Pass, Severity: finding.Low, BaseSeverity: finding.Low, Detail: "d", Fingerprint: finding.Fingerprint("SSHD-0009", "")},
		{CheckID: "AUTH-0001", Module: "AUTH", Title: "a", Result: finding.Pass, Severity: finding.Low, BaseSeverity: finding.Low, Detail: "d", Fingerprint: finding.Fingerprint("AUTH-0001", "")},
		{CheckID: "SSHD-0002", Module: "SSHD", Title: "b", Result: finding.Pass, Severity: finding.Low, BaseSeverity: finding.Low, Detail: "d", Fingerprint: finding.Fingerprint("SSHD-0002", "")},
	}, nil)

	out := render1(t, in)
	validate(t, compileSchema(t), out)

	var doc struct {
		Findings []struct {
			CheckID string `json:"check_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{"AUTH-0001", "SSHD-0002", "SSHD-0009"}
	for i, id := range want {
		if doc.Findings[i].CheckID != id {
			t.Errorf("finding %d is %s, want %s", i, doc.Findings[i].CheckID, id)
		}
	}
}

// TestUndefinedPostureRendersAsNull is what ADR-0010 bought. An all-UNKNOWN
// run has no posture; the document must say so rather than saying zero, which
// would report a host in perfect failure when nobody looked at it.
func TestUndefinedPostureRendersAsNull(t *testing.T) {
	findings, errs := evaluateFixture(t, "sshd-unreadable") // the only finding is UNKNOWN
	out := render1(t, inputFor(findings, errs))

	validate(t, compileSchema(t), out)

	if !bytes.Contains(out, []byte(`"posture": null`)) {
		t.Errorf("undefined posture was not rendered as null:\n%s", out)
	}
	if bytes.Contains(out, []byte(`"posture": 0`)) {
		t.Error("undefined posture was rendered as zero")
	}
	// Coverage is defined and zero here, which is a different statement: there
	// was an applicable check and it was not evaluated.
	if !bytes.Contains(out, []byte(`"coverage": 0`)) {
		t.Errorf("coverage should be 0 for a run that evaluated nothing:\n%s", out)
	}
}

// TestPostureIsNeverEmittedWithoutCoverage is the acceptance criterion, and
// the invariant holds structurally: Render takes a score.Score, which computes
// both figures together, so there is no way to supply one without the other.
// A caller cannot express the forbidden state, and if a future change made it
// expressible the renderer refuses it.
func TestPostureIsNeverEmittedWithoutCoverage(t *testing.T) {
	// Coverage is undefined only when nothing applies to the host. Posture is
	// then necessarily undefined too, so the forbidden combination cannot be
	// constructed -- this asserts that property rather than assuming it.
	for _, in := range [][]finding.Finding{
		nil,
		{{CheckID: "SSHD-0002", Result: finding.NotApplicable, Severity: finding.High}},
		{{Result: finding.NotApplicable}, {Result: finding.NotApplicable}},
	} {
		s := score.Compute(in, 1)
		_, coverageOK := s.Coverage()
		_, postureOK := s.Posture()
		if postureOK && !coverageOK {
			t.Fatal("score produced a posture with no coverage; the renderer's guarantee rests on this being impossible")
		}
		if coverageOK {
			continue
		}

		// Undefined coverage is written as null, never as 0: 0% of an empty
		// set is a division by zero (ADR-0010). The document is still valid,
		// because a scan of a host that legitimately has nothing to check is a
		// successful scan.
		var buf bytes.Buffer
		if err := render.Render(&buf, render.Input{
			Tool:  render.Tool{Name: "plumbline", Version: "0.1.0"},
			Score: s, Findings: in,
		}); err != nil {
			t.Fatalf("Render: %v", err)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`"coverage": null`)) {
			t.Errorf("undefined coverage was not rendered as null:\n%s", buf.Bytes())
		}
		if bytes.Contains(buf.Bytes(), []byte(`"coverage": 0`)) {
			t.Error("undefined coverage was rendered as zero")
		}
	}
}

// TestFactErrorsAreCarried: a document that drops the reasons for its own gaps
// cannot explain them months later, which is the difference between evidence
// and a screenshot.
func TestFactErrorsAreCarried(t *testing.T) {
	findings, errs := evaluateFixture(t, "sshd-unreadable")
	if len(errs) == 0 {
		t.Fatal("the unreadable fixture produced no fact error")
	}
	out := render1(t, inputFor(findings, errs))
	validate(t, compileSchema(t), out)

	if !bytes.Contains(out, []byte(`"kind": "permission"`)) {
		t.Errorf("the fact error's kind is missing from the document:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`"degraded": true`)) {
		t.Error("a run with a failed collector is not marked degraded")
	}
}

// TestSchemaFileIsTheOneCIValidates guards against the test drifting onto a
// copy of the schema. There is one public API and this is the file.
func TestSchemaFileIsTheOneCIValidates(t *testing.T) {
	if _, err := os.Stat(schemaPath); err != nil {
		t.Fatalf("the published schema is not where this test reads it: %v", err)
	}
}

// TestASuppressedFindingValidatesAgainstTheSchema is the gate on WP-29's one
// schema change. `suppression` was added to findings-v1 as an optional field,
// which VERSIONING.md §4.1 permits within a major — but the schema declares
// additionalProperties:false throughout, so a field added to the Go struct and
// not to the schema is a document that fails validation in CI. This test is
// what makes the two move together.
func TestASuppressedFindingValidatesAgainstTheSchema(t *testing.T) {
	sch := compileSchema(t)
	findings, errs := evaluateFixture(t, "sshd-permit-yes")

	set, err := suppress.Parse([]byte(fmt.Sprintf(
		`{"schema":%q,"suppressions":[{"fingerprint":%q,"justification":"accepted for the bastion; SEC-4471","expires_at":"2027-01-31T00:00:00Z"}]}`,
		suppress.Schema, findings[0].Fingerprint)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	out := set.Apply(findings, started)
	if out.Suppressed() != 1 {
		t.Fatalf("the fixture's first finding was not suppressed, so this test proves nothing: %+v", out)
	}

	doc := render1(t, inputFor(out.Findings, errs))
	validate(t, sch, doc)

	// And the field is actually in the document rather than merely permitted
	// by it. A `suppression` that omitempty'd itself away would validate.
	for _, want := range []string{`"suppression"`, `"justification"`, `"original_result"`, `"SKIPPED"`} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("the rendered document omits %s:\n%s", want, doc)
		}
	}
}

// TestAnUnsuppressedDocumentCarriesNoSuppressionKey. The field is optional, and
// optional means absent — not present and empty. Every consumer written before
// this field existed must see a byte-identical document for an unsuppressed
// scan.
func TestAnUnsuppressedDocumentCarriesNoSuppressionKey(t *testing.T) {
	findings, errs := evaluateFixture(t, "sshd-permit-yes")
	if doc := render1(t, inputFor(findings, errs)); bytes.Contains(doc, []byte(`"suppression"`)) {
		t.Errorf("an unsuppressed scan emitted a suppression key:\n%s", doc)
	}
}

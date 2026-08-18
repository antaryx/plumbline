// Package json renders findings as a findings/v1 document.
//
// This is the public API (ADR-0007). Go consumers do not import Plumbline;
// they read this JSON, so its shape is a contract validated against
// schema/findings-v1.schema.json in CI rather than a serialisation detail.
//
// Two properties are load-bearing.
//
// The output is deterministic: the same findings and the same catalog produce
// byte-identical documents. Findings are sorted by check ID and every object
// is a struct rather than a map, so key order is fixed by declaration rather
// than by Go's map iteration. A diff between two scans has to show what
// changed on the host, not what changed in a hash seed.
//
// Posture is never emitted without coverage. That is not a convention here, it
// is the shape of the input: the renderer takes a score.Score, which computes
// both figures together and can express "undefined" for each, so there is no
// way to hand it one without the other. A posture with no coverage beside it
// is a number with no scale — 100 over two checks out of two hundred is not a
// clean host, it is an unexamined one.
package json

import (
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// Schema is the document schema this renderer emits.
const Schema = "findings/v1"

// ErrPostureWithoutCoverage reports the invariant this renderer exists to
// guarantee: a posture is never written without the coverage that gives it
// scale.
//
// It should be unreachable. score.Score computes both figures together and
// cannot produce a defined posture with an undefined coverage, so a caller
// cannot express the forbidden state. It is checked anyway, because an
// invariant that holds only by construction stops holding the first time the
// construction changes, and this one is a rendering rule the architecture
// states outright (ARCHITECTURE.md §5).
var ErrPostureWithoutCoverage = errors.New("render/json: refusing to emit posture without coverage")

// Tool identifies the binary that produced the document.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Built   string `json:"built,omitempty"`
}

// Host describes the machine. Absent or partial under --redact.
type Host struct {
	Hostname  string `json:"hostname,omitempty"`
	OSID      string `json:"os_id,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

// Scan records the conditions the findings were produced under. Without euid
// and root, a reader cannot tell why coverage is what it is.
type Scan struct {
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished"`
	Root         string    `json:"root"`
	EUID         int       `json:"euid"`
	Profile      string    `json:"profile,omitempty"`
	BundleSHA256 string    `json:"bundle_sha256,omitempty"`
	Host         *Host     `json:"host,omitempty"`
}

// Input is everything a document is made of.
//
// Score is passed whole rather than as two numbers on purpose: it is what
// makes "posture is never emitted without coverage" a property of the type
// instead of a rule someone has to remember.
type Input struct {
	Tool       Tool
	Scan       Scan
	Score      score.Score
	Findings   []finding.Finding
	FactErrors []fact.Error
	// Degraded reports that one or more collectors failed, which is what makes
	// coverage less than complete. It corresponds to exit code 4.
	Degraded bool
}

// document is the wire shape. Field order is output order, and "schema" is
// first so a consumer can branch on it before parsing anything else.
type document struct {
	Schema         string            `json:"schema"`
	Tool           Tool              `json:"tool"`
	CatalogVersion int               `json:"catalog_version"`
	Scan           Scan              `json:"scan"`
	Summary        summary           `json:"summary"`
	Findings       []finding.Finding `json:"findings"`
	FactErrors     []fact.Error      `json:"fact_errors,omitempty"`
}

type summary struct {
	Counts     counts         `json:"counts"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	// Posture and Coverage are nil when undefined, which is not zero
	// (ADR-0010). A consumer that coerces null to 0 reports a host in perfect
	// failure when in fact nobody looked at it.
	Posture  *float64 `json:"posture"`
	Coverage *float64 `json:"coverage"`
	Degraded bool     `json:"degraded,omitempty"`
}

type counts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
	Skipped       int `json:"skipped"`
	Unknown       int `json:"unknown"`
	Total         int `json:"total"`
}

// Render writes a findings/v1 document to w.
func Render(w io.Writer, in Input) error {
	doc, err := build(in)
	if err != nil {
		return err
	}
	if err := doc.check(); err != nil {
		return err
	}

	enc := stdjson.NewEncoder(w)
	// Paths and directive values are already neutralised by the time they
	// reach here (THREAT-MODEL.md T-03); escaping them again as HTML entities
	// would only make evidence harder to read.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("render/json: %w", err)
	}
	return nil
}

// build assembles the document and enforces the rendering invariants before
// anything is written. A document is refused whole rather than emitted with a
// field that lies.
func build(in Input) (document, error) {
	posture, postureOK := in.Score.Posture()
	coverage, coverageOK := in.Score.Coverage()

	doc := document{
		Schema:         Schema,
		Tool:           in.Tool,
		CatalogVersion: in.Score.CatalogVersion(),
		Scan:           in.Scan,
		Summary: summary{
			Counts:     countsOf(in.Score.Counts()),
			BySeverity: failuresBySeverity(in.Findings),
			Degraded:   in.Degraded,
		},
		Findings:   sortedByCheckID(in.Findings),
		FactErrors: sortedErrors(in.FactErrors),
	}
	if postureOK {
		doc.Summary.Posture = &posture
	}
	if coverageOK {
		doc.Summary.Coverage = &coverage
	}

	if doc.Tool.Name == "" {
		doc.Tool.Name = "plumbline"
	}
	return doc, nil
}

// check enforces the rendering invariants on the assembled document, before a
// byte is written. A document is refused whole rather than emitted with a
// field that lies.
func (d document) check() error {
	if d.Summary.Posture != nil && d.Summary.Coverage == nil {
		return ErrPostureWithoutCoverage
	}
	return nil
}

func countsOf(c score.Counts) counts {
	return counts{
		Pass:          c.Pass,
		Fail:          c.Fail,
		NotApplicable: c.NotApplicable,
		Skipped:       c.Skipped,
		Unknown:       c.Unknown,
		Total:         c.Total,
	}
}

// failuresBySeverity counts FAIL findings by effective severity. A map is
// deterministic here because encoding/json sorts map keys, and the set of keys
// is closed.
func failuresBySeverity(in []finding.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range in {
		if f.Result == finding.Fail {
			out[string(f.Severity)]++
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sortedByCheckID returns the findings in check-ID order without disturbing
// the caller's slice. Two scans of one host must diff to nothing, which
// requires an order that does not depend on evaluation timing.
func sortedByCheckID(in []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CheckID != out[j].CheckID {
			return out[i].CheckID < out[j].CheckID
		}
		// One check can report on several subjects; the subject orders them.
		return out[i].Subject < out[j].Subject
	})
	if len(out) == 0 {
		// findings is required and must be [] rather than null: a consumer
		// iterating the array should not have to special-case a clean scan.
		return []finding.Finding{}
	}
	return out
}

func sortedErrors(in []fact.Error) []fact.Error {
	if len(in) == 0 {
		return nil
	}
	out := make([]fact.Error, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Fact < out[j].Fact })
	return out
}

// Package sarif renders findings as SARIF 2.1.0 for GitHub Advanced Security
// and anything else that ingests SARIF.
//
// The mapping is specified in docs/adr/0018-sarif-mapping.md and that document,
// not this comment, is the contract. What follows is why the code looks the way
// it does.
//
// **SARIF is a source-analysis format and this is a host auditor.** The two
// models disagree in three places, and each has an easy wrong answer:
// UNKNOWN has no SARIF level, a SARIF result is something to act on rather
// than a record of everything examined, and a SARIF location is a file region
// where many findings here are about a sysctl or an account. The three
// decisions below are the resolution.
//
// **UNKNOWN is a warning, never `none`.** `none` files it as informational,
// which makes the host look cleaner than the scan found it; `error` claims a
// failure nobody observed. `warning` is right because the *consequence* is the
// same as a finding's: somebody has to look. The properties bag carries the
// literal result and reason so a consumer that models Plumbline can still tell
// the two apart.
//
// **A suppressed finding uses SARIF's own `suppressions` array.** SARIF models
// suppression natively, with a justification field, and it is the one place the
// two models line up exactly: an accepted risk shows in GitHub as dismissed
// with a reason rather than as absent.
//
// **PASS and NOT_APPLICABLE are not results.** They are counted in the
// invocation's properties. Emitting 74 passing checks per run buries the three
// that matter, and a security tab that is mostly noise is one nobody opens.
//
// No SARIF library is imported. The binary runs as root and every import is
// supply-chain surface (CLAUDE.md rule 7); the subset needed here is structs
// and encoding/json.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/sanitize"
	"github.com/antaryx/plumbline/internal/score"
)

// Version and SchemaURI identify the dialect emitted. Both are literals rather
// than derived: a consumer branches on them before parsing anything else.
const (
	Version   = "2.1.0"
	SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

	// FingerprintKey is the partialFingerprints key. It is versioned so a
	// future change of derivation can be introduced alongside the old one
	// rather than silently redefining it — see ADR-0018, which explains why
	// that matters more here than anywhere else in the codebase.
	FingerprintKey = "plumblineFingerprint/v1"

	// InformationURI is the tool's home, which GitHub links from every alert.
	InformationURI = "https://github.com/antaryx/plumbline"
)

// Tool identifies the binary that produced the run.
type Tool struct {
	Name    string
	Version string
	Commit  string
}

// Scan records the conditions the findings were produced under.
type Scan struct {
	Started  time.Time
	Finished time.Time
	Root     string
	EUID     int
	Profile  string
	Hostname string
}

// Input is everything a SARIF run is made of.
//
// Score is passed whole for the reason the other two renderers take it whole:
// it makes "posture is never emitted without coverage" a property of the type
// rather than a rule someone has to remember.
type Input struct {
	Tool     Tool
	Scan     Scan
	Score    score.Score
	Findings []finding.Finding
	// Degraded reports that a collector failed. It becomes
	// invocation.executionSuccessful, which is the field SARIF has for exactly
	// this and which consumers surface as "the run did not complete cleanly".
	Degraded bool
}

// ---------------------------------------------------------------------------
// the wire shape
// ---------------------------------------------------------------------------

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool              toolSection       `json:"tool"`
	AutomationDetails *automationDetail `json:"automationDetails,omitempty"`
	Invocations       []invocation      `json:"invocations"`
	Results           []result          `json:"results"`
	ColumnKind        string            `json:"columnKind"`
}

type toolSection struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	SemanticVersion string       `json:"semanticVersion,omitempty"`
	InformationURI  string       `json:"informationUri"`
	Rules           []ruleDesc   `json:"rules"`
	Properties      *propertyBag `json:"properties,omitempty"`
}

type ruleDesc struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name,omitempty"`
	ShortDescription     *text        `json:"shortDescription,omitempty"`
	FullDescription      *text        `json:"fullDescription,omitempty"`
	Help                 *text        `json:"help,omitempty"`
	HelpURI              string       `json:"helpUri,omitempty"`
	DefaultConfiguration *ruleConfig  `json:"defaultConfiguration,omitempty"`
	Properties           *propertyBag `json:"properties,omitempty"`
}

type ruleConfig struct {
	Level string `json:"level"`
}

type text struct {
	Text string `json:"text"`
}

type automationDetail struct {
	ID string `json:"id"`
}

type invocation struct {
	ExecutionSuccessful bool         `json:"executionSuccessful"`
	StartTimeUTC        string       `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string       `json:"endTimeUtc,omitempty"`
	WorkingDirectory    *artifactLoc `json:"workingDirectory,omitempty"`
	Properties          *propertyBag `json:"properties,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
	Properties          *propertyBag      `json:"properties,omitempty"`
}

type location struct {
	PhysicalLocation physicalLoc `json:"physicalLocation"`
}

type physicalLoc struct {
	ArtifactLocation artifactLoc `json:"artifactLocation"`
}

type artifactLoc struct {
	URI string `json:"uri"`
}

type suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// propertyBag is an ordered map. SARIF property bags are free-form objects, and
// a Go map would marshal in a different order on... no: encoding/json sorts map
// keys, so a map is deterministic. It is a struct anyway, because the keys here
// are a documented interface and a struct is where that gets written down.
type propertyBag struct {
	Result         string   `json:"plumbline/result,omitempty"`
	OriginalResult string   `json:"plumbline/original_result,omitempty"`
	UnknownReason  string   `json:"plumbline/unknown_reason,omitempty"`
	Subject        string   `json:"plumbline/subject,omitempty"`
	Module         string   `json:"plumbline/module,omitempty"`
	SecuritySev    string   `json:"security-severity,omitempty"`
	Tags           []string `json:"tags,omitempty"`

	Counts         *counts  `json:"plumbline/counts,omitempty"`
	Posture        *float64 `json:"plumbline/posture,omitempty"`
	Coverage       *float64 `json:"plumbline/coverage,omitempty"`
	CatalogVersion int      `json:"plumbline/catalog_version,omitempty"`
	EUID           *int     `json:"plumbline/euid,omitempty"`
	Profile        string   `json:"plumbline/profile,omitempty"`
	Hostname       string   `json:"plumbline/hostname,omitempty"`
}

type counts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"not_applicable"`
	Skipped       int `json:"skipped"`
	Total         int `json:"total"`
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

// Render writes a SARIF 2.1.0 document.
//
// Deterministic for a given Input: findings are sorted rather than ranged over
// from a map, so two runs of an unchanged host produce byte-identical SARIF and
// a consumer diffing them sees nothing.
func Render(w io.Writer, in Input) error {
	emitted := emittable(in.Findings)

	rules, index := rulesFor(emitted)
	results := make([]result, 0, len(emitted))
	for _, f := range emitted {
		results = append(results, resultFor(f, index[f.CheckID], in.Scan))
	}

	doc := document{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []run{{
			Tool: toolSection{Driver: driver{
				Name:            in.Tool.Name,
				Version:         in.Tool.Version,
				SemanticVersion: semanticVersion(in.Tool.Version),
				InformationURI:  InformationURI,
				Rules:           rules,
			}},
			AutomationDetails: &automationDetail{ID: automationID(in.Scan)},
			Invocations:       []invocation{invocationFor(in)},
			Results:           results,
			// SARIF requires a columnKind when regions carry columns. None do
			// here, but consumers validate the field's presence and the spec's
			// default differs between implementations, so it is stated.
			ColumnKind: "utf16CodeUnits",
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// emittable selects the findings that become SARIF results, sorted.
//
// PASS and NOT_APPLICABLE never appear; nor does a SKIPPED that carries no
// suppression, because a check the profile did not run is not a finding about
// this host — there is nothing to dismiss and nothing to fix. A SKIPPED that
// *does* carry one is emitted, suppressed, because an accepted risk is a
// finding whose standing changed rather than one that went away.
func emittable(in []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range in {
		switch f.Result {
		case finding.Fail, finding.Unknown:
			out = append(out, f)
		case finding.Skipped:
			if f.Suppression != nil {
				out = append(out, f)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CheckID != out[j].CheckID {
			return out[i].CheckID < out[j].CheckID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// underlying is the verdict the check reached, seeing through a suppression.
func underlying(f finding.Finding) finding.Result {
	if f.Suppression != nil {
		return f.Suppression.OriginalResult
	}
	return f.Result
}

// levelFor maps a finding to a SARIF level.
//
// A suppressed finding keeps the level its original verdict would have had: it
// is still a finding, and only its standing has changed. Losing that would
// make every dismissal look trivial.
func levelFor(f finding.Finding) string {
	switch underlying(f) {
	case finding.Unknown:
		// Never "none". See ADR-0018: `none` files an unknown as
		// informational, which reports a cleaner host than the scan saw.
		return "warning"
	case finding.Fail:
		switch f.Severity {
		case finding.Critical, finding.High:
			return "error"
		default:
			return "warning"
		}
	default:
		return "note"
	}
}

// securitySeverity is the numeric string GitHub ranks alerts by. Without it
// every alert renders as "medium" whatever its severity, which is why it is
// emitted on every rule rather than only on the interesting ones.
//
// The bands are GitHub's documented CVSS-style ranges, not invented ones:
// 9.0+ critical, 7.0+ high, 4.0+ medium, 0.1+ low.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "9.5"
	case finding.High:
		return "8.0"
	case finding.Medium:
		return "5.5"
	case finding.Low:
		return "3.0"
	default:
		return "0.5"
	}
}

// rulesFor builds one reportingDescriptor per check that produced a result,
// and the index each result points at.
func rulesFor(in []finding.Finding) ([]ruleDesc, map[string]int) {
	index := map[string]int{}
	// Non-nil even when empty: SARIF specifies rules as an array, and
	// `"rules": null` is not one. A host with nothing to report is a real
	// state and must still produce a document a consumer will accept.
	rules := []ruleDesc{}
	for _, f := range in {
		if _, seen := index[f.CheckID]; seen {
			continue
		}
		index[f.CheckID] = len(rules)

		r := ruleDesc{
			ID:               f.CheckID,
			Name:             f.CheckID,
			ShortDescription: &text{Text: clean(f.Title)},
			DefaultConfiguration: &ruleConfig{
				Level: levelFor(finding.Finding{Result: finding.Fail, Severity: f.BaseSeverity}),
			},
			Properties: &propertyBag{
				Module:      f.Module,
				SecuritySev: securitySeverity(f.BaseSeverity),
				Tags:        []string{"security", "plumbline", strings.ToLower(f.Module)},
			},
		}
		if d := clean(f.Detail); d != "" {
			r.FullDescription = &text{Text: d}
		}
		if f.Remediation != nil {
			if h := clean(f.Remediation.Summary); h != "" {
				r.Help = &text{Text: h}
			}
		}
		rules = append(rules, r)
	}
	return rules, index
}

// resultFor renders one finding.
func resultFor(f finding.Finding, ruleIndex int, s Scan) result {
	props := &propertyBag{
		Result:        string(f.Result),
		UnknownReason: string(f.UnknownReason),
		Subject:       clean(f.Subject),
		Module:        f.Module,
	}

	out := result{
		RuleID:              f.CheckID,
		RuleIndex:           ruleIndex,
		Level:               levelFor(f),
		Message:             text{Text: messageFor(f)},
		Locations:           []location{locationFor(f, s)},
		PartialFingerprints: map[string]string{FingerprintKey: f.Fingerprint},
		Properties:          props,
	}

	if f.Suppression != nil {
		props.OriginalResult = string(f.Suppression.OriginalResult)
		out.Suppressions = []suppression{{
			// "external": the decision lives in a suppression file outside the
			// tool, which is exactly what SARIF's external kind describes.
			Kind:          "external",
			Justification: clean(f.Suppression.Justification),
		}}
	}
	return out
}

// messageFor is what a consumer shows as the alert text.
//
// An UNKNOWN opens by saying so. A consumer that ignores the properties bag —
// which is most of them — must still not read this as a failure, and the first
// four words are the only part of a SARIF message guaranteed to be displayed.
func messageFor(f finding.Finding) string {
	detail := clean(f.Detail)
	if detail == "" {
		detail = clean(f.Title)
	}
	if underlying(f) == finding.Unknown {
		reason := string(f.UnknownReason)
		if reason == "" {
			reason = "no reason recorded"
		}
		return fmt.Sprintf("Could not determine (%s): %s", reason, detail)
	}
	return detail
}

// locationFor points at the subject when it is a path, and at the scan root
// otherwise.
//
// No region is ever emitted. Plumbline knows which file is wrong, not which
// line of it, and a fabricated "startLine": 1 is a claim about evidence that
// does not exist — the same class of lie as reporting PASS for something that
// was never read.
func locationFor(f finding.Finding, s Scan) location {
	uri := "file:///"
	if root := strings.TrimSpace(s.Root); root != "" && root != "/" {
		uri = "file://" + ensureLeadingSlash(root)
	}
	if subject := clean(f.Subject); strings.HasPrefix(subject, "/") {
		// A subject naming several paths at once is one finding about a set;
		// the first is the one to point at, and all of them stay in the
		// properties bag.
		if first, _, found := strings.Cut(subject, ","); found {
			subject = strings.TrimSpace(first)
		}
		uri = "file://" + subject
	}
	return location{PhysicalLocation: physicalLoc{ArtifactLocation: artifactLoc{URI: uri}}}
}

func ensureLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

// invocationFor carries everything that is true of the run rather than of one
// finding — including the passing checks, which are not results.
func invocationFor(in Input) invocation {
	c := in.Score.Counts()
	props := &propertyBag{
		Counts: &counts{
			Pass: c.Pass, Fail: c.Fail, Unknown: c.Unknown,
			NotApplicable: c.NotApplicable, Skipped: c.Skipped, Total: c.Total,
		},
		CatalogVersion: in.Score.CatalogVersion(),
		Profile:        in.Scan.Profile,
		Hostname:       in.Scan.Hostname,
	}
	euid := in.Scan.EUID
	props.EUID = &euid

	// Posture and coverage travel together or not at all, which is the same
	// invariant the JSON and terminal renderers enforce: a posture with no
	// scale beside it flatters an unexamined host.
	if posture, okP := in.Score.Posture(); okP {
		if coverage, okC := in.Score.Coverage(); okC {
			props.Posture = &posture
			props.Coverage = &coverage
		}
	}

	inv := invocation{
		// A degraded run is one where a collector failed, and SARIF has a
		// field for precisely that. Reporting true would tell a consumer the
		// scan saw the whole host when it did not.
		ExecutionSuccessful: !in.Degraded,
		Properties:          props,
	}
	if !in.Scan.Started.IsZero() {
		inv.StartTimeUTC = in.Scan.Started.UTC().Format(time.RFC3339)
	}
	if !in.Scan.Finished.IsZero() {
		inv.EndTimeUTC = in.Scan.Finished.UTC().Format(time.RFC3339)
	}
	if root := strings.TrimSpace(in.Scan.Root); root != "" {
		inv.WorkingDirectory = &artifactLoc{URI: "file://" + ensureLeadingSlash(root)}
	}
	return inv
}

// automationID groups runs of the same thing across commits, which is what
// lets a consumer tell "the same scan, later" from "a different scan".
func automationID(s Scan) string {
	profile := s.Profile
	if profile == "" {
		profile = "default"
	}
	return "plumbline/" + profile
}

// semanticVersion emits the version only when it is one. SARIF's
// semanticVersion field is specified as semver, and a development or
// release-candidate version such as "1.0.0-rc1" qualifies while "none" or ""
// does not.
func semanticVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || v == "dev" || v == "unknown" {
		return ""
	}
	if _, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0]); err != nil {
		return ""
	}
	return v
}

// clean neutralises control characters in text that came from the host.
//
// Sanitisation happens once, where untrusted text becomes a finding
// (THREAT-MODEL.md T-03). It is called again here for the same reason the
// terminal renderer calls it: this text is about to be embedded in a document
// somebody else's UI will render, and the cost of being wrong is theirs.
func clean(s string) string {
	return strings.TrimSpace(sanitize.Text(s))
}

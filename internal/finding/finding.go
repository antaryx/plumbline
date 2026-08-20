// Package finding defines the output contract. These types serialise directly
// into findings-v1.schema.json, which is Plumbline's public API — see
// docs/DATA-MODEL.md and 05-VERSIONING.md §4. Changing a field here is a
// schema change, not a refactor.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/antaryx/plumbline/internal/sanitize"
)

// Result is the outcome of evaluating a check. The set is closed: adding a
// sixth state is a breaking schema change.
type Result string

const (
	// Pass: the condition was tested and met.
	Pass Result = "PASS"
	// Fail: the condition was tested and not met.
	Fail Result = "FAIL"
	// NotApplicable: the subject does not exist here (no sshd installed).
	// Leaves both numerator and denominator; does not affect coverage.
	NotApplicable Result = "NOT_APPLICABLE"
	// Skipped: deliberately not run (profile, filter, privilege policy).
	// Reduces coverage.
	Skipped Result = "SKIPPED"
	// Unknown: could not be determined. Reduces coverage and is surfaced
	// prominently. A check that cannot tell must never return Pass.
	Unknown Result = "UNKNOWN"
)

// Scores reports whether this result participates in the posture calculation.
func (r Result) Scores() bool { return r == Pass || r == Fail }

// Severity is the impact class of a failing check.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Weight is the scoring weight for a severity. Weights change only in a MAJOR
// release (05-VERSIONING.md §6).
func (s Severity) Weight() float64 {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// UnknownReason is a machine-readable explanation for an Unknown result.
type UnknownReason string

const (
	ReasonFactMissing    UnknownReason = "fact_not_collected"
	ReasonPermission     UnknownReason = "insufficient_privileges"
	ReasonParse          UnknownReason = "unparseable_source"
	ReasonTruncated      UnknownReason = "source_truncated"
	ReasonFactVersion    UnknownReason = "fact_version_mismatch"
	ReasonAmbiguousState UnknownReason = "ambiguous_system_state"
	ReasonInternal       UnknownReason = "internal_error"
)

// Evidence is the material a verdict was derived from. A finding without
// evidence is a rumour; the renderer shows it and the auditor keeps it.
type Evidence struct {
	Source  string `json:"source"`           // "/etc/ssh/sshd_config" or "exec: sshd -T"
	Line    int    `json:"line,omitempty"`   // 1-based, 0 when not line-oriented
	Excerpt string `json:"excerpt"`          // sanitised, length-capped
	SHA256  string `json:"sha256,omitempty"` // over the full source, for the bundle
}

// NewEvidence builds a piece of evidence with every untrusted string already
// neutralised.
//
// THREAT-MODEL.md T-03 puts sanitisation here, in the constructor, rather than
// in each renderer: a control every output format has to remember is a control
// the next output format forgets. The catalog runner sanitises again on the
// way out, so a check that builds an Evidence literal is safe too — but a
// check author copying the reference implementation should copy this.
//
// sha256 is the digest of the full source in the bundle's evidence store, or
// empty when the evidence is not backed by a stored blob.
func NewEvidence(source string, line int, excerpt, sha256 string) Evidence {
	return Evidence{
		Source:  sanitize.Text(source),
		Line:    line,
		Excerpt: sanitize.Excerpt(excerpt),
		SHA256:  sha256,
	}
}

// Remediation is how to fix a failing check. Steps are for humans, Commands
// are for review-then-run. Plumbline never executes either.
type Remediation struct {
	Summary  string   `json:"summary"`
	Effort   string   `json:"effort"` // LOW | MEDIUM | HIGH
	Steps    []string `json:"steps,omitempty"`
	Commands []string `json:"commands,omitempty"`
	// Caution warns about anything that can lock an operator out. Present on
	// every check that touches remote access.
	Caution string `json:"caution,omitempty"`
}

// ControlRef maps a finding to an external control identifier. Only
// public-domain frameworks are shipped; see COMPLIANCE-DATA-POLICY.md.
type ControlRef struct {
	Framework string `json:"framework"` // "nist-800-53-r5", "disa-stig-rhel9"
	Control   string `json:"control"`   // bare identifier, never control text
}

// Reference is external reading, not a control mapping.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Finding is one evaluated check. This struct is the schema.
type Finding struct {
	CheckID string `json:"check_id"`
	Module  string `json:"module"`
	Title   string `json:"title"`

	Result        Result        `json:"result"`
	UnknownReason UnknownReason `json:"unknown_reason,omitempty"`

	// Severity is effective (after context adjustment); BaseSeverity is the
	// catalog default. Both are reported so adjustment is never hidden.
	Severity     Severity `json:"severity"`
	BaseSeverity Severity `json:"base_severity"`

	// Detail states what was actually observed, with real values substituted.
	Detail string `json:"detail"`

	Evidence    []Evidence   `json:"evidence,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
	Mappings    []ControlRef `json:"mappings,omitempty"`
	References  []Reference  `json:"references,omitempty"`

	// Fingerprint identifies this finding across runs so that suppressions and
	// SARIF baselines remain stable. Changing how it is computed is a
	// breaking schema change (05-VERSIONING.md §4.4).
	Fingerprint string `json:"fingerprint"`

	// Subject is the specific thing this finding is about (a path, an account,
	// a port). Empty when the check is about the host as a whole.
	Subject string `json:"subject,omitempty"`

	// SkippedBy names the profile that put this check out of scope. Set only
	// when Result is SKIPPED and there is no suppression.
	//
	// It exists because the three ways a check can end up SKIPPED are
	// different facts and a consumer has to be able to tell them apart: an
	// accepted risk carries a Suppression, a check outside the declared
	// baseline carries this, and anything else is the runner's own doing. A
	// profile skip also leaves the posture denominator, which nothing could
	// compute without a marker to key on.
	//
	// Added in findings/v1 as an optional field, which VERSIONING.md §4.1
	// permits within a schema major.
	SkippedBy string `json:"skipped_by,omitempty"`

	// Suppression is present when an operator accepted this finding and the
	// acceptance was still live at scan time. Result is SKIPPED whenever it is
	// set, and OriginalResult inside it says what the verdict would otherwise
	// have been.
	//
	// Added in findings/v1 as an optional field, which VERSIONING.md §4.1
	// permits within a schema major. Consumers written before it existed
	// ignore it and see a SKIPPED finding, which is true.
	Suppression *Suppression `json:"suppression,omitempty"`
}

// Suppression records an accepted risk on a finding.
//
// **OriginalResult is the field that makes this honest.** A suppressed finding
// keeps its row, its severity, its detail and its evidence, and states what it
// would have been. Without that field a suppression is indistinguishable from
// a check that never ran, and "we accepted this" and "we never looked" would
// render identically — which is the failure this whole feature exists to
// avoid.
type Suppression struct {
	// Justification is the operator's reason, copied from the suppression
	// file. Never empty: the parser rejects a blank one.
	Justification string `json:"justification"`

	// ExpiresAt is the RFC 3339 expiry, when the rule carried one. A
	// suppression that appears here has not lapsed as of the scan.
	ExpiresAt string `json:"expires_at,omitempty"`

	// OriginalResult is the result the check actually reached. Always FAIL or
	// UNKNOWN — a PASS is never suppressed.
	OriginalResult Result `json:"original_result"`
}

// Fingerprint computes the stable identity of a finding about subject.
// Deliberately excludes result, severity and detail: a finding that flips from
// FAIL to PASS is the same finding, and a suppression written last quarter
// must still match.
func Fingerprint(checkID, subject string) string {
	h := sha256.Sum256([]byte(checkID + "\x00" + strings.TrimSpace(subject)))
	return hex.EncodeToString(h[:16])
}

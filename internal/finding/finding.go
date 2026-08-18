// Package finding defines the output contract. These types serialise directly
// into findings-v1.schema.json, which is Plumbline's public API — see
// docs/DATA-MODEL.md and 05-VERSIONING.md §4. Changing a field here is a
// schema change, not a refactor.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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
}

// Fingerprint computes the stable identity of a finding about subject.
// Deliberately excludes result, severity and detail: a finding that flips from
// FAIL to PASS is the same finding, and a suppression written last quarter
// must still match.
func Fingerprint(checkID, subject string) string {
	h := sha256.Sum256([]byte(checkID + "\x00" + strings.TrimSpace(subject)))
	return hex.EncodeToString(h[:16])
}

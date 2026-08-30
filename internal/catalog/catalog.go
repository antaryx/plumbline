// Package catalog holds the immutable set of checks and evaluates them.
//
// A check is a pure function from facts to a finding. It receives no System,
// no context, no clock and no network — the signature is the enforcement, and
// it is what makes the whole catalog testable from fixtures.
package catalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/sanitize"
)

// Version is the catalog version stamped into every score and bundle. It is a
// monotonic integer, bumped by any change to the set of checks or their
// metadata. Scores are comparable only within one catalog version
// (05-VERSIONING.md §3).
//
// 2 adds the KERNEL module (WP-16); 3 completes it; 4 adds USERS (WP-17); 5
// completes USERS with the group and password-aging checks; 6 completes SSHD
// (WP-18); 7 adds CRON (WP-19); 8 adds LOGGING (WP-20); 9 adds SERVICES
// (WP-21); 10 adds NETWORK and AUTH, completing the v0.2 catalog (WP-22,
// WP-23); 11 adds FILESYS and wires the shared walker into the scan (WP-24),
// completing the v0.2.0 catalog.
const Version = 34

// Outcome is what a check's Eval returns. The runner converts it into a
// finding, filling in identity and fingerprint so a check cannot get those
// wrong.
type Outcome struct {
	Result        finding.Result
	UnknownReason finding.UnknownReason
	// Subject is the specific thing this outcome is about; it feeds the
	// fingerprint. Leave empty for host-wide checks.
	Subject string
	Detail  string
	// Severity overrides the catalog default for this outcome only. Zero value
	// means "use BaseSeverity". Used where one check has genuinely different
	// impact per observed value.
	Severity finding.Severity
	Evidence []finding.Evidence
}

// Check is one catalog entry.
type Check struct {
	ID     string // "SSHD-0002" — permanent, never reused, never renumbered
	Module string // "SSHD"
	Title  string
	// Description explains what is being tested and why it matters. It is
	// rendered into CHECK-REFERENCE.md.
	Description string

	BaseSeverity finding.Severity
	Tags         []string

	// Requires lists the facts this check reads. The runner resolves the check
	// to UNKNOWN automatically if any required fact is absent, so Eval never
	// has to defend against a missing fact it declared.
	Requires []fact.ID

	// Eval is pure. Given a Set in which every required fact is present, it
	// returns exactly one Outcome.
	Eval func(*fact.Set) Outcome

	Remediation *finding.Remediation
	Mappings    []finding.ControlRef
	References  []finding.Reference

	// SinceCatalog records when the check entered the catalog, so a diff can
	// distinguish "newly failing" from "newly existing".
	SinceCatalog int
	// Deprecated, when set, means the check still runs but is on its way out.
	Deprecated *Deprecation
}

// Deprecation records a check's retirement.
type Deprecation struct {
	SinceCatalog int
	Reason       string
	ReplacedBy   []string
}

// Catalog is an immutable, ordered set of checks.
type Catalog struct {
	checks map[string]Check
	order  []string
}

// New builds a catalog, rejecting duplicate or malformed IDs. A malformed
// catalog is a programming error and panics at startup rather than producing
// subtly wrong reports later.
func New(checks ...Check) (*Catalog, error) {
	c := &Catalog{checks: map[string]Check{}}
	for _, ck := range checks {
		if err := validate(ck); err != nil {
			return nil, err
		}
		if _, dup := c.checks[ck.ID]; dup {
			return nil, fmt.Errorf("duplicate check ID %s", ck.ID)
		}
		c.checks[ck.ID] = ck
		c.order = append(c.order, ck.ID)
	}
	sort.Strings(c.order)
	return c, nil
}

// MustNew is New for package-level catalog construction.
func MustNew(checks ...Check) *Catalog {
	c, err := New(checks...)
	if err != nil {
		panic(err)
	}
	return c
}

func validate(ck Check) error {
	switch {
	case ck.ID == "":
		return fmt.Errorf("check has no ID")
	case ck.Module == "":
		return fmt.Errorf("%s: no module", ck.ID)
	case !strings.HasPrefix(ck.ID, ck.Module+"-"):
		return fmt.Errorf("%s: ID must start with module prefix %q", ck.ID, ck.Module+"-")
	case ck.Title == "":
		return fmt.Errorf("%s: no title", ck.ID)
	case ck.BaseSeverity == "":
		return fmt.Errorf("%s: no base severity", ck.ID)
	case ck.Eval == nil:
		return fmt.Errorf("%s: no Eval", ck.ID)
	case len(ck.Requires) == 0:
		return fmt.Errorf("%s: declares no required facts", ck.ID)
	}
	return nil
}

// Get returns a check by ID.
func (c *Catalog) Get(id string) (Check, bool) {
	ck, ok := c.checks[id]
	return ck, ok
}

// IDs returns all check IDs in sorted order, which is also evaluation order.
// Deterministic ordering is a correctness property, not a nicety: it is what
// makes two runs over one bundle byte-identical.
func (c *Catalog) IDs() []string {
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// Len reports the number of checks.
func (c *Catalog) Len() int { return len(c.order) }

// Observer is notified as each check reaches a verdict, so that a caller can
// show progress instead of waiting for the slice.
//
// **The contract is narrow on purpose.** CheckDone is called once per check,
// synchronously, on the goroutine that called EvaluateWith, in the same
// deterministic order the returned slice carries. An implementation must not
// block for long — it is on the evaluation path — and must not retain the
// finding beyond the call unless it copies it.
//
// It is also called before anything the *pipeline* does to a finding: profile
// scoping and suppression both happen after evaluation, so an observer sees a
// suppressed finding as the FAIL it is rather than as SUPPRESSED. That is the
// honest thing for a live view of evaluation to show and the wrong thing for a
// report to show, which is why the report is rendered from the slice and not
// from these events.
type Observer interface {
	CheckDone(finding.Finding)
}

// Evaluate runs the whole catalog against a fact set and returns findings in
// deterministic order.
func (c *Catalog) Evaluate(facts *fact.Set) []finding.Finding {
	return c.EvaluateWith(facts, nil)
}

// EvaluateWith is Evaluate with an observer notified as each check finishes.
// A nil observer is the plain evaluation, which is why Evaluate is one line.
//
// Evaluation is sequential, and that is a correctness property rather than an
// unfinished optimisation: IDs returns sorted order, two runs over one bundle
// must be byte-identical, and 109 checks over a collected fact set take about
// a millisecond. Nothing here would be faster in parallel and the determinism
// would have to be rebuilt afterwards. An observer is therefore called from
// one goroutine — but an implementation shared with the collector runner, which
// genuinely is concurrent, still has to be safe for concurrent use.
func (c *Catalog) EvaluateWith(facts *fact.Set, obs Observer) []finding.Finding {
	out := make([]finding.Finding, 0, len(c.order))
	for _, id := range c.order {
		f := c.EvaluateOne(c.checks[id], facts)
		out = append(out, f)
		if obs != nil {
			obs.CheckDone(f)
		}
	}
	return out
}

// EvaluateOne runs a single check, applying the three guarantees a check
// author does not have to implement themselves: required facts are present,
// panics become UNKNOWN rather than crashing the scan, and identity fields are
// filled in consistently.
func (c *Catalog) EvaluateOne(ck Check, facts *fact.Set) (f finding.Finding) {
	f = finding.Finding{
		CheckID:      ck.ID,
		Module:       ck.Module,
		Title:        ck.Title,
		BaseSeverity: ck.BaseSeverity,
		Severity:     ck.BaseSeverity,
		Mappings:     ck.Mappings,
		References:   ck.References,
		Fingerprint:  finding.Fingerprint(ck.ID, ""),
	}

	// A panic in one check must never take down a scan. In CI, any panic over
	// the fixture corpus is a test failure, so this is a production safety net
	// rather than a place bugs go to hide.
	defer func() {
		if r := recover(); r != nil {
			f.Result = finding.Unknown
			f.UnknownReason = finding.ReasonInternal
			f.Detail = fmt.Sprintf("check panicked: %v", r)
			f.Remediation = nil
		}
	}()

	// Required-fact gate. This is why Eval can read its facts unconditionally.
	for _, id := range ck.Requires {
		if e, bad := facts.Err(id); bad {
			f.Result = finding.Unknown
			f.UnknownReason = reasonFor(e.Kind)
			f.Detail = sanitize.Text(fmt.Sprintf("required fact %s unavailable: %s", id, e.Msg))
			// A fact error that names a path is citable, and DATA-MODEL.md
			// §5.5 requires every UNKNOWN to carry evidence. Without this the
			// gate produced the one class of finding in the project that said
			// "I do not know" and gave the reader nothing to look at — which
			// is precisely the finding an auditor most needs to follow up.
			if e.Path != "" {
				f.Evidence = sanitizeEvidence([]finding.Evidence{
					finding.NewEvidence(e.Path, 0, e.Msg, ""),
				})
			}
			return f
		}
		if !containsID(facts.IDs(), id) {
			f.Result = finding.Unknown
			f.UnknownReason = finding.ReasonFactMissing
			f.Detail = fmt.Sprintf("required fact %s was not collected", id)
			return f
		}
		// Present is not the same as usable. A bundle written by a newer build
		// carries facts this one cannot decode, and the reader keeps them
		// verbatim so that forwarding the bundle loses nothing — but a check
		// that ran anyway would read the zero value out of its typed accessor
		// and report the host as having no sshd, no accounts and no firewall.
		// That is a statement about the host manufactured from a decode
		// failure, which is the worst thing this codebase can produce.
		if op, opaque := facts.Opaque(id); opaque {
			f.Result = finding.Unknown
			f.UnknownReason = finding.ReasonFactVersion
			f.Detail = fmt.Sprintf(
				"required fact %s is present in this bundle at version %d, which this build of the catalog does not understand. Nothing may be concluded from it: the bundle was written by a different version of Plumbline, and re-evaluating it needs a build that knows this fact's shape.",
				id, op.OpaqueFact())
			f.Evidence = sanitizeEvidence([]finding.Evidence{
				finding.NewEvidence(string(id), 0,
					fmt.Sprintf("fact version %d is not decodable by this build", op.OpaqueFact()), ""),
			})
			return f
		}
	}

	oc := ck.Eval(facts)
	f.Result = oc.Result
	f.UnknownReason = oc.UnknownReason
	// Everything a check interpolated came from the host: a directive value, a
	// path, a command line. It is neutralised here, on the single path out of
	// a check, so that no renderer and no future check author has to remember
	// (THREAT-MODEL.md T-03). Sanitisation is the identity function on the
	// ordinary text every honest host produces.
	f.Detail = sanitize.Text(oc.Detail)
	f.Evidence = sanitizeEvidence(oc.Evidence)
	f.Subject = sanitize.Text(oc.Subject)
	// The fingerprint is taken from the sanitised subject so that a suppression
	// an operator wrote cannot be dodged by re-encoding a control character.
	f.Fingerprint = finding.Fingerprint(ck.ID, f.Subject)
	if oc.Severity != "" {
		f.Severity = oc.Severity
	}
	if oc.Result == finding.Fail {
		f.Remediation = ck.Remediation
	}
	return f
}

// sanitizeEvidence neutralises the evidence a check produced. It is applied
// whether or not the check used finding.NewEvidence, because an Evidence
// literal is the easiest thing in this codebase to write by hand.
func sanitizeEvidence(in []finding.Evidence) []finding.Evidence {
	if len(in) == 0 {
		return nil
	}
	out := make([]finding.Evidence, len(in))
	for i, e := range in {
		out[i] = finding.NewEvidence(e.Source, e.Line, e.Excerpt, e.SHA256)
	}
	return out
}

func reasonFor(k fact.ErrorKind) finding.UnknownReason {
	switch k {
	case fact.ErrPermission:
		return finding.ReasonPermission
	case fact.ErrParse:
		return finding.ReasonParse
	case fact.ErrTruncated:
		return finding.ReasonTruncated
	case fact.ErrNotCollected:
		return finding.ReasonFactMissing
	case fact.ErrInternal:
		return finding.ReasonInternal
	default:
		return finding.ReasonAmbiguousState
	}
}

func containsID(ids []fact.ID, want fact.ID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

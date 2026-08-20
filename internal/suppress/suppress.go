// Package suppress applies an operator's accepted-risk decisions to findings.
//
// A team that has looked at a finding and accepted it must be able to say so,
// or the second scan reports the same thing as the first and people stop
// reading the report. That is the adoption problem this package solves. What
// it must not do is solve it by making the finding go away.
//
// Four rules follow from that, and each one is a thing a lesser
// implementation gets wrong.
//
// **A suppressed finding is still in the document.** Its result becomes
// SKIPPED, and it carries a finding.Suppression recording the justification,
// the expiry, and — the load-bearing field — the result it would otherwise
// have had. A suppression that removes a row is indistinguishable from a check
// that never ran, and the difference between "we accepted this" and "we never
// looked" is the entire value of the artefact.
//
// **A suppression without a justification is rejected.** Not warned about,
// rejected: the file fails to parse and the scan does not run. An
// unaccountable suppression is a silent one with extra steps, and the moment
// the format tolerates a blank reason it becomes the format everyone uses.
//
// **Expiry is judged against the scan, not against the clock.** See Apply.
//
// **A rule that matched nothing is reported.** Fingerprints change when a
// check's subject changes, so a suppression file rots. A rule that no longer
// matches is either a finding that got fixed — good news worth telling someone
// about — or a suppression that has quietly stopped protecting what its author
// thought it protected. Both are worth a line of output.
//
// This package touches no OS. It parses bytes the caller has already read
// through internal/system, which is what keeps --root from ever applying to a
// path the operator named (ADR-0011): a suppression file lives in the
// operator's working directory, not inside the filesystem under audit.
package suppress

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
)

// Schema is the value the schema key must carry. It is checked rather than
// assumed so that a file written for a future format fails loudly here instead
// of being silently half-understood.
const Schema = "suppressions/v1"

// File is the on-disk shape of a suppression file.
type File struct {
	Schema string `json:"schema"`
	Rules  []Rule `json:"suppressions"`
}

// Rule is one accepted finding.
type Rule struct {
	// Fingerprint is finding.Fingerprint(check_id, subject), copied from a
	// findings document. It is the match key because it is stable across runs
	// by construction: it excludes result, severity and detail, so a finding
	// that flips FAIL to PASS and back is the same finding, and a suppression
	// written last quarter still matches.
	Fingerprint string `json:"fingerprint"`

	// Justification is why this risk was accepted. Required, and required to
	// be non-blank.
	Justification string `json:"justification"`

	// ExpiresAt is an RFC 3339 timestamp. Optional; absent means the
	// acceptance does not lapse on its own.
	ExpiresAt string `json:"expires_at,omitempty"`

	// CheckID and Subject are optional and advisory — they exist so a human
	// reading the file can tell what a hex fingerprint refers to. When present
	// they are *verified* against the fingerprint rather than trusted, because
	// a comment that can drift from what it describes is worse than no comment.
	CheckID string `json:"check_id,omitempty"`
	Subject string `json:"subject,omitempty"`

	expires time.Time // parsed form of ExpiresAt; zero when absent
}

// Expires returns the parsed expiry and whether the rule has one.
func (r Rule) Expires() (time.Time, bool) { return r.expires, !r.expires.IsZero() }

// Set is a parsed, validated suppression file.
type Set struct {
	byFingerprint map[string]Rule
	order         []string // parse order, for deterministic reporting
}

// Len is the number of rules the file carried.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Parse reads a suppression file.
//
// Every error names the rule by index and says what is wrong with it. A
// suppression file is hand-edited — that is the point of it — so the parser's
// job is to be specific about what to fix, not merely to refuse.
func Parse(data []byte) (*Set, error) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(data)))
	// Unknown fields are an error rather than an ignored typo. "justifcation"
	// silently parsing as an absent justification is exactly the failure this
	// package exists to prevent.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("suppression file is not valid JSON: %w", err)
	}

	if f.Schema != Schema {
		return nil, fmt.Errorf("suppression file declares schema %q; this build understands %q",
			f.Schema, Schema)
	}

	set := &Set{byFingerprint: make(map[string]Rule, len(f.Rules))}
	for i, r := range f.Rules {
		r.Fingerprint = strings.ToLower(strings.TrimSpace(r.Fingerprint))
		if !fingerprintPattern.MatchString(r.Fingerprint) {
			return nil, fmt.Errorf("suppression %d: fingerprint %q is not 32 lowercase hex characters; "+
				"copy it from the fingerprint field of a findings document", i, r.Fingerprint)
		}
		if strings.TrimSpace(r.Justification) == "" {
			return nil, fmt.Errorf("suppression %d (%s): justification is required and may not be blank — "+
				"a suppression nobody can account for is a hidden finding", i, r.Fingerprint)
		}
		if r.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, r.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("suppression %d (%s): expires_at %q is not an RFC 3339 timestamp "+
					"such as 2027-01-31T00:00:00Z: %w", i, r.Fingerprint, r.ExpiresAt, err)
			}
			r.expires = t
		}
		// The advisory fields are verified, never trusted. If they disagree
		// with the fingerprint the file has drifted, and the operator is
		// looking at a rule that does not do what its own label says.
		if r.CheckID != "" || r.Subject != "" {
			if want := finding.Fingerprint(r.CheckID, r.Subject); want != r.Fingerprint {
				return nil, fmt.Errorf("suppression %d: check_id %q with subject %q fingerprints to %s, "+
					"not the %s recorded here — the rule and its label describe different findings",
					i, r.CheckID, r.Subject, want, r.Fingerprint)
			}
		}
		if _, dup := set.byFingerprint[r.Fingerprint]; dup {
			return nil, fmt.Errorf("suppression %d: fingerprint %s appears more than once; "+
				"two justifications for one finding means one of them is not being applied",
				i, r.Fingerprint)
		}
		set.byFingerprint[r.Fingerprint] = r
		set.order = append(set.order, r.Fingerprint)
	}
	return set, nil
}

// Outcome is what applying a set did — to the findings, and to the rules.
type Outcome struct {
	// Findings is the input with suppressed entries rewritten. Always the full
	// list: nothing is ever dropped.
	Findings []finding.Finding

	// Applied are the rules that suppressed something, in file order.
	Applied []Rule

	// Expired are rules that matched a finding but had lapsed, so the finding
	// kept its original result. These are the ones worth acting on: somebody
	// accepted a risk with a deadline and the deadline has passed.
	Expired []Rule

	// Unmatched are rules that matched no finding at all.
	Unmatched []Rule
}

// Suppressed is the number of findings whose result this outcome changed.
func (o Outcome) Suppressed() int { return len(o.Applied) }

// Apply rewrites every FAIL and UNKNOWN whose fingerprint carries a live rule.
//
// **at is the moment expiry is measured against, and the caller passes the
// scan's start time rather than the wall clock.** That is what keeps a bundle
// re-evaluable: the same bundle, the same catalog and the same suppression
// file produce the same findings today, next week and in three years, which is
// the property that makes a bundle evidence rather than a snapshot of an
// opinion. Reading the clock here instead would mean an archived bundle
// silently changes its verdict on the day a suppression lapses, and the
// artefact would no longer say what it said when it was signed.
//
// PASS is never suppressed. There is nothing to accept about a check that
// passed, and rewriting one to SKIPPED would delete good news; a rule whose
// finding now passes is reported as unmatched instead, which is how an
// operator learns the suppression is no longer needed.
func (s *Set) Apply(in []finding.Finding, at time.Time) Outcome {
	out := Outcome{Findings: in}
	if s == nil || len(s.byFingerprint) == 0 {
		return out
	}

	out.Findings = make([]finding.Finding, len(in))
	copy(out.Findings, in)

	applied := map[string]bool{}
	expired := map[string]bool{}

	for i := range out.Findings {
		f := &out.Findings[i]
		if f.Result != finding.Fail && f.Result != finding.Unknown {
			continue
		}
		rule, ok := s.byFingerprint[f.Fingerprint]
		if !ok {
			continue
		}
		if exp, has := rule.Expires(); has && !at.Before(exp) {
			// Lapsed. The finding keeps its result — that is the whole
			// purpose of an expiry — and the rule is reported so the lapse is
			// visible rather than merely effective.
			expired[rule.Fingerprint] = true
			continue
		}
		f.Suppression = &finding.Suppression{
			Justification:  strings.TrimSpace(rule.Justification),
			ExpiresAt:      rule.ExpiresAt,
			OriginalResult: f.Result,
		}
		f.Result = finding.Skipped
		applied[rule.Fingerprint] = true
	}

	for _, fp := range s.order {
		rule := s.byFingerprint[fp]
		switch {
		case applied[fp]:
			out.Applied = append(out.Applied, rule)
		case expired[fp]:
			out.Expired = append(out.Expired, rule)
		default:
			out.Unmatched = append(out.Unmatched, rule)
		}
	}
	return out
}

// SortRules orders rules by fingerprint. Callers that render a set rather than
// an outcome use it so that two reports of an unchanged host are identical.
func SortRules(in []Rule) {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Fingerprint < in[j].Fingerprint })
}

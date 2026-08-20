// Package score computes posture and coverage from a set of findings.
//
// Two numbers, and they are never separated. ARCHITECTURE.md §5:
//
//	Evaluated = PASS + FAIL                              the only states that score
//	Coverage  = Evaluated / (Total − NOT_APPLICABLE) × 100
//	Posture   = Σ(weight of PASS) / Σ(weight of Evaluated) × 100
//
// The shape of those formulas is the whole point. SKIPPED and UNKNOWN leave
// the posture denominator entirely and reduce coverage instead, so an
// unprivileged scan reports "posture 82, coverage 44%" — truthfully saying it
// checked less than half of what applies and found what it could check to be
// sound — rather than the audited design's punitive 40, which counted every
// question it was not allowed to ask as a failure. Punishing a user for not
// being root teaches them to ignore the number.
//
// There is one score. The audited design's second one, a Risk Score,
// double-counted the first with arbitrary constants and was removed
// (docs/audit/argus-design-audit.md A-13). Exposure context belongs in
// severity adjustment, where it is visible and explainable.
package score

import "github.com/antaryx/plumbline/internal/finding"

// Counts is the tally of findings by result state.
type Counts struct {
	Pass          int
	Fail          int
	NotApplicable int
	Skipped       int
	Unknown       int
	Total         int

	// OutOfProfile is how many of Skipped were put out of scope by the active
	// profile. It is a subset of Skipped, not a sixth state, and it is not
	// serialised anywhere — it exists so Applicable can subtract it.
	OutOfProfile int
}

// Evaluated is the number of checks that reached a verdict. Only these score:
// a check that did not run is not evidence of anything.
func (c Counts) Evaluated() int { return c.Pass + c.Fail }

// Applicable is the number of checks that could have produced a verdict about
// this host.
//
// NOT_APPLICABLE leaves the question entirely — a host with no sshd installed
// is not doing badly at sshd configuration, and it is not doing well either.
//
// **A check the active profile excluded leaves it too**, and that is the whole
// point of a profile: it declares what applies, so the applicable set *is* the
// profile. Without this, scanning a container against a thirty-check baseline
// would report coverage of 38% and a posture capped in red — punishing an
// operator for scoping the question correctly, which is the same mistake the
// audited design made by counting unasked questions as failures.
func (c Counts) Applicable() int { return c.Total - c.NotApplicable - c.OutOfProfile }

// Score is posture and coverage for one evaluation of one catalog.
//
// The fields are unexported and read through methods on purpose. Posture and
// coverage can both be *undefined* — there was nothing to compute them over —
// and undefined is not zero. A struct with a plain float64 field invites a
// caller to print the zero value, and "posture 0" on a host that was never
// examined is the single most misleading thing this tool could say. The
// accessors return (value, ok) for the same reason fact.Get returns three
// values: the caller cannot read the number without acknowledging whether
// there is one.
type Score struct {
	catalogVersion int
	counts         Counts

	coverage        float64
	coverageDefined bool

	posture        float64
	postureDefined bool
}

// Compute tallies findings and derives the two figures.
//
// catalogVersion is carried rather than looked up: a score is only meaningful
// against the catalog that produced it, and the caller is the only one who
// knows which catalog ran.
func Compute(findings []finding.Finding, catalogVersion int) Score {
	s := Score{catalogVersion: catalogVersion}

	var passWeight, evaluatedWeight float64
	for _, f := range findings {
		s.counts.Total++
		switch f.Result {
		case finding.Pass:
			s.counts.Pass++
			// The effective severity, after any context adjustment: what this
			// check is worth on this host, not what it is worth in general.
			passWeight += f.Severity.Weight()
			evaluatedWeight += f.Severity.Weight()
		case finding.Fail:
			s.counts.Fail++
			evaluatedWeight += f.Severity.Weight()
		case finding.NotApplicable:
			s.counts.NotApplicable++
		case finding.Skipped:
			s.counts.Skipped++
			if f.SkippedBy != "" {
				s.counts.OutOfProfile++
			}
		case finding.Unknown:
			s.counts.Unknown++
		}
	}

	// Coverage is the share of applicable checks that reached a verdict. It is
	// undefined when nothing applied to this host: "0% of the applicable
	// checks were evaluated" is a division by zero, not a zero, and a host
	// that nothing applies to has not been covered badly.
	if applicable := s.counts.Applicable(); applicable > 0 {
		s.coverage = float64(s.counts.Evaluated()) / float64(applicable) * 100
		s.coverageDefined = true
	}

	// Posture is undefined whenever the denominator is empty, which happens in
	// two ways: nothing was evaluated, or everything evaluated carries zero
	// weight (an INFO-only run). Both mean the same thing — there is no
	// evidence to form a judgement from — and reporting either as 0 would
	// claim every check failed.
	if evaluatedWeight > 0 {
		s.posture = passWeight / evaluatedWeight * 100
		s.postureDefined = true
	}

	return s
}

// CatalogVersion is the catalog the findings were produced by. Scores are
// comparable only within one version (docs/VERSIONING.md §3).
func (s Score) CatalogVersion() int { return s.catalogVersion }

// Counts returns the tally the figures were derived from.
func (s Score) Counts() Counts { return s.counts }

// Coverage returns the share of applicable checks that were evaluated, and
// whether it is defined at all. It is undefined when no check applied to this
// host.
//
// Renderers must show coverage wherever they show posture. A posture score
// without its coverage is a number with no scale: 100 over two checks out of
// two hundred is not a clean host, it is an unexamined one.
func (s Score) Coverage() (float64, bool) { return s.coverage, s.coverageDefined }

// Posture returns the weighted share of evaluated checks that passed, and
// whether it is defined at all.
//
// Undefined means nothing was evaluated, or nothing evaluated carried weight.
// It does not mean zero. A caller that renders undefined as 0 has reintroduced
// the audited scoring bug: an all-SKIPPED run would report a host in perfect
// failure when in fact nobody looked at it.
func (s Score) Posture() (float64, bool) { return s.posture, s.postureDefined }

// Comparable reports whether two scores can be compared at all.
//
// Scores from different catalog versions cannot: adding four checks to the
// catalog moves posture without anything on the host changing, so a fall from
// 71 to 68 across a catalog bump says nothing about the host. `plumbline diff`
// refuses such a comparison unless it is explicitly forced, and annotates it
// even then (CLI-SPEC.md).
func Comparable(a, b Score) bool { return a.catalogVersion == b.catalogVersion }

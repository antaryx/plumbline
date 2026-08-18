package score_test

import (
	"math"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// f builds a finding with just the two fields scoring reads.
func f(r finding.Result, sev finding.Severity) finding.Finding {
	return finding.Finding{Result: r, Severity: sev, BaseSeverity: sev}
}

func repeat(n int, in finding.Finding) []finding.Finding {
	out := make([]finding.Finding, n)
	for i := range out {
		out[i] = in
	}
	return out
}

const epsilon = 1e-9

func approx(a, b float64) bool { return math.Abs(a-b) < epsilon }

// wantPosture asserts both the value and, more importantly, whether there is
// one at all.
func wantPosture(t *testing.T, s score.Score, value float64, defined bool) {
	t.Helper()
	got, ok := s.Posture()
	if ok != defined {
		t.Fatalf("posture defined = %v, want %v (value was %v)", ok, defined, got)
	}
	if defined && !approx(got, value) {
		t.Errorf("posture = %v, want %v", got, value)
	}
}

func wantCoverage(t *testing.T, s score.Score, value float64, defined bool) {
	t.Helper()
	got, ok := s.Coverage()
	if ok != defined {
		t.Fatalf("coverage defined = %v, want %v (value was %v)", ok, defined, got)
	}
	if defined && !approx(got, value) {
		t.Errorf("coverage = %v, want %v", got, value)
	}
}

// TestNothingEvaluatedLeavesPostureUndefined is the acceptance criterion and
// the audited scoring bug. "Nobody looked" and "everything failed" are
// different statements about a host, and a scorer that renders the first as 0
// tells an operator their machine is in perfect failure when in fact it was
// never examined.
//
// Coverage is 0 here and that is correct: there were applicable checks, and
// none of them were evaluated. Posture has no denominator at all.
func TestNothingEvaluatedLeavesPostureUndefined(t *testing.T) {
	cases := []struct {
		name string
		in   []finding.Finding
	}{
		{"all skipped", repeat(20, f(finding.Skipped, finding.High))},
		{"all unknown", repeat(20, f(finding.Unknown, finding.High))},
		{"skipped and unknown together", append(
			repeat(10, f(finding.Skipped, finding.Critical)),
			repeat(10, f(finding.Unknown, finding.Low))...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := score.Compute(tc.in, 1)

			wantCoverage(t, s, 0, true)
			wantPosture(t, s, 0, false)

			if got := s.Counts().Evaluated(); got != 0 {
				t.Errorf("evaluated = %d, want 0", got)
			}
			if got := s.Counts().Total; got != 20 {
				t.Errorf("total = %d, want 20", got)
			}
		})
	}
}

// TestNotApplicableAffectsNeitherFigure is the acceptance criterion. A host
// with no sshd installed is not failing sshd checks and is not passing them:
// the question does not apply, so it leaves both the numerator and the
// denominator rather than being counted as either.
func TestNotApplicableAffectsNeitherFigure(t *testing.T) {
	base := []finding.Finding{
		f(finding.Pass, finding.High),
		f(finding.Fail, finding.High),
		f(finding.Unknown, finding.High),
	}
	before := score.Compute(base, 1)

	withNA := append(append([]finding.Finding(nil), base...), repeat(50, f(finding.NotApplicable, finding.Critical))...)
	after := score.Compute(withNA, 1)

	bp, _ := before.Posture()
	ap, _ := after.Posture()
	if !approx(bp, ap) {
		t.Errorf("posture moved from %v to %v when NOT_APPLICABLE findings were added", bp, ap)
	}
	bc, _ := before.Coverage()
	ac, _ := after.Coverage()
	if !approx(bc, ac) {
		t.Errorf("coverage moved from %v to %v when NOT_APPLICABLE findings were added", bc, ac)
	}

	// Fifty CRITICAL non-applicable checks are worth nothing in either
	// direction, however heavy their severity.
	wantPosture(t, after, 50, true)           // one HIGH pass, one HIGH fail
	wantCoverage(t, after, 2.0/3.0*100, true) // two of three applicable
	if got := after.Counts().Applicable(); got != 3 {
		t.Errorf("applicable = %d, want 3", got)
	}
	if got := after.Counts().Total; got != 53 {
		t.Errorf("total = %d, want 53", got)
	}
}

// TestUnprivilegedRunIsNotPunished is the acceptance criterion, and the reason
// the formulas are shaped this way.
//
// An operator runs without root. Most checks cannot read what they need and
// resolve to UNKNOWN; the handful that can be answered all pass. The truthful
// report is "the parts I could check are sound, and I could only check a
// third" — a high posture at low coverage. The audited design divided by the
// whole catalog and reported a low number, which punishes a user for a
// privilege they did not have and teaches them the score is noise.
func TestUnprivilegedRunIsNotPunished(t *testing.T) {
	var corpus []finding.Finding
	corpus = append(corpus, repeat(8, f(finding.Pass, finding.High))...)
	corpus = append(corpus, f(finding.Fail, finding.Low))
	corpus = append(corpus, repeat(21, f(finding.Unknown, finding.Critical))...)

	s := score.Compute(corpus, 1)

	posture, ok := s.Posture()
	if !ok {
		t.Fatal("posture is undefined on a run that evaluated nine checks")
	}
	coverage, _ := s.Coverage()

	// 24 weight passing of 25 evaluated: high. Nine of thirty applicable: low.
	wantPosture(t, s, 24.0/25.0*100, true)
	wantCoverage(t, s, 30.0, true)

	if posture < 90 {
		t.Errorf("posture %v punishes an unprivileged run whose evaluated checks passed", posture)
	}
	if coverage > 50 {
		t.Errorf("coverage %v does not reflect that two thirds of the catalog could not be answered", coverage)
	}

	// The same host scanned as root, with those UNKNOWNs answered and failing,
	// must score far worse. If it does not, coverage is not doing its job.
	asRoot := append(append([]finding.Finding(nil), corpus[:9]...), repeat(21, f(finding.Fail, finding.Critical))...)
	rooted := score.Compute(asRoot, 1)
	rp, _ := rooted.Posture()
	if rp >= posture {
		t.Errorf("a scan that found 21 critical failures scored %v, no worse than the blind scan's %v", rp, posture)
	}
}

// TestWeightArithmetic pins the exact numbers. Weights are a MAJOR-release
// concern (VERSIONING.md §6), so a change to finding.Severity.Weight() must
// break this test rather than quietly moving every user's posture.
func TestWeightArithmetic(t *testing.T) {
	// The weights this arithmetic depends on, asserted directly so that a
	// change to them fails here and names itself.
	for _, w := range []struct {
		sev  finding.Severity
		want float64
	}{
		{finding.Critical, 4},
		{finding.High, 3},
		{finding.Medium, 2},
		{finding.Low, 1},
		{finding.Info, 0},
	} {
		if got := w.sev.Weight(); got != w.want {
			t.Fatalf("%s weight = %v, want %v — the arithmetic below assumes these", w.sev, got, w.want)
		}
	}

	cases := []struct {
		name            string
		in              []finding.Finding
		posture         float64
		postureDefined  bool
		coverage        float64
		coverageDefined bool
	}{
		{
			name:    "one high pass",
			in:      []finding.Finding{f(finding.Pass, finding.High)},
			posture: 100, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			name:    "one high fail",
			in:      []finding.Finding{f(finding.Fail, finding.High)},
			posture: 0, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// 3 of 6: severity cancels out when it is equal on both sides.
			name:    "one high pass, one high fail",
			in:      []finding.Finding{f(finding.Pass, finding.High), f(finding.Fail, finding.High)},
			posture: 50, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// 1 of 1+4: a critical failure outweighs a low pass four to one,
			// which is the entire reason posture is weighted.
			name:    "low pass, critical fail",
			in:      []finding.Finding{f(finding.Pass, finding.Low), f(finding.Fail, finding.Critical)},
			posture: 20, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// 3 of 3+2.
			name:    "high pass, medium fail",
			in:      []finding.Finding{f(finding.Pass, finding.High), f(finding.Fail, finding.Medium)},
			posture: 60, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// 4+4 of 4+4+3.
			name: "two critical passes, one high fail",
			in: []finding.Finding{
				f(finding.Pass, finding.Critical),
				f(finding.Pass, finding.Critical),
				f(finding.Fail, finding.High),
			},
			posture: 8.0 / 11.0 * 100, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// INFO weighs nothing, so an INFO-only run has an empty
			// denominator even though two checks were evaluated. Undefined,
			// not zero: the checks ran, they simply carry no judgement.
			name: "info only leaves posture undefined",
			in: []finding.Finding{
				f(finding.Pass, finding.Info),
				f(finding.Fail, finding.Info),
			},
			posture: 0, postureDefined: false, coverage: 100, coverageDefined: true,
		},
		{
			// Weightless checks do not dilute the ones that count.
			name: "info alongside weighted checks",
			in: []finding.Finding{
				f(finding.Pass, finding.High),
				f(finding.Fail, finding.High),
				f(finding.Pass, finding.Info),
				f(finding.Fail, finding.Info),
			},
			posture: 50, postureDefined: true, coverage: 100, coverageDefined: true,
		},
		{
			// Two of four applicable evaluated; the evaluated pair is one HIGH
			// pass against one MEDIUM fail.
			name: "the full mixture",
			in: []finding.Finding{
				f(finding.Pass, finding.High),
				f(finding.Fail, finding.Medium),
				f(finding.Unknown, finding.Critical),
				f(finding.Skipped, finding.Critical),
				f(finding.NotApplicable, finding.Critical),
			},
			posture: 60, postureDefined: true, coverage: 50, coverageDefined: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := score.Compute(tc.in, 1)
			wantPosture(t, s, tc.posture, tc.postureDefined)
			wantCoverage(t, s, tc.coverage, tc.coverageDefined)
		})
	}
}

// TestNothingApplicableLeavesCoverageUndefined: when no check applies, "0% of
// the applicable checks were evaluated" is a division by zero rather than a
// zero. The same conflation that makes an undefined posture dangerous applies
// here, so coverage answers the same way.
func TestNothingApplicableLeavesCoverageUndefined(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []finding.Finding
	}{
		{"empty catalog", nil},
		{"everything not applicable", repeat(12, f(finding.NotApplicable, finding.High))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := score.Compute(tc.in, 1)
			wantCoverage(t, s, 0, false)
			wantPosture(t, s, 0, false)
		})
	}
}

// TestCounts: the tally the figures are derived from must itself be right, or
// a correct formula produces a wrong number.
func TestCounts(t *testing.T) {
	s := score.Compute([]finding.Finding{
		f(finding.Pass, finding.High),
		f(finding.Pass, finding.Low),
		f(finding.Fail, finding.Critical),
		f(finding.NotApplicable, finding.High),
		f(finding.Skipped, finding.High),
		f(finding.Unknown, finding.High),
		f(finding.Unknown, finding.Medium),
	}, 7)

	got := s.Counts()
	want := score.Counts{Pass: 2, Fail: 1, NotApplicable: 1, Skipped: 1, Unknown: 2, Total: 7}
	if got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
	if got.Evaluated() != 3 {
		t.Errorf("evaluated = %d, want 3", got.Evaluated())
	}
	if got.Applicable() != 6 {
		t.Errorf("applicable = %d, want 6", got.Applicable())
	}
	if s.CatalogVersion() != 7 {
		t.Errorf("catalog version = %d, want 7", s.CatalogVersion())
	}
}

// TestComparableAcrossCatalogVersions: adding checks to the catalog moves
// posture without anything on the host changing, so a comparison across
// versions describes the catalog rather than the machine.
func TestComparableAcrossCatalogVersions(t *testing.T) {
	a := score.Compute([]finding.Finding{f(finding.Pass, finding.High)}, 16)
	b := score.Compute([]finding.Finding{f(finding.Fail, finding.High)}, 16)
	c := score.Compute([]finding.Finding{f(finding.Pass, finding.High)}, 17)

	if !score.Comparable(a, b) {
		t.Error("two scores from catalog 16 were refused as incomparable")
	}
	if score.Comparable(a, c) {
		t.Error("scores from catalog 16 and 17 were treated as comparable")
	}
	if score.Comparable(c, a) {
		t.Error("comparability is not symmetric")
	}
}

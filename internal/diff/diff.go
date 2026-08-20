// Package diff compares two evaluations of the same host.
//
// The question it answers is "what changed overnight", and the reason it can
// answer it cheaply is that everything upstream is deterministic: the same
// facts and the same catalog produce byte-identical findings, so any
// difference between two runs is a difference in the host rather than noise in
// the tool.
//
// **Both sides are evaluated with today's catalog.** A bundle stores facts,
// not verdicts, so `diff` re-runs the current catalog over each one. That makes
// a whole class of confusion impossible: a check whose logic was corrected
// between the two collections cannot show up as the host having changed,
// because the same code judged both. It is also why there is no
// catalog-drift flag — there is no drift to allow.
//
// **A suppressed finding is compared by what it really is.** internal/suppress
// records the verdict a check actually reached in Suppression.OriginalResult,
// so this package can ask "was this failing?" of a suppressed finding and get a
// true answer. Without that field a suppression would look identical to a fix,
// and "we accepted this" would diff as "resolved" — which is the exact
// confusion the suppression design exists to prevent.
//
// This package touches no OS and no clock. It is a pure function of two
// finding sets.
package diff

import (
	"sort"

	"github.com/antaryx/plumbline/internal/finding"
)

// Category is one kind of change. Unchanged findings have no category and are
// never reported: a diff that lists everything is a report, not a diff.
type Category string

const (
	// Resolved: it was failing, and now it passes, does not apply, or is gone.
	Resolved Category = "RESOLVED"

	// NewFailure: it was not failing, and now it is.
	NewFailure Category = "NEW FAILURE"

	// NewlySuppressed: an operator accepted it since the last run. Not a fix,
	// and rendered separately from one for that reason.
	NewlySuppressed Category = "NEWLY SUPPRESSED"

	// Regressed: it was an accepted risk and no longer is, because the rule
	// expired or was removed from the suppression file. The host did not
	// necessarily change; the acceptance did.
	Regressed Category = "REGRESSED"

	// VerdictChanged: failing before and failing now, but not in the same way
	// — FAIL became UNKNOWN or the reverse.
	//
	// This category is not one of the four transitions WP-30 names, and it is
	// here because without it the report contradicts itself. UNKNOWN leaves
	// the posture denominator and FAIL does not, so a host where one check
	// slid from FAIL to UNKNOWN shows a posture delta with no change listed to
	// explain it. It is also the transition that matters most on its own
	// terms: the tool has stopped being able to tell, and a diff that treats
	// losing visibility as "no change" is the failure this project refuses
	// everywhere else.
	VerdictChanged Category = "VERDICT CHANGED"
)

// Change is one finding that moved, carrying both sides so a renderer can show
// what it was and what it became.
//
// Old or New is nil when the finding was absent from that side. That happens
// without any catalog change: a check that reports per-subject findings emits
// one per path it found, so a file appearing or disappearing between two scans
// adds or removes a fingerprint.
type Change struct {
	Category Category
	Old      *finding.Finding
	New      *finding.Finding
}

// Finding returns whichever side is present, preferring the new one. Every
// change has at least one.
func (c Change) Finding() finding.Finding {
	if c.New != nil {
		return *c.New
	}
	return *c.Old
}

// CheckID and Fingerprint identify the change regardless of which side exists.
func (c Change) CheckID() string     { return c.Finding().CheckID }
func (c Change) Fingerprint() string { return c.Finding().Fingerprint }

// Result is the whole comparison.
type Result struct {
	Changes []Change
}

// Of returns the changes in one category, in report order.
func (r Result) Of(c Category) []Change {
	var out []Change
	for _, ch := range r.Changes {
		if ch.Category == c {
			out = append(out, ch)
		}
	}
	return out
}

// Empty reports whether nothing moved.
func (r Result) Empty() bool { return len(r.Changes) == 0 }

// Categories is the order categories are reported in: what needs acting on
// first, then what changed because somebody decided something, then the good
// news.
var Categories = []Category{NewFailure, Regressed, VerdictChanged, NewlySuppressed, Resolved}

// suppressed reports whether an operator accepted this finding.
func suppressed(f *finding.Finding) bool { return f != nil && f.Suppression != nil }

// underlying is the verdict the check actually reached, seeing through a
// suppression to the result recorded beneath it.
func underlying(f *finding.Finding) finding.Result {
	if f == nil {
		return ""
	}
	if f.Suppression != nil {
		return f.Suppression.OriginalResult
	}
	return f.Result
}

// failing reports whether a side is a finding at all — FAIL or UNKNOWN, before
// any suppression is taken into account.
//
// UNKNOWN counts as failing here for the same reason it does everywhere else
// in this codebase: a check that could not tell is not a check that passed, and
// a diff that treated it as one would report "resolved" the morning a file
// became unreadable.
func failing(f *finding.Finding) bool {
	switch underlying(f) {
	case finding.Fail, finding.Unknown:
		return true
	default:
		return false
	}
}

// Compare joins two finding sets by fingerprint and classifies what moved.
//
// The classification is ordered, and the order is what makes it correct. A
// finding that was suppressed and is now failing satisfies both "regressed"
// and "new failure" on a naive reading; it is a regression, because the host
// may not have changed at all — the acceptance lapsed. Testing that case first
// is what stops it being reported as though somebody broke something.
func Compare(old, next []finding.Finding) Result {
	oldByFP := index(old)
	newByFP := index(next)

	var res Result
	add := func(o, n *finding.Finding) {
		if cat, ok := classify(o, n); ok {
			res.Changes = append(res.Changes, Change{Category: cat, Old: o, New: n})
		}
	}

	// Pass one: the fingerprints present on both sides. This is the join
	// proper, and on a well-behaved check it is the only pass that does
	// anything.
	var oldOnly, newOnly []*finding.Finding
	for _, fp := range sortedKeys(oldByFP) {
		if n, ok := newByFP[fp]; ok {
			add(oldByFP[fp], n)
		} else {
			oldOnly = append(oldOnly, oldByFP[fp])
		}
	}
	for _, fp := range sortedKeys(newByFP) {
		if _, ok := oldByFP[fp]; !ok {
			newOnly = append(newOnly, newByFP[fp])
		}
	}

	// Pass two: subject drift.
	//
	// A fingerprint is hash(check_id, subject), and several checks in the
	// catalog set a subject only when they have something to point at — SSHD
	// -0003 reports subject "" when it passes and "PasswordAuthentication"
	// when it fails. The same check on the same host therefore fingerprints
	// differently either side of a verdict change, and a fingerprint-only join
	// sees a finding vanish and an unrelated one appear.
	//
	// The categories stay correct without this pass, but the report reads
	// "ABSENT → FAIL", which tells an operator the check is new when in fact
	// it just started failing. Pairing is deliberately narrow: only when a
	// check has exactly one unmatched finding on each side, which is precisely
	// the host-wide case this affects, and never for a check reporting several
	// subjects at once, where guessing which path became which would be worse
	// than saying nothing.
	oldRest, newRest := pairBySingleton(oldOnly, newOnly, add)
	for _, o := range oldRest {
		add(o, nil)
	}
	for _, n := range newRest {
		add(nil, n)
	}

	// Sorted by category first so a renderer can walk the list once, then by
	// check ID and subject. Nothing here ranges over a map in output order:
	// two diffs of the same pair of bundles must be byte-identical.
	rank := map[Category]int{}
	for i, c := range Categories {
		rank[c] = i
	}
	sort.SliceStable(res.Changes, func(i, j int) bool {
		a, b := res.Changes[i], res.Changes[j]
		if rank[a.Category] != rank[b.Category] {
			return rank[a.Category] < rank[b.Category]
		}
		if a.CheckID() != b.CheckID() {
			return a.CheckID() < b.CheckID()
		}
		return a.Finding().Subject < b.Finding().Subject
	})
	return res
}

// classify decides what one pair of sides represents, and whether it is a
// change at all.
//
// The order is what makes it correct. A finding that was suppressed and is now
// failing satisfies both "regressed" and "new failure" on a naive reading; it
// is a regression, because the host may not have changed at all — the
// acceptance lapsed. Testing that first is what stops it being reported as
// though somebody broke something.
func classify(o, n *finding.Finding) (Category, bool) {
	switch {
	case suppressed(o) && !suppressed(n) && failing(n):
		return Regressed, true
	case !suppressed(o) && suppressed(n):
		return NewlySuppressed, true
	case failing(o) && !failing(n):
		return Resolved, true
	case !failing(o) && failing(n):
		return NewFailure, true
	case failing(o) && failing(n) && underlying(o) != underlying(n):
		return VerdictChanged, true
	default:
		// Unchanged, or a change this diff does not consider one: two passing
		// runs, two identically-suppressed runs, a check that was
		// NOT_APPLICABLE both times.
		return "", false
	}
}

// pairBySingleton joins leftovers whose check ID appears exactly once on each
// side, and returns whatever it could not pair.
func pairBySingleton(oldOnly, newOnly []*finding.Finding, add func(o, n *finding.Finding)) (oldRest, newRest []*finding.Finding) {
	byCheckOld := groupByCheck(oldOnly)
	byCheckNew := groupByCheck(newOnly)

	paired := map[string]bool{}
	for _, id := range sortedCheckIDs(byCheckOld) {
		o, n := byCheckOld[id], byCheckNew[id]
		if len(o) == 1 && len(n) == 1 {
			add(o[0], n[0])
			paired[id] = true
		}
	}
	for _, f := range oldOnly {
		if !paired[f.CheckID] {
			oldRest = append(oldRest, f)
		}
	}
	for _, f := range newOnly {
		if !paired[f.CheckID] {
			newRest = append(newRest, f)
		}
	}
	return oldRest, newRest
}

func groupByCheck(in []*finding.Finding) map[string][]*finding.Finding {
	out := map[string][]*finding.Finding{}
	for _, f := range in {
		out[f.CheckID] = append(out[f.CheckID], f)
	}
	return out
}

func sortedCheckIDs(m map[string][]*finding.Finding) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]*finding.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func index(in []finding.Finding) map[string]*finding.Finding {
	out := make(map[string]*finding.Finding, len(in))
	for i := range in {
		f := in[i]
		out[f.Fingerprint] = &f
	}
	return out
}

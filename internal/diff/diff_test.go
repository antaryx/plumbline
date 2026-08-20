package diff_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/diff"
	"github.com/antaryx/plumbline/internal/finding"
)

// f builds one finding. Fingerprint is derived the way the pipeline derives
// it, so a test that changes a subject changes the fingerprint too — which is
// the behaviour the join has to cope with.
func f(checkID, subject string, result finding.Result) finding.Finding {
	return finding.Finding{
		CheckID: checkID, Module: "SSHD", Title: checkID + " title",
		Result: result, Severity: finding.High, BaseSeverity: finding.High,
		Subject: subject, Fingerprint: finding.Fingerprint(checkID, subject),
	}
}

// accepted marks a finding suppressed, exactly as internal/suppress does.
func accepted(in finding.Finding, why string) finding.Finding {
	in.Suppression = &finding.Suppression{
		Justification: why, OriginalResult: in.Result,
	}
	in.Result = finding.Skipped
	return in
}

// only asserts the comparison produced exactly one change, in the category
// named, and returns it.
func only(t *testing.T, r diff.Result, want diff.Category) diff.Change {
	t.Helper()
	if len(r.Changes) != 1 {
		t.Fatalf("expected exactly one change, got %d: %+v", len(r.Changes), r.Changes)
	}
	if got := r.Changes[0].Category; got != want {
		t.Fatalf("category = %s, want %s", got, want)
	}
	return r.Changes[0]
}

// ---------------------------------------------------------------------------
// the four transitions WP-30 names
// ---------------------------------------------------------------------------

func TestResolved(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  []finding.Finding
		next []finding.Finding
	}{
		{"fail becomes pass",
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)},
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)}},
		{"unknown becomes pass",
			[]finding.Finding{f("SSHD-0002", "", finding.Unknown)},
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)}},
		{"fail becomes not applicable",
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)},
			[]finding.Finding{f("SSHD-0002", "", finding.NotApplicable)}},
		{"the subject stopped existing",
			[]finding.Finding{f("FILESYS-0001", "/usr/bin/old", finding.Fail)},
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			only(t, diff.Compare(tc.old, tc.next), diff.Resolved)
		})
	}
}

func TestNewFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  []finding.Finding
		next []finding.Finding
	}{
		{"pass becomes fail",
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)},
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)}},
		{"pass becomes unknown",
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)},
			[]finding.Finding{f("SSHD-0002", "", finding.Unknown)}},
		{"a new subject appears already failing",
			nil,
			[]finding.Finding{f("FILESYS-0001", "/usr/bin/new", finding.Fail)}},
		{"not applicable becomes fail",
			[]finding.Finding{f("SSHD-0002", "", finding.NotApplicable)},
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			only(t, diff.Compare(tc.old, tc.next), diff.NewFailure)
		})
	}
}

// TestNewlySuppressed. Accepting a risk must never diff as fixing one — the
// two are the opposite of each other in every way that matters to whoever
// reads the report.
func TestNewlySuppressed(t *testing.T) {
	old := []finding.Finding{f("SSHD-0002", "", finding.Fail)}
	next := []finding.Finding{accepted(f("SSHD-0002", "", finding.Fail), "bastion, SEC-4471")}

	c := only(t, diff.Compare(old, next), diff.NewlySuppressed)
	if c.New.Suppression.Justification != "bastion, SEC-4471" {
		t.Errorf("the justification did not survive the join: %+v", c.New.Suppression)
	}
	if c.New.Suppression.OriginalResult != finding.Fail {
		t.Errorf("original_result = %s, want FAIL", c.New.Suppression.OriginalResult)
	}
}

// TestRegressed is the transition that would be misreported by any diff that
// looked only at Result. Both sides are SKIPPED-or-FAIL, and only
// Suppression.OriginalResult distinguishes "the acceptance lapsed" from
// "somebody broke something".
func TestRegressed(t *testing.T) {
	old := []finding.Finding{accepted(f("SSHD-0002", "", finding.Fail), "was temporary")}
	next := []finding.Finding{f("SSHD-0002", "", finding.Fail)}

	c := only(t, diff.Compare(old, next), diff.Regressed)
	if c.Old.Suppression == nil {
		t.Error("the lapsed acceptance is not carried on the old side, so nothing can explain the change")
	}
}

// ---------------------------------------------------------------------------
// the fifth transition, and why it exists
// ---------------------------------------------------------------------------

// TestVerdictChangedIsNotSilent. FAIL and UNKNOWN are both findings, so
// neither RESOLVED nor NEW FAILURE covers a slide between them — but UNKNOWN
// leaves the posture denominator and FAIL does not, so the score moves. A diff
// that reported no change while the posture changed would be contradicting
// itself on the same page.
func TestVerdictChangedIsNotSilent(t *testing.T) {
	old := []finding.Finding{f("SSHD-0002", "", finding.Fail)}
	next := []finding.Finding{f("SSHD-0002", "", finding.Unknown)}

	c := only(t, diff.Compare(old, next), diff.VerdictChanged)
	if c.Old.Result != finding.Fail || c.New.Result != finding.Unknown {
		t.Errorf("both sides are not carried: %+v", c)
	}
	// And the reverse.
	only(t, diff.Compare(next, old), diff.VerdictChanged)
}

// ---------------------------------------------------------------------------
// what must not be reported
// ---------------------------------------------------------------------------

// TestUnchangedFindingsAreNotReported. A diff that prints everything is a
// report, and the whole value here is that an operator can read the output in
// ten seconds at 09:00.
func TestUnchangedFindingsAreNotReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  []finding.Finding
		next []finding.Finding
	}{
		{"two passing runs",
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)},
			[]finding.Finding{f("SSHD-0002", "", finding.Pass)}},
		{"still failing",
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)},
			[]finding.Finding{f("SSHD-0002", "", finding.Fail)}},
		{"still not applicable",
			[]finding.Finding{f("SSHD-0002", "", finding.NotApplicable)},
			[]finding.Finding{f("SSHD-0002", "", finding.NotApplicable)}},
		{"still accepted",
			[]finding.Finding{accepted(f("SSHD-0002", "", finding.Fail), "why")},
			[]finding.Finding{accepted(f("SSHD-0002", "", finding.Fail), "why")}},
		{"a check that passes and never existed before",
			nil,
			[]finding.Finding{f("SSHD-0099", "", finding.Pass)}},
		{"two empty sets",
			nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := diff.Compare(tc.old, tc.next); !got.Empty() {
				t.Errorf("expected no change, got %+v", got.Changes)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// joining the two sets
// ---------------------------------------------------------------------------

// TestSubjectDriftStillPairs is the edge case the fingerprint join cannot
// handle on its own. Several checks set a subject only when they have
// something to point at, so the same check on the same host fingerprints
// differently either side of a verdict change. Without the singleton fallback
// this reports "ABSENT → FAIL", which tells an operator the check is new.
func TestSubjectDriftStillPairs(t *testing.T) {
	old := []finding.Finding{f("SSHD-0003", "", finding.Pass)}
	next := []finding.Finding{f("SSHD-0003", "PasswordAuthentication", finding.Fail)}

	if old[0].Fingerprint == next[0].Fingerprint {
		t.Fatal("the fixture does not actually drift, so this test proves nothing")
	}

	c := only(t, diff.Compare(old, next), diff.NewFailure)
	if c.Old == nil {
		t.Fatal("the old side was dropped; the change reads as a check that did not exist before")
	}
	if c.Old.Result != finding.Pass {
		t.Errorf("old result = %s, want PASS", c.Old.Result)
	}
}

// TestDriftPairingDoesNotGuessBetweenSubjects. The fallback is narrow on
// purpose. A check reporting several paths at once genuinely has one finding
// per path, and pairing "/usr/bin/a went away" with "/usr/bin/b appeared"
// would invent a transition that did not happen.
func TestDriftPairingDoesNotGuessBetweenSubjects(t *testing.T) {
	old := []finding.Finding{
		f("FILESYS-0001", "/usr/bin/a", finding.Fail),
		f("FILESYS-0001", "/usr/bin/b", finding.Fail),
	}
	next := []finding.Finding{
		f("FILESYS-0001", "/usr/bin/c", finding.Fail),
		f("FILESYS-0001", "/usr/bin/d", finding.Fail),
	}

	got := diff.Compare(old, next)
	if len(got.Of(diff.Resolved)) != 2 || len(got.Of(diff.NewFailure)) != 2 {
		t.Fatalf("expected two resolved and two new, got %+v", got.Changes)
	}
	for _, c := range got.Changes {
		if c.Old != nil && c.New != nil {
			t.Errorf("two different subjects were paired into one transition: %+v", c)
		}
	}
}

// TestCompareIsDeterministic. A diff that reorders itself between runs is a
// diff that produces noise in a nightly job, which is the failure this whole
// command exists to avoid.
func TestCompareIsDeterministic(t *testing.T) {
	old := []finding.Finding{
		f("SSHD-0002", "", finding.Fail),
		f("USERS-0001", "", finding.Pass),
		accepted(f("CRON-0001", "/etc/crontab", finding.Fail), "accepted"),
		f("FILESYS-0001", "/usr/bin/x", finding.Fail),
	}
	next := []finding.Finding{
		f("SSHD-0002", "", finding.Pass),
		f("USERS-0001", "", finding.Fail),
		f("CRON-0001", "/etc/crontab", finding.Fail),
		f("KERNEL-0001", "", finding.Unknown),
	}

	first := signature(diff.Compare(old, next))
	for i := 0; i < 20; i++ {
		if got := signature(diff.Compare(old, next)); got != first {
			t.Fatalf("run %d differs from the first:\n %s\n %s", i, first, got)
		}
	}
}

// signature renders a comparison by content. fmt.Sprint over the changes
// themselves would print the pointer addresses in Old and New, which differ
// every run and would make this test fail for a reason that is not the one it
// is looking for.
func signature(r diff.Result) string {
	var b strings.Builder
	for _, c := range r.Changes {
		fmt.Fprintf(&b, "%s|%s|%s|%s→%s\n",
			c.Category, c.CheckID(), c.Finding().Subject,
			side(c.Old), side(c.New))
	}
	return b.String()
}

func side(f *finding.Finding) string {
	if f == nil {
		return "ABSENT"
	}
	if f.Suppression != nil {
		return "SUPPRESSED(" + string(f.Suppression.OriginalResult) + ")"
	}
	return string(f.Result)
}

// TestCategoriesAreOrderedByUrgency. The renderer walks diff.Categories, so
// the constant is the report's running order and worth pinning.
func TestCategoriesAreOrderedByUrgency(t *testing.T) {
	want := []diff.Category{
		diff.NewFailure, diff.Regressed, diff.VerdictChanged,
		diff.NewlySuppressed, diff.Resolved,
	}
	if fmt.Sprint(diff.Categories) != fmt.Sprint(want) {
		t.Errorf("Categories = %v, want %v", diff.Categories, want)
	}
}

// TestOneComparisonCoversEveryCategoryAtOnce. Each transition is asserted in
// isolation above; this one proves they do not interfere when a real host
// moves in several directions overnight.
func TestOneComparisonCoversEveryCategoryAtOnce(t *testing.T) {
	old := []finding.Finding{
		f("SSHD-0002", "", finding.Fail),                      // → resolved
		f("SSHD-0003", "", finding.Pass),                      // → new failure
		f("SSHD-0004", "", finding.Fail),                      // → newly suppressed
		accepted(f("SSHD-0005", "", finding.Fail), "lapsing"), // → regressed
		f("SSHD-0006", "", finding.Fail),                      // → verdict changed
		f("SSHD-0007", "", finding.Pass),                      // → unchanged
	}
	next := []finding.Finding{
		f("SSHD-0002", "", finding.Pass),
		f("SSHD-0003", "", finding.Fail),
		accepted(f("SSHD-0004", "", finding.Fail), "accepted today"),
		f("SSHD-0005", "", finding.Fail),
		f("SSHD-0006", "", finding.Unknown),
		f("SSHD-0007", "", finding.Pass),
	}

	got := diff.Compare(old, next)
	for _, want := range []struct {
		cat diff.Category
		id  string
	}{
		{diff.Resolved, "SSHD-0002"},
		{diff.NewFailure, "SSHD-0003"},
		{diff.NewlySuppressed, "SSHD-0004"},
		{diff.Regressed, "SSHD-0005"},
		{diff.VerdictChanged, "SSHD-0006"},
	} {
		in := got.Of(want.cat)
		if len(in) != 1 || in[0].CheckID() != want.id {
			t.Errorf("%s should hold exactly %s, got %+v", want.cat, want.id, in)
		}
	}
	if len(got.Changes) != 5 {
		t.Errorf("the unchanged check leaked into the diff: %+v", got.Changes)
	}
}

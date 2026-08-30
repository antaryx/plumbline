package text

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// The report's pacing is asserted from inside the package, and that is the
// point of this file existing rather than the assertions living in text_test.go.
//
// **A timing test that actually waits is the worst of both worlds.** It is slow
// — the schedule this file exercises is nine or ten seconds of real sleeping —
// and it is flaky, because a scheduler under `go test -race` is not a stopwatch
// and any bound loose enough to be reliable is too loose to catch a delay
// applied in the wrong place. What matters about the pacing is its *schedule*:
// how many pauses, of which length, at which points in the document. Replacing
// the one indirection the package has for sleeping turns that schedule into
// data a test can read, and the whole file runs in under a millisecond.
//
// The end-to-end proof that the flag reaches this code is somewhere else and
// does pay real time for it: TestTheReportIsPacedOnATerminal in
// internal/cli/pty_internal_test.go.

// recordSleeps replaces the package's sleep with a recorder and returns what it
// collects. The swap is undone by t.Cleanup, and no test in this package runs
// in parallel, which is what makes a package-level variable safe to borrow.
func recordSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var got []time.Duration
	prev := sleep
	sleep = func(d time.Duration) { got = append(got, d) }
	t.Cleanup(func() { sleep = prev })
	return &got
}

// noSleeps makes every pause instant while leaving the schedule in place, for
// the tests that are about the bytes rather than the timing.
func noSleeps(t *testing.T) {
	t.Helper()
	prev := sleep
	sleep = func(time.Duration) {}
	t.Cleanup(func() { sleep = prev })
}

// paceSample is two failures, one unknown, one accepted risk and one collection
// gap: enough that every paced point in the report is reached at least twice.
func paceSample() Input {
	findings := []finding.Finding{
		{
			CheckID: "SSHD-0002", Module: "SSHD", Title: "Root may not log in over SSH",
			Result: finding.Fail, Severity: finding.High,
			Remediation: &finding.Remediation{Summary: "Set PermitRootLogin no and reload sshd."},
			Fingerprint: "aaaa",
		},
		{
			CheckID: "AUTH-0004", Module: "AUTH", Title: "PAM does not accept an empty password",
			Result: finding.Fail, Severity: finding.Critical,
			Remediation: &finding.Remediation{Summary: "Remove nullok from every pam_unix.so auth rule."},
			Fingerprint: "bbbb",
		},
		{
			CheckID: "FILESYS-0010", Module: "FILESYS", Title: "Every uid resolves",
			Result: finding.Unknown, UnknownReason: finding.ReasonAmbiguousState,
			Severity: finding.Medium, Fingerprint: "cccc",
		},
		{
			CheckID: "CRON-0004", Module: "CRON", Title: "cron.allow decides who may schedule work",
			Result: finding.Skipped, Severity: finding.Medium, Fingerprint: "dddd",
			Suppression: &finding.Suppression{
				Justification:  "batch host; the operators list is managed by configuration management",
				OriginalResult: finding.Fail,
			},
		},
		{
			CheckID: "KERNEL-0004", Module: "KERNEL", Title: "IP forwarding is disabled",
			Result: finding.Pass, Severity: finding.Medium, Fingerprint: "eeee",
		},
	}
	started := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	return Input{
		Tool:     Tool{Name: "plumbline", Version: "0.3.0-dev"},
		Scan:     Scan{Started: started, Finished: started.Add(2 * time.Second), Profile: "default"},
		Score:    score.Compute(findings, 34),
		Findings: findings,
		FactErrors: []fact.Error{
			{Fact: "shadow", Kind: fact.ErrPermission, Path: "/etc/shadow", Msg: "permission denied"},
		},
	}
}

// The three paced points, by the count the sample implies.
const (
	// [=] Collection gaps, [=] Warnings and suggestions, [=] Accepted risks,
	// [=] Scan summary. The scan phase's module headings are `[+]` and are not
	// sections; see TestTheScanPhaseIsNotPaced.
	sampleSections = 4
	// Two warnings, one unknown, one accepted risk.
	sampleEntries = 4
)

// TestOnlyATerminalThatAskedForAPaceIsPaced is the gate on the two conditions,
// and it is the one this whole feature turns on.
//
// A delay in a redirected report is not a nicety that happens to be wasted: it
// is `plumbline scan --format terminal > report.txt` in a nightly job taking ten
// seconds longer for nothing, and `plumbline scan | grep WARNING` in somebody's
// shell appearing to hang. Width is 0 for everything that is not a terminal —
// the seam's TerminalWidth answers no for a file, a pipe and a test buffer — so
// the two conditions here are "somebody is looking at this" and "they did not
// turn it off".
func TestOnlyATerminalThatAskedForAPaceIsPaced(t *testing.T) {
	for _, tc := range []struct {
		name  string
		width int
		pace  time.Duration
		paced bool
	}{
		{"a terminal at the default pace", 100, DefaultPace, true},
		{"a terminal at --pace 0", 100, 0, false},
		{"a file at the default pace", 0, DefaultPace, false},
		{"a file at --pace 0", 0, 0, false},
		{"a caller that set neither", 0, 0, false},
		{"a negative pace is not a pace", 100, -time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recordSleeps(t)

			in := paceSample()
			in.Width, in.Pace = tc.width, tc.pace
			if err := Render(&bytes.Buffer{}, in); err != nil {
				t.Fatalf("Render: %v", err)
			}

			if paced := len(*got) > 0; paced != tc.paced {
				t.Errorf("paced=%v, want %v (%d pauses: %v)", paced, tc.paced, len(*got), *got)
			}
		})
	}
}

// TestTheThreeDelaysAreMultiplesOfThePace pins the arithmetic, including the
// numbers the default produces. They are stated here as literals rather than
// recomputed from the constants, because a test that derives the answer the same
// way the code does cannot notice the code deriving it wrongly.
func TestTheThreeDelaysAreMultiplesOfThePace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		width int
		pace  time.Duration
		want  pacer
	}{
		{
			name: "the default", width: 100, pace: DefaultPace,
			want: pacer{section: 600 * time.Millisecond, entry: 80 * time.Millisecond, line: 20 * time.Millisecond},
		},
		{
			name: "--pace 250ms slows the report with the stream", width: 100, pace: 250 * time.Millisecond,
			want: pacer{section: 1500 * time.Millisecond, entry: 200 * time.Millisecond, line: 50 * time.Millisecond},
		},
		{
			name: "--pace 5ms leaves the report as quick as the rows", width: 100, pace: 5 * time.Millisecond,
			want: pacer{section: 30 * time.Millisecond, entry: 4 * time.Millisecond, line: time.Millisecond},
		},
		{name: "no terminal", width: 0, pace: DefaultPace, want: pacer{}},
		{name: "no pace", width: 100, pace: 0, want: pacer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newPacer(tc.width, tc.pace); got != tc.want {
				t.Errorf("newPacer(%d, %s) = %+v, want %+v", tc.width, tc.pace, got, tc.want)
			}
		})
	}
}

// TestNewPacerTakesTheMeasuredWidthAndNotTheClamp is the guard on the one
// mistake that would silently pace every redirect: displayWidth turns a
// non-terminal's 0 into the fixed grid, so a caller that reached for the width
// the layout uses would get 78 and pace a file.
func TestNewPacerTakesTheMeasuredWidthAndNotTheClamp(t *testing.T) {
	if got := newPacer(displayWidth(0), DefaultPace); got == (pacer{}) {
		t.Skip("displayWidth(0) no longer returns a positive width; this guard is moot")
	}
	if got := newPacer(0, DefaultPace); got != (pacer{}) {
		t.Errorf("newPacer(0, %s) = %+v, want the zero pacer: a file must not be paced", DefaultPace, got)
	}
}

// TestEverySectionGetsTheBreathAndEveryEntryTheBeat reads the schedule off the
// document it produced, so it stays true as sections are added.
func TestEverySectionGetsTheBreathAndEveryEntryTheBeat(t *testing.T) {
	got := recordSleeps(t)

	in := paceSample()
	in.Width, in.Pace = 100, DefaultPace

	var buf bytes.Buffer
	if err := Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	want := newPacer(in.Width, in.Pace)
	sections, entries := 0, 0
	for _, d := range *got {
		switch d {
		case want.section:
			sections++
		case want.entry:
			entries++
		default:
			t.Errorf("unrecognised pause of %s; the report paced something this test does not know about", d)
		}
	}

	// At column 0, which is where a heading is. `[=] ` also appears mid-line in
	// the summary's cross-reference to the accepted-risks block, and that is
	// prose rather than a section.
	if headings := headingLines(out); sections != len(headings) {
		t.Errorf("%d section pauses for %d section headings %q", sections, len(headings), headings)
	}
	if sections != sampleSections {
		t.Errorf("%d section pauses, want %d", sections, sampleSections)
	}
	if bullets := len(bulletLines(out)); entries != bullets {
		t.Errorf("%d entry pauses for %d entries: %v", entries, bullets, bulletLines(out))
	}
	if entries != sampleEntries {
		t.Errorf("%d entry pauses, want %d", entries, sampleEntries)
	}
}

// bulletLines are the entry headlines in the warnings, unknown and accepted
// blocks: `  - [HIGH] Title [ID]` and `  * Title [ID]`.
//
// The severity tag is what separates them from a scan-phase row, which wears
// the same bullet and the same indent — `  - Title ....... [ WARNING ]` — and
// is deliberately not paced.
var bulletRe = regexp.MustCompile(`^  (- \[|\* )`)

// headingLines are the top-level section headings, which sit at column 0.
func headingLines(out string) []string {
	var found []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "[=] ") {
			found = append(found, l)
		}
	}
	return found
}

func bulletLines(out string) []string {
	var found []string
	for _, l := range strings.Split(out, "\n") {
		if bulletRe.MatchString(l) {
			found = append(found, l)
		}
	}
	return found
}

// TestTheScanPhaseIsNotPaced.
//
// `eval` renders the whole document, scan phase included, and on a real catalog
// that is a hundred and twelve rows. Pacing them would add eleven seconds to a
// command whose entire purpose is to re-read an archive quickly, and it would
// do it a second time for a `scan` on a terminal that had *already* watched the
// live stream draw the same rows.
func TestTheScanPhaseIsNotPaced(t *testing.T) {
	got := recordSleeps(t)

	in := paceSample()
	in.Width, in.Pace = 100, DefaultPace

	var buf bytes.Buffer
	if err := Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if rows := strings.Count(buf.String(), "[ OK ]") + strings.Count(buf.String(), "[ WARNING ]"); rows == 0 {
		t.Fatal("the scan phase did not render; this test would prove nothing")
	}

	// Every pause is accounted for by a section or an entry, so none of them
	// belongs to a scan-phase row.
	if want := sampleSections + sampleEntries; len(*got) != want {
		t.Errorf("%d pauses, want %d: %v", len(*got), want, *got)
	}
}

// TestPacingChangesNoBytes is the property the nightly diff depends on. A pause
// falls between two writes and never inside one, so the same findings produce
// the same report whether it was watched or piped.
func TestPacingChangesNoBytes(t *testing.T) {
	noSleeps(t)

	in := paceSample()
	in.Width = 100

	var paced, instant bytes.Buffer
	in.Pace = DefaultPace
	if err := Render(&paced, in); err != nil {
		t.Fatalf("Render paced: %v", err)
	}
	in.Pace = 0
	if err := Render(&instant, in); err != nil {
		t.Fatalf("Render unpaced: %v", err)
	}

	if !bytes.Equal(paced.Bytes(), instant.Bytes()) {
		t.Errorf("the paced report differs from the unpaced one:\n--- paced\n%s\n--- unpaced\n%s",
			paced.String(), instant.String())
	}
}

// TestAFailedWriteStopsThePauses.
//
// A closed pipe — `plumbline scan --verbose | head` — ends the report on its
// first write. Every write after that is a no-op, so a schedule that kept being
// honoured would leave the process asleep for ten seconds producing output that
// has nowhere to go.
func TestAFailedWriteStopsThePauses(t *testing.T) {
	got := recordSleeps(t)

	in := paceSample()
	in.Width, in.Pace = 100, DefaultPace
	if err := Render(brokenWriter{}, in); err == nil {
		t.Fatal("Render on a broken writer returned nil")
	}
	if len(*got) != 0 {
		t.Errorf("%d pauses after the descriptor went away: %v", len(*got), *got)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// TestTheScriptWaterfallsALineAtATime covers the third delay, which lives in
// the remediation block rather than the report and therefore has its own entry
// point and its own chance to be wired wrong.
func TestTheScriptWaterfallsALineAtATime(t *testing.T) {
	got := recordSleeps(t)

	script := "#!/bin/sh\nset -eu\n\nsysctl -w net.ipv4.ip_forward=0\nchmod 600 -- /etc/crontab\n"
	in := RemediationInput{
		Covered: 2, Uncovered: 1, Script: script,
		Width: 100, Pace: DefaultPace,
	}
	if err := RenderRemediation(&bytes.Buffer{}, in); err != nil {
		t.Fatalf("RenderRemediation: %v", err)
	}

	want := newPacer(in.Width, in.Pace)
	sections, lines := 0, 0
	for _, d := range *got {
		switch d {
		case want.section:
			sections++
		case want.line:
			lines++
		default:
			t.Errorf("unrecognised pause of %s in the remediation block", d)
		}
	}
	if sections != 1 {
		t.Errorf("%d section pauses, want 1 for `[=] Proposed remediation script`", sections)
	}
	if n := len(strings.Split(strings.TrimRight(script, "\n"), "\n")); lines != n {
		t.Errorf("%d line pauses for a %d-line script", lines, n)
	}
}

// TestTheScriptIsDumpedToAFile is the same separation the report makes, on the
// block that is most likely to be piped somewhere: `--fix > fix.sh`.
func TestTheScriptIsDumpedToAFile(t *testing.T) {
	got := recordSleeps(t)

	if err := RenderRemediation(&bytes.Buffer{}, RemediationInput{
		Covered: 1, Script: "sysctl -w net.ipv4.ip_forward=0\n", Width: 0, Pace: DefaultPace,
	}); err != nil {
		t.Fatalf("RenderRemediation: %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("%d pauses writing the script to a non-terminal: %v", len(*got), *got)
	}
}

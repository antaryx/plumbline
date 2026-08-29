package text_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
)

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// visible is what the terminal actually draws: escape sequences removed and
// the result measured in runes, not bytes. Every assertion about alignment in
// this file goes through it, because measuring the bytes is exactly the mistake
// the layout exists to avoid — `…` is three bytes and one column, and a green
// token is eleven bytes of nothing.
func visible(line string) string { return ansi.ReplaceAllString(line, "") }

func width(line string) int { return len([]rune(visible(line))) }

// fixedWidth is a width function for a terminal that never changes size.
func fixedWidth(n int) func() (int, bool) {
	return func() (int, bool) { return n, true }
}

func streamRows(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(visible(l), "[+] ") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no rows in:\n%s", buf.String())
	}
	return out
}

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{CheckID: "AUTH-0001", Title: "A password quality module is enforced",
			Result: finding.Pass, Severity: finding.Medium},
		{CheckID: "CONTAINERS-0001", Title: "The Docker daemon remaps container users to unprivileged host ranges",
			Result: finding.NotApplicable, Severity: finding.High},
		{CheckID: "KERNEL-0004", Title: "The kernel ring buffer is not readable by unprivileged users",
			Result: finding.Fail, Severity: finding.High},
		{CheckID: "SSHD-0009", Title: "Root login is disabled over SSH",
			Result: finding.Unknown, Severity: finding.Low},
	}
}

// TestEveryRowIsExactlyTheTerminalWidth.
//
// This is the whole claim of the layout and it is asserted at several widths,
// with colour both on and off. Colour is the interesting half: a token carries
// eleven bytes of escape sequence that draw nothing, so a gap computed with len
// rather than visibleWidth would put the coloured rows several columns short
// and the plain ones exactly right — a misalignment that only appears on a real
// terminal, which is the one place no test looks.
func TestEveryRowIsExactlyTheTerminalWidth(t *testing.T) {
	for _, columns := range []int{45, 60, 80, 100, 120} {
		for _, colour := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/colour=%v", columns, colour), func(t *testing.T) {
				var buf bytes.Buffer
				s := text.NewStream(&buf, colour, fixedWidth(columns))
				for _, f := range sampleFindings() {
					s.CheckDone(f)
				}
				s.CollectorDone("containers-service", "ok", 0)

				for _, row := range streamRows(t, &buf) {
					if got := width(row); got != columns {
						t.Errorf("row is %d columns, want %d:\n  %q", got, columns, visible(row))
					}
				}
			})
		}
	}
}

// TestTheTerminalWidthIsReadPerRow.
//
// Resizing mid-scan must reflow from the next row, which is only true if the
// width is asked for every line rather than cached at construction. The width
// function here changes its answer on each call, and the rows have to follow
// it.
func TestTheTerminalWidthIsReadPerRow(t *testing.T) {
	widths := []int{100, 80, 60}
	i := 0
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, func() (int, bool) {
		w := widths[i]
		i++
		return w, true
	})

	for _, f := range sampleFindings()[:3] {
		s.CheckDone(f)
	}

	rows := streamRows(t, &buf)
	for n, row := range rows {
		if got := width(row); got != widths[n] {
			t.Errorf("row %d is %d columns, want %d (the terminal was resized)", n, got, widths[n])
		}
	}
}

// TestTheCheckIDSurvivesEveryWidth.
//
// The ID is what a suppression file matches on and what `plumbline explain`
// takes. A layout that truncates the assembled line eats it first, because it
// is at the end — so a narrow terminal would silently produce rows nobody can
// act on. The title gives way instead, and below the width where even that is
// pointless the row drops to the ID alone.
func TestTheCheckIDSurvivesEveryWidth(t *testing.T) {
	for _, columns := range []int{20, 24, 30, 40, 45, 60, 80, 120} {
		var buf bytes.Buffer
		s := text.NewStream(&buf, false, fixedWidth(columns))
		for _, f := range sampleFindings() {
			s.CheckDone(f)
		}

		text := buf.String()
		for _, f := range sampleFindings() {
			if !strings.Contains(text, f.CheckID) {
				t.Errorf("at %d columns, %s is not in its own row:\n%s", columns, f.CheckID, visible(text))
			}
		}
	}
}

// TestANarrowTerminalIsNotWidenedToFitTheLayout.
//
// An earlier version clamped the layout to a 40-column floor, which on a
// 30-column terminal produced 40-column rows that the terminal then wrapped —
// destroying the column far more thoroughly than a short row would. The rule
// is that a row may exceed the terminal only when even the compact form does
// not fit, and never by much.
func TestANarrowTerminalIsNotWidenedToFitTheLayout(t *testing.T) {
	const columns = 30
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(columns))
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}

	for _, row := range streamRows(t, &buf) {
		// The overflow that remains is the compact row itself: a long ID plus
		// a long token cannot be made shorter without losing one of them.
		if got := width(row); got > columns+8 {
			t.Errorf("row is %d columns on a %d-column terminal:\n  %q", got, columns, visible(row))
		}
	}
}

// TestTheStreamAndTheReportUseOneVocabulary.
//
// The two appear in the same session — the stream on stderr while the scan
// runs, the report on stdout under --verbose — and an operator who watched
// `[ WARNING ]` scroll past must find `[ WARNING ]` when they grep the report.
// The words therefore come from statusToken, which the report also uses, and
// this pins the mapping so a future edit to either cannot split them.
func TestTheStreamAndTheReportUseOneVocabulary(t *testing.T) {
	cases := []struct {
		result finding.Result
		want   string
	}{
		{finding.Pass, "[ OK ]"},
		{finding.Fail, "[ WARNING ]"},
		{finding.Unknown, "[ UNKNOWN ]"},
		{finding.NotApplicable, "[ SKIPPED ]"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		s := text.NewStream(&buf, false, fixedWidth(80))
		s.CheckDone(finding.Finding{CheckID: "T-0001", Title: "t", Result: c.result})
		if !strings.Contains(visible(buf.String()), c.want) {
			t.Errorf("%s rendered as %q, want %s", c.result, visible(buf.String()), c.want)
		}
	}
}

// The colours are the report's in every state but one. NOT_APPLICABLE is dim in
// the report so that rows carrying no verdict do not compete with the three
// that do; in a scrolling stream the same rows read as a display failure rather
// than an answer, so they are cyan — a category of their own, and visibly not a
// warning.
func TestTheStreamColoursItsStates(t *testing.T) {
	cases := []struct {
		result finding.Result
		want   string
	}{
		{finding.Pass, "\x1b[1;38;2;34;197;94m"},         // green
		{finding.Fail, "\x1b[1;38;2;239;68;68m"},         // red
		{finding.Unknown, "\x1b[1;38;2;245;158;11m"},     // amber
		{finding.NotApplicable, "\x1b[38;2;96;165;250m"}, // cyan
	}
	for _, c := range cases {
		var buf bytes.Buffer
		s := text.NewStream(&buf, true, fixedWidth(80))
		s.CheckDone(finding.Finding{CheckID: "T-0001", Title: "t", Result: c.result})
		if !strings.Contains(buf.String(), c.want) {
			t.Errorf("%s drawn as %q, want the sequence %q", c.result, buf.String(), c.want)
		}
	}
}

// --quiet keeps the tally and drops the narration. The counters still count:
// the tally is of what was evaluated, not of what was printed.
func TestQuietDropsTheRowsAndKeepsTheTally(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80)).Quiet(true)
	s.Phase("Evaluating")
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}
	s.CollectorDone("kernel", "ok", 0)
	s.Close(score.Compute(sampleFindings(), 33))

	out := visible(buf.String())
	if strings.Contains(out, "[+] ") {
		t.Errorf("--quiet still narrated:\n%s", out)
	}
	if strings.Contains(out, "[*] Evaluating") {
		t.Errorf("--quiet still announced a phase:\n%s", out)
	}
	if !strings.Contains(out, "1 passed, 1 failed, 1 unknown, 1 not applicable") {
		t.Errorf("--quiet lost the tally it exists to keep:\n%s", out)
	}
}

// Colour off means no escape sequences at all, which is what makes the stream
// safe on a pipe and readable in a captured log.
func TestColourOffEmitsNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	s.Phase("Evaluating")
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}
	s.CollectorDone("kernel", "failed", 2*time.Second)
	s.Close(score.Compute(sampleFindings(), 33))

	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("escape sequences with colour off:\n%q", buf.String())
	}
}

// TestConcurrentCollectorEventsProduceWholeLines.
//
// collect.Runner calls CollectorDone from the collector goroutines and they run
// at once. Without the mutex two of them interleave inside one Fprintf and the
// operator gets a row with another row's token in the middle of it — which the
// race detector would catch on the counters but not on the writer, because a
// bytes.Buffer racing is a corrupted line rather than a panic.
func TestConcurrentCollectorEventsProduceWholeLines(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, true, fixedWidth(80))

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.CollectorDone(fmt.Sprintf("collector-%02d", n), "ok", 0)
		}(i)
	}
	wg.Wait()

	rows := streamRows(t, &buf)
	if len(rows) != 64 {
		t.Fatalf("got %d rows, want 64", len(rows))
	}
	for _, row := range rows {
		if got := width(row); got != 80 {
			t.Errorf("interleaved row (%d columns): %q", got, visible(row))
		}
		if strings.Count(visible(row), "[ DONE ]") != 1 {
			t.Errorf("row carries more than one verdict: %q", visible(row))
		}
	}
}

// TestTheClosingTallyNamesTheFailures.
func TestTheClosingTallyNamesTheFailures(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}
	s.Tally(true)
	s.Hint("Run again with --verbose for detailed evidence and remediation.")
	s.Close(score.Compute(sampleFindings(), 33))

	out := visible(buf.String())
	for _, want := range []string{
		"posture", "coverage",
		"1 passed, 1 failed, 1 unknown, 1 not applicable",
		"KERNEL-0004",
		// A screen with no detail on it reads as a tool that found nothing to
		// say, so the last line always names where the rest went.
		"--verbose",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the tally does not mention %q:\n%s", want, out)
		}
	}
}

// A posture that is undefined must not be printed as zero. score.Score returns
// (value, ok) precisely so that "nothing was evaluated" cannot be rendered as
// "posture 0", and the last line of the stream must not undo that.
func TestAnUndefinedPostureIsNotPrintedAsZero(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	s.Close(score.Compute(nil, 33))

	out := visible(buf.String())
	if strings.Contains(out, "posture 0") {
		t.Errorf("an unevaluated host was scored:\n%s", out)
	}
	if !strings.Contains(out, "no posture") {
		t.Errorf("the tally does not say why there is no score:\n%s", out)
	}
}

// A nil stream is the disabled one, and every method has to tolerate it so
// that the CLI can hold one variable instead of a branch at each call site.
func TestANilStreamIsSilent(t *testing.T) {
	var s *text.Stream
	s.Phase("x")
	s.CheckDone(finding.Finding{CheckID: "T-0001"})
	s.CollectorDone("c", "ok", 0)
	s.Close(score.Compute(nil, 33))
}

// TestTheThreeOutputModes.
//
// The modes are two independent switches and this is the table that says what
// each produces. It exists because the standard mode was wrong twice: first it
// carried the whole detailed report, then it carried the severity tally, and
// both times the effect was the same — the stream the operator asked to watch
// scrolled off the top before the run finished.
//
// What standard mode may contain is therefore stated as a closed list, and the
// tally's absence is asserted rather than assumed.
func TestTheThreeOutputModes(t *testing.T) {
	cases := []struct {
		name              string
		quiet, tally      bool
		wantRows, wantSum bool
		wantTally         bool
	}{
		{"standard", false, false, true, true, false},
		{"--verbose", false, true, true, true, true},
		{"--quiet", true, false, false, true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			s := text.NewStream(&buf, false, fixedWidth(90)).Quiet(c.quiet).Tally(c.tally)
			s.Phase("Collecting host evidence")
			s.CollectorDone("kernel", "ok", 0)
			s.Phase("Evaluating the catalog")
			for _, f := range sampleFindings() {
				s.CheckDone(f)
			}
			s.Close(score.Compute(sampleFindings(), 33))
			out := visible(buf.String())

			if got := strings.Contains(out, "[+] Checking "); got != c.wantRows {
				t.Errorf("evaluation rows present = %v, want %v:\n%s", got, c.wantRows, out)
			}
			if got := strings.Contains(out, "[+] Collecting "); got != c.wantRows {
				t.Errorf("collection rows present = %v, want %v:\n%s", got, c.wantRows, out)
			}
			if got := strings.Contains(out, "[*] Collecting host evidence"); got != c.wantRows {
				t.Errorf("phase headers present = %v, want %v:\n%s", got, c.wantRows, out)
			}
			if got := strings.Contains(out, "[*] Result"); got != c.wantSum {
				t.Errorf("result block present = %v, want %v:\n%s", got, c.wantSum, out)
			}
			// The tally is the line that pushed the stream off the screen.
			if got := strings.Contains(out, "!  HIGH"); got != c.wantTally {
				t.Errorf("severity tally present = %v, want %v:\n%s", got, c.wantTally, out)
			}
		})
	}
}

// The closing block's *length* is asserted end-to-end over a real terminal, in
// internal/cli/pty_internal_test.go, rather than here. A version of that
// assertion lived in this file and was worthless: it constructed a Stream, did
// not call Tally, and concluded that standard mode prints no tally — which is a
// fact about this type and says nothing about whether the scan command sets the
// flag. The line that decides it, Tally(verbose), is in scan.go and was never
// executed.

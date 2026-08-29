package text_test

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
)

// Any CSI sequence, not only the colour ones: the heartbeat writes an
// erase-line, and a test that measured its bytes would be making exactly the
// mistake visible exists to prevent.
var ansi = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// visible is what the terminal actually draws: escape sequences removed and
// the result measured in runes, not bytes. Every assertion about alignment in
// this file goes through it, because measuring the bytes is exactly the mistake
// the layout exists to avoid — `…` is three bytes and one column, and a green
// token is eleven bytes of nothing.
func visible(line string) string {
	return strings.ReplaceAll(ansi.ReplaceAllString(line, ""), "\r", "")
}

func width(line string) int { return len([]rune(visible(line))) }

// fixedWidth is a width function for a terminal that never changes size.
func fixedWidth(n int) func() (int, bool) {
	return func() (int, bool) { return n, true }
}

func streamRows(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(visible(l), "  - ") {
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
				s.Await()

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
	s.Await()

	rows := streamRows(t, &buf)
	for n, row := range rows {
		if got := width(row); got != widths[n] {
			t.Errorf("row %d is %d columns, want %d (the terminal was resized)", n, got, widths[n])
		}
	}
}

// TestAStreamedRowIsATitleAndAVerdict.
//
// **The row used to end ` (AUTH-0001)...` and no longer does**, which reverses
// the contract the test that stood here asserted — that the check ID survived
// every width, because the ID was in the fixed tail and only the title gave.
//
// The reasoning behind that was sound about the ID and wrong about the stream.
// An ID is for copying: into a suppression file, into `plumbline explain`. The
// stream scrolls past at a tenth of a second a row and nothing can be copied
// out of it, while the report underneath carries the ID on every entry and is
// still on screen when the scan ends. So the ID was costing the title columns
// on exactly the terminals where the title had none to spare, to carry a field
// that was already somewhere better.
//
// What a streamed row is now: the verb, the title, and the verdict.
func TestAStreamedRowIsATitleAndAVerdict(t *testing.T) {
	for _, columns := range []int{20, 24, 30, 40, 45, 60, 80, 120} {
		t.Run(fmt.Sprintf("%d", columns), func(t *testing.T) {
			var buf bytes.Buffer
			s := text.NewStream(&buf, false, fixedWidth(columns))
			for _, f := range sampleFindings() {
				s.CheckDone(f)
			}
			s.Await()

			for _, row := range streamRows(t, &buf) {
				line := visible(row)
				for _, f := range sampleFindings() {
					if strings.Contains(line, f.CheckID) {
						t.Errorf("a streamed row still carries a check ID: %q", line)
					}
				}
				if strings.Contains(line, "...") {
					t.Errorf("a streamed row still carries the trailing ellipsis: %q", line)
				}
				if !strings.HasPrefix(line, "  - Checking ") {
					t.Errorf("a row is not `  - Checking <title>`: %q", line)
				}
			}
		})
	}
}

// TestANarrowTerminalIsNotWidenedToFitTheLayout.
//
// An earlier version clamped the layout to a 40-column floor, which on a
// 30-column terminal produced 40-column rows that the terminal then wrapped —
// destroying the column far more thoroughly than a short row would. The rule
// is that a row may exceed the terminal only when there is no room left for
// even one column of title, and then by exactly one.
func TestANarrowTerminalIsNotWidenedToFitTheLayout(t *testing.T) {
	const columns = 30
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(columns))
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}
	s.Await()

	for _, row := range streamRows(t, &buf) {
		if got := width(row); got > columns {
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
		s.Await()
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
		s.Await()
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
	if strings.Contains(out, "  - ") {
		t.Errorf("--quiet still narrated:\n%s", out)
	}
	if strings.Contains(out, "[+] Module:") {
		t.Errorf("--quiet still opened a module section:\n%s", out)
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
// at once. Sixty-four of them here, against a writer only one goroutine is
// allowed to touch: if a row were ever drawn by its producer rather than queued
// for the drawing goroutine, two would interleave inside one Fprintf and the
// operator would get a row with another row's token in the middle of it — which
// the race detector catches on the counters but not on the writer, because a
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
	s.Await()

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

			if got := strings.Contains(out, "  - Checking "); got != c.wantRows {
				t.Errorf("evaluation rows present = %v, want %v:\n%s", got, c.wantRows, out)
			}
			if got := strings.Contains(out, "  - Collecting "); got != c.wantRows {
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

// writeLog records each Write separately.
//
// It is the only way to see the thing the pace exists for. The assembled text
// of a paced row and an unpaced one is byte-identical; what differs is that the
// paced one leaves the terminal holding a title with the cursor after it for a
// beat, and that is visible in the sequence of writes and nowhere else.
type writeLog struct {
	mu sync.Mutex
	w  []string
}

func (l *writeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w = append(l.w, string(p))
	return len(p), nil
}

func (l *writeLog) writes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.w...)
}

func (l *writeLog) text() string { return strings.Join(l.writes(), "") }

// bufferedLog is a writer that holds what it is given until it is flushed,
// recording writes and flushes in one sequence with the moment each happened.
//
// **It stands in for the one thing that would break the pace silently.** A
// buffered writer produces byte-identical output to an unbuffered one; the
// difference is only ever in when the bytes appear, so nothing that inspects
// the text can see it. This can: a flush recorded after the title and before
// the verdict is the property, and its absence is the wall of text.
type bufferedLog struct {
	mu    sync.Mutex
	start time.Time
	held  []byte
	ev    []logEvent
}

type logEvent struct {
	kind string // "write" or "flush"
	text string // what the write carried, or what the flush released
	at   time.Duration
}

func newBufferedLog() *bufferedLog { return &bufferedLog{start: time.Now()} }

func (l *bufferedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = append(l.held, p...)
	l.ev = append(l.ev, logEvent{kind: "write", text: string(p), at: time.Since(l.start)})
	return len(p), nil
}

func (l *bufferedLog) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, logEvent{kind: "flush", text: string(l.held), at: time.Since(l.start)})
	l.held = nil
	return nil
}

func (l *bufferedLog) events() []logEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]logEvent(nil), l.ev...)
}

// TestTheTitleIsFlushedBeforeTheStreamSleeps.
//
// The pace is a delay between two writes, and a delay between two writes shows
// an operator nothing unless the first one has actually reached the screen. On
// os.Stderr — an *os.File, one write(2) per Write — it has, which is why this
// could not be caught by the CLI: the effect works there and would keep working
// until somebody wrapped stderr in a bufio.Writer for an unrelated reason, at
// which point the stream would go back to arriving in complete rows with no
// test anywhere going red. So the guarantee is asserted against a writer that
// does buffer.
//
// Three claims, and the middle one is the whole point:
//
//   - the title is written before the pause;
//   - it is *flushed* before the pause, not merely written;
//   - the flush lands early in the pause rather than at the end of it, which is
//     what distinguishes a flush placed between the two writes from one placed
//     after both.
func TestTheTitleIsFlushedBeforeTheStreamSleeps(t *testing.T) {
	const pace = 300 * time.Millisecond

	log := newBufferedLog()
	s := text.NewStream(log, false, fixedWidth(80)).Pace(pace)
	s.CheckDone(finding.Finding{CheckID: "T-0001", Title: "a check", Result: finding.Pass})
	s.Await()

	ev := log.events()

	// This row is the first of its module, so a heading and its flush precede
	// it. The heading is not what the pace is measured against — see section.
	for len(ev) > 0 && strings.Contains(visible(ev[0].text), "[+] Module:") {
		ev = ev[1:]
	}
	if len(ev) < 2 {
		t.Fatalf("expected a write and a flush before the verdict, got %+v", ev)
	}
	if ev[0].kind != "write" || !strings.HasPrefix(ev[0].text, "  - Checking ") {
		t.Fatalf("the first event is not the title: %+v", ev[0])
	}
	if ev[1].kind != "flush" {
		t.Fatalf("the title was written and not flushed, so nothing was on screen during the pause: %+v", ev)
	}
	if !strings.HasPrefix(ev[1].text, "  - Checking ") || strings.Contains(ev[1].text, "\n") {
		t.Errorf("the flush released something other than the title: %q", ev[1].text)
	}

	// The flush has to be inside the first half of the pause, not at the end of
	// it. A renderer that wrote both halves and flushed afterwards would still
	// produce a flush event — just not one an operator could see anything by.
	if ev[1].at > pace/2 {
		t.Errorf("the title was flushed %s into a %s pace: the flush is after the sleep, not before it", ev[1].at, pace)
	}
	if strings.Contains(visible(ev[1].text), "[ OK ]") {
		t.Errorf("the verdict was already on screen when the pause began: %q", visible(ev[1].text))
	}

	last := ev[len(ev)-1]
	if last.at < pace {
		t.Errorf("the row finished in %s against a pace of %s", last.at, pace)
	}
	if !strings.Contains(visible(last.text), "[ OK ]") {
		t.Errorf("the last event is not the verdict: %+v", last)
	}
}

// TestAPacedRowIsDrawnInTwoHalves.
//
// The title goes out on its own, without a newline; the verdict arrives a beat
// later and completes the line. A single Fprintf followed by a sleep would take
// exactly as long, produce identical bytes, and show the operator nothing —
// which is why this asserts on the writes rather than on the text.
func TestAPacedRowIsDrawnInTwoHalves(t *testing.T) {
	const pace = 40 * time.Millisecond

	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80)).Pace(pace)

	start := time.Now()
	s.CheckDone(finding.Finding{CheckID: "T-0001", Title: "a check", Result: finding.Pass})
	queued := time.Since(start)
	s.Await()
	drawn := time.Since(start)

	if queued > pace/2 {
		t.Errorf("CheckDone took %s to return against a pace of %s: the delay is being charged to the engine", queued, pace)
	}
	if drawn < pace {
		t.Errorf("the row was finished in %s, faster than its own pace of %s", drawn, pace)
	}

	writes := log.writes()

	// Same reason as above: the heading opening the module goes out first and
	// is not part of the row.
	for len(writes) > 0 && strings.Contains(visible(writes[0]), "[+] Module:") {
		writes = writes[1:]
	}
	if len(writes) < 2 {
		t.Fatalf("the row went out in one write, so nothing was ever left on screen waiting: %q", writes)
	}
	first, last := writes[0], writes[len(writes)-1]
	switch {
	case strings.Contains(first, "\n"):
		t.Errorf("the first half ended its line: %q", first)
	case !strings.HasPrefix(first, "  - Checking "):
		t.Errorf("the first half is not the row's title: %q", first)
	case strings.Contains(visible(first), "[ OK ]"):
		t.Errorf("the verdict went out with the title, so the pace showed nothing: %q", first)
	}
	if !strings.Contains(visible(last), "[ OK ]") || !strings.HasSuffix(last, "\n") {
		t.Errorf("the second half is not the verdict and its newline: %q", last)
	}
}

// TestThePaceIsNotChargedToTheEngine.
//
// Fifty rows at a tenth of a second each is five seconds of display. Drawn by
// whoever produced them, that would be five seconds of evaluation — the catalog
// does the whole hundred and nine in about 1.3 ms — and, during collection,
// five seconds of collector goroutines sitting in a sleep instead of reading
// the host. Queuing has to be free.
func TestThePaceIsNotChargedToTheEngine(t *testing.T) {
	const (
		rows = 50
		pace = 100 * time.Millisecond
	)

	s := text.NewStream(io.Discard, false, fixedWidth(80)).Pace(pace)
	defer s.Stop()

	start := time.Now()
	for i := range rows {
		s.CheckDone(finding.Finding{
			CheckID: fmt.Sprintf("T-%04d", i), Title: "a check", Result: finding.Pass,
		})
	}
	elapsed := time.Since(start)

	// One row's pace is a generous ceiling for fifty appends under a mutex, and
	// it is below the two that a single synchronous draw would already cost.
	if elapsed > pace {
		t.Errorf("%d checks took %s to queue against a pace of %s: the engine is waiting for the display",
			rows, elapsed, pace)
	}
}

// TestStopFinishesTheLineItIsOn.
//
// Ctrl-C during a paced stream cuts the wait short, and the row that was
// half-drawn when it arrived gets its verdict anyway. Abandoning it would leave
// the operator's shell prompt appended to a plumbline row.
func TestStopFinishesTheLineItIsOn(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80)).Pace(time.Hour)
	s.CheckDone(finding.Finding{CheckID: "T-0001", Title: "a check", Result: finding.Pass})

	// Wait for the title to reach the terminal, so that Stop lands in the pause
	// rather than before the row was picked up at all.
	deadline := time.Now().Add(5 * time.Second)
	for len(log.writes()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the row never reached the writer")
		}
		time.Sleep(time.Millisecond)
	}

	done := make(chan struct{})
	go func() { defer close(done); s.Stop() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop waited out the pace instead of cutting it short")
	}

	out := log.text()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("Stop left half a row on the terminal: %q", out)
	}
	if !strings.Contains(visible(out), "[ OK ]") {
		t.Errorf("Stop dropped the verdict of the row it was drawing: %q", visible(out))
	}
}

// TestTheRendererDefaultsToNoPace.
//
// The delay is the CLI's decision, not this package's. A renderer that slept by
// default would put eighteen seconds into every test that draws a row and into
// any future caller that never asked to be slowed down; DefaultPace is a
// constant for the flag to reach for, not a field value.
func TestTheRendererDefaultsToNoPace(t *testing.T) {
	s := text.NewStream(io.Discard, false, fixedWidth(80))
	defer s.Stop()

	start := time.Now()
	for _, f := range sampleFindings() {
		s.CheckDone(f)
	}
	s.Await()

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("an unpaced stream took %s to draw %d rows", elapsed, len(sampleFindings()))
	}
}

// section is one module heading and the rows drawn under it.
type section struct {
	module string
	rows   []string
}

// sections parses the stream back into the shape it draws: a run of headings,
// each followed by its rule and its rows.
//
// It asserts the frame as it goes — a row before any heading, or a heading
// without its rule under it, is a broken display and there is no point carrying
// it forward into a comparison of check IDs.
func sections(t *testing.T, out string) []section {
	t.Helper()

	var got []section
	lines := strings.Split(visible(out), "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "[+] Module: "):
			module := strings.TrimPrefix(line, "[+] Module: ")
			if i+1 >= len(lines) || strings.Trim(lines[i+1], "-") != "" || lines[i+1] == "" {
				next := ""
				if i+1 < len(lines) {
					next = lines[i+1]
				}
				t.Errorf("the heading for %s is not underlined; the line below it is %q", module, next)
			}
			got = append(got, section{module: module})
		case strings.HasPrefix(line, "  - "):
			if len(got) == 0 {
				t.Errorf("a row was drawn before any module heading: %q", line)
				continue
			}
			got[len(got)-1].rows = append(got[len(got)-1].rows, line)
		case strings.HasPrefix(line, "[+] "):
			t.Errorf("a row is still drawn with the report's module marker: %q", line)
		}
	}
	return got
}

// contains reports whether every id appears, in order, one per row.
func rowIDs(rows []string) string { return strings.Join(rows, "\n") }

// TestRowsAreGroupedUnderTheirModule.
//
// The display is a hierarchy and not a list: a heading per module, a rule under
// the heading, and the module's checks indented beneath it. This asserts the
// whole frame at once — which headings, in what order, and which rows landed
// under each — because the three are one claim. A heading in the right place
// with the wrong rows under it is not a partial success.
func TestRowsAreGroupedUnderTheirModule(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	// The rows no longer carry their check ID, so each one is identified here
	// by a distinct title — which is what an operator watching identifies it by
	// too.
	for _, id := range []string{"AUTH-0001", "AUTH-0002", "KERNEL-0004", "KERNEL-0007", "SSHD-0009"} {
		s.CheckDone(finding.Finding{CheckID: id, Title: "the check called " + id, Result: finding.Pass})
	}
	s.Await()

	got := sections(t, buf.String())
	want := []section{
		{"AUTH", []string{"the check called AUTH-0001", "the check called AUTH-0002"}},
		{"KERNEL", []string{"the check called KERNEL-0004", "the check called KERNEL-0007"}},
		{"SSHD", []string{"the check called SSHD-0009"}},
	}
	if len(got) != len(want) {
		t.Fatalf("drew %d module sections, want %d:\n%s", len(got), len(want), visible(buf.String()))
	}
	for i, w := range want {
		if got[i].module != w.module {
			t.Errorf("section %d is %q, want %q", i, got[i].module, w.module)
			continue
		}
		if len(got[i].rows) != len(w.rows) {
			t.Errorf("%s holds %d rows, want %d:\n%s", w.module, len(got[i].rows), len(w.rows), rowIDs(got[i].rows))
			continue
		}
		for j, id := range w.rows {
			if !strings.Contains(got[i].rows[j], id) {
				t.Errorf("row %d under %s is %q, want %q", j, w.module, got[i].rows[j], id)
			}
		}
	}
}

// TestAModuleIsReopenedRatherThanMisfiled.
//
// The drawing goroutine has no lookahead — it compares the row in its hand
// against the module already on screen, because it cannot see what is queued
// behind it and must not print a heading for a module a Ctrl-C is about to
// cancel. The cost of that is this: an out-of-order catalog would open AUTH
// twice rather than once.
//
// **That is the right failure and it is worth pinning as one.** The alternative
// — remembering every module already seen and suppressing the second heading —
// files rows under a heading several screens above them, which is a display
// that lies. Reopening is visibly odd and points straight at the catalog
// ordering that caused it.
func TestAModuleIsReopenedRatherThanMisfiled(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	for _, id := range []string{"AUTH-0001", "KERNEL-0004", "AUTH-0002"} {
		s.CheckDone(finding.Finding{CheckID: id, Title: "a check", Result: finding.Pass})
	}
	s.Await()

	got := sections(t, buf.String())
	if len(got) != 3 {
		t.Fatalf("drew %d sections, want 3 (AUTH, KERNEL, AUTH):\n%s", len(got), visible(buf.String()))
	}
	for i, want := range []string{"AUTH", "KERNEL", "AUTH"} {
		if got[i].module != want {
			t.Errorf("section %d is %q, want %q", i, got[i].module, want)
		}
	}
	for i, sec := range got {
		if len(sec.rows) != 1 {
			t.Errorf("section %d (%s) holds %d rows, want 1: a row was filed under the wrong heading",
				i, sec.module, len(sec.rows))
		}
	}
}

// TestCollectorRowsBelongToNoModule.
//
// A collector is not a check and has no module, so the collection phase is a
// flat run of rows under its phase header. The two failures this rules out are
// a heading with an empty name — which is what a naive "the module changed"
// test produces on the first collector row — and a collector row silently
// clearing the module, so that the check after it reprints a heading that is
// already on screen.
func TestCollectorRowsBelongToNoModule(t *testing.T) {
	var buf bytes.Buffer
	s := text.NewStream(&buf, false, fixedWidth(80))
	s.Phase("Collecting host evidence")
	s.CollectorDone("kernel", "ok", 0)
	s.CollectorDone("sshd", "ok", 0)
	s.Phase("Evaluating the catalog")
	s.CheckDone(finding.Finding{CheckID: "AUTH-0001", Title: "a check", Result: finding.Pass})
	s.CheckDone(finding.Finding{CheckID: "AUTH-0002", Title: "a check", Result: finding.Pass})
	s.Await()

	out := visible(buf.String())
	if strings.Contains(out, "[+] Module: \n") || strings.Contains(out, "[+] Module: -") {
		t.Errorf("a collector opened a module with no name:\n%s", out)
	}
	if n := strings.Count(out, "[+] Module: "); n != 1 {
		t.Errorf("drew %d module headings for two collectors and one module, want 1:\n%s", n, out)
	}

	// The collector rows are above the first heading, and the check rows below
	// it. Anything else means the heading was placed by row order rather than
	// by module.
	heading := strings.Index(out, "[+] Module: AUTH")
	switch {
	case heading < 0:
		t.Fatalf("no AUTH heading:\n%s", out)
	case strings.Index(out, "  - Collecting kernel") > heading:
		t.Errorf("a collector row was drawn inside the AUTH section:\n%s", out)
	case strings.Index(out, "  - Checking") < heading:
		t.Errorf("a check row was drawn above its own heading:\n%s", out)
	}
}

// TestTheModuleRuleNeverOutgrowsTheTerminal.
//
// The rule under a heading is a fixed 51 columns, because one that reached the
// right margin would compete with the column of brackets it is introducing. A
// terminal narrower than that gets a shorter rule rather than a wrapped one:
// a rule that wraps is two rules, and it puts a stray line of dashes between a
// heading and its first row.
func TestTheModuleRuleNeverOutgrowsTheTerminal(t *testing.T) {
	for _, c := range []struct {
		columns int
		rule    int
	}{
		{120, 51}, {80, 51}, {51, 51}, {40, 40}, {24, 24},
	} {
		t.Run(fmt.Sprintf("%d", c.columns), func(t *testing.T) {
			var buf bytes.Buffer
			s := text.NewStream(&buf, false, fixedWidth(c.columns))
			s.CheckDone(finding.Finding{CheckID: "AUTH-0001", Title: "a check", Result: finding.Pass})
			s.Await()

			for _, line := range strings.Split(visible(buf.String()), "\n") {
				if strings.HasPrefix(line, "---") {
					if got := width(line); got != c.rule {
						t.Errorf("the rule is %d columns on a %d-column terminal, want %d", got, c.columns, c.rule)
					}
					return
				}
			}
			t.Errorf("no rule under the heading:\n%s", visible(buf.String()))
		})
	}
}

// sgr is the colour half of the escapes: the sequences that change how a rune
// is drawn without moving the cursor.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// screen replays writes the way a terminal would, and returns what would be on
// it.
//
// **The heartbeat is the only thing in this package whose correctness is a
// claim about the cursor**, and a test that inspected the bytes could not see
// it: `\r` + erase + a row is, as a string, the heartbeat followed by the row,
// and reads as corruption. On a terminal it is the row alone. So the assertions
// that matter go through this.
//
// It understands exactly what the renderer emits: `\n` starts a line, `\r`
// returns to column 0, ESC[2K clears the line the cursor is on, and anything
// else overwrites from the cursor. ESC[2K leaves the cursor where it was, which
// here is always column 0 because the renderer always sends `\r` first.
func screen(raw string) []string {
	var (
		lines []string
		cur   []rune
		col   int
	)
	src := []rune(sgr.ReplaceAllString(raw, ""))
	for i := 0; i < len(src); i++ {
		switch {
		case src[i] == '\n':
			lines = append(lines, string(cur))
			cur, col = nil, 0
		case src[i] == '\r':
			col = 0
		case src[i] == '\033' && i+3 < len(src) && string(src[i:i+4]) == "\033[2K":
			cur = nil
			i += 3
		default:
			for col >= len(cur) {
				cur = append(cur, ' ')
			}
			cur[col] = src[i]
			col++
		}
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return lines
}

// beats returns the heartbeat writes, in order, as the terminal would draw
// them. A write that only erases is not a beat; it is the erase.
func (l *writeLog) beats() []string {
	var out []string
	for _, w := range l.writes() {
		if text := visible(w); strings.Contains(text, "Still working") {
			out = append(out, text)
		}
	}
	return out
}

// awaitBeat waits for the heartbeat to reach the writer, or fails.
func awaitBeat(t *testing.T, log *writeLog, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, b := range log.beats() {
			if strings.Contains(b, want) {
				return b
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no heartbeat naming %q in:\n%q", want, log.writes())
	return ""
}

// TestTheHeartbeatCoversASlowCollector.
//
// The freeze this exists for: twelve cheap collectors finish in milliseconds,
// one filesystem walk takes twenty-four seconds with a cold page cache, and
// rows are written on completion — so the terminal held still for
// twenty-four seconds and looked like a tool that had crashed.
//
// The heartbeat is the display's answer to having nothing to draw. It names the
// collector actually responsible, not "working…", because the operator's
// question is which one.
func TestTheHeartbeatCoversASlowCollector(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))
	defer s.Stop()

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")

	beat := awaitBeat(t, log, "fswalk")
	if !strings.HasPrefix(beat, "[~] Still working: fswalk") {
		t.Errorf("the heartbeat does not read as one: %q", beat)
	}
}

// TestTheHeartbeatNamesTheSlowestCollector.
//
// Several collectors can be in flight, and only one of them is the answer. The
// one that has been running longest is what the screen is waiting for; the
// others are counted, not listed, because a line that named all of them would
// be the thing that wraps.
func TestTheHeartbeatNamesTheSlowestCollector(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))
	defer s.Stop()

	s.CollectorStarted("fswalk")
	time.Sleep(20 * time.Millisecond)
	s.CollectorStarted("users")
	s.CollectorStarted("network")
	s.Phase("Collecting host evidence")

	beat := awaitBeat(t, log, "fswalk")
	if !strings.Contains(beat, "and 2 more") {
		t.Errorf("the heartbeat did not count the other collectors: %q", beat)
	}
	if strings.Contains(beat, "users") || strings.Contains(beat, "network") {
		t.Errorf("the heartbeat listed every collector instead of the slowest: %q", beat)
	}
}

// TestTheHeartbeatNeverEndsALine.
//
// **This is the whole cursor discipline in one assertion.** The heartbeat lives
// on the line the next row is going to be drawn on, and gets off it with a
// carriage return and an erase. A newline anywhere in it would leave the line
// behind on the screen permanently, and every erase after that would be
// clearing the wrong line — which is the failure mode a cursor-up would have
// had to work around instead.
func TestTheHeartbeatNeverEndsALine(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))
	defer s.Stop()

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")
	awaitBeat(t, log, "fswalk")

	for _, w := range log.writes() {
		if strings.Contains(w, "Still working") && strings.Contains(w, "\n") {
			t.Errorf("a heartbeat ended its line: %q", w)
		}
	}
}

// TestTheHeartbeatIsErasedBeforeTheRowThatFollowsIt.
//
// A row has to start at column 0 of a clean line or its right-aligned bracket
// is aligned against a line that already has a spinner on it. The erase is what
// guarantees that, and it has to be its own write before the row's — a row
// drawn over the heartbeat without erasing first leaves the tail of the longer
// string behind.
func TestTheHeartbeatIsErasedBeforeTheRowThatFollowsIt(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")
	awaitBeat(t, log, "fswalk")

	s.CollectorDone("fswalk", "ok", 24*time.Second)
	s.Await()
	s.Stop()

	// The last beat, then an erase, then the row: nothing may be drawn between
	// the heartbeat and the erase that takes it off.
	writes := log.writes()
	last := -1
	for i, w := range writes {
		if strings.Contains(w, "Still working") {
			last = i
		}
	}
	if last < 0 || last+1 >= len(writes) {
		t.Fatalf("no write followed the last heartbeat: %q", writes)
	}
	if got := writes[last+1]; visible(got) != "" {
		t.Errorf("the write after the last heartbeat is not a bare erase: %q", got)
	}

	// And what the terminal is left holding is a whole row on a clean line —
	// replayed as a terminal would, not read as bytes.
	for _, line := range screen(log.text()) {
		if strings.Contains(line, "[ DONE ]") {
			if strings.Contains(line, "Still working") {
				t.Errorf("the row was drawn on top of the heartbeat: %q", line)
			}
			if width(line) != 80 {
				t.Errorf("the row after a heartbeat is %d columns, want 80: %q", width(line), line)
			}
			return
		}
	}
	t.Errorf("no collector row on the terminal:\n%q", screen(log.text()))
}

// TestTheHeartbeatNeverSplitsARow.
//
// A paced row is a title, a pause, and a verdict, and the pause is the longest
// window in the display with the cursor sitting mid-line. A heartbeat drawn
// into it would erase the title and put the verdict on the end of a spinner.
//
// It cannot happen, and the reason is structural rather than careful: the
// heartbeat is drawn by the same goroutine that draws rows, from the top of its
// loop, so while a row is in its pause that goroutine is inside draw and not
// anywhere near a heartbeat. This asserts the property that the structure buys.
func TestTheHeartbeatNeverSplitsARow(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80)).Pace(500 * time.Millisecond)

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")
	awaitBeat(t, log, "fswalk")

	s.CheckDone(finding.Finding{CheckID: "AUTH-0001", Title: "a check", Result: finding.Pass})
	s.Await()
	s.Stop()

	// Walk the writes and fail on a heartbeat that lands between a title and
	// its verdict.
	open := false
	for _, w := range log.writes() {
		text := visible(w)
		switch {
		case strings.Contains(text, "Still working"):
			if open {
				t.Fatalf("a heartbeat was drawn inside a half-finished row: %q", log.writes())
			}
		case strings.HasPrefix(text, "  - ") && !strings.HasSuffix(text, "\n"):
			open = true
		case strings.HasSuffix(text, "\n"):
			open = false
		}
	}
}

// TestTheHeartbeatStopsWhenNothingIsRunning.
//
// The heartbeat is a statement about the host, not a decoration. When the last
// collector finishes there is nothing to be waiting for, and a spinner still
// turning under the evaluation rows would be saying something false about a
// scan that had moved on.
func TestTheHeartbeatStopsWhenNothingIsRunning(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))
	defer s.Stop()

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")
	awaitBeat(t, log, "fswalk")

	s.CollectorDone("fswalk", "ok", time.Second)
	s.Await()

	before := len(log.beats())
	time.Sleep(400 * time.Millisecond) // several beat intervals
	if after := len(log.beats()); after != before {
		t.Errorf("%d more heartbeats after the last collector finished", after-before)
	}
}

// TestTheHeartbeatNeverOutgrowsTheTerminal.
//
// A heartbeat wider than the window wraps onto a second screen line, and the
// erase only reaches the line the cursor is on — so half a spinner would be
// left above every row for the rest of the scan. Truncation is the fix, and it
// is the same truncate the rows use.
func TestTheHeartbeatNeverOutgrowsTheTerminal(t *testing.T) {
	for _, columns := range []int{20, 30, 40, 80} {
		t.Run(fmt.Sprintf("%d", columns), func(t *testing.T) {
			log := &writeLog{}
			s := text.NewStream(log, false, fixedWidth(columns))
			defer s.Stop()

			s.CollectorStarted("containers-service-with-a-very-long-name")
			s.CollectorStarted("another-one")
			s.Phase("Collecting host evidence")

			deadline := time.Now().Add(5 * time.Second)
			for len(log.beats()) == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			beats := log.beats()
			if len(beats) == 0 {
				t.Fatal("no heartbeat")
			}
			for _, b := range beats {
				if got := len([]rune(b)); got > columns {
					t.Errorf("a heartbeat is %d columns on a %d-column terminal: %q", got, columns, b)
				}
			}
		})
	}
}

// TestStopLeavesNoHeartbeatOnTheTerminal.
//
// Ctrl-C during a slow collector, and the closing block written straight after.
// A heartbeat still on the last line would have the result block appended to it
// — `[~] Still working: fswalk (24s) /[*] Result posture …` — because nothing
// after this point writes a newline first. Stop takes it off on the way out.
func TestStopLeavesNoHeartbeatOnTheTerminal(t *testing.T) {
	log := &writeLog{}
	s := text.NewStream(log, false, fixedWidth(80))

	s.CollectorStarted("fswalk")
	s.Phase("Collecting host evidence")
	awaitBeat(t, log, "fswalk")

	s.Close(score.Compute(nil, 33))

	lines := screen(log.text())
	for _, line := range lines {
		if strings.Contains(line, "Still working") {
			t.Errorf("a heartbeat survived onto the finished terminal: %q\n%q", line, lines)
		}
		if strings.Contains(line, "Still working") && strings.Contains(line, "[*] Result") {
			t.Errorf("the closing block was appended to the heartbeat line: %q", line)
		}
	}
	var found bool
	for _, line := range lines {
		if strings.HasPrefix(line, "[*] Result") {
			found = true
		}
	}
	if !found {
		t.Errorf("no result block on its own line:\n%q", lines)
	}
}

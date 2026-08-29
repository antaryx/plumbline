package text

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// The live stream is the second thing this package draws and it obeys a
// different rule from the first, so the difference is worth stating before the
// code.
//
// **The report is a record and the stream is a view.** The report goes to
// stdout on a grid fixed at reportWidth, because two runs over an unchanged
// host have to be byte-identical or a nightly diff is noise. The stream goes to
// **stderr** as the scan happens, is never redirected into a file anybody
// diffs, and is gone as soon as the terminal scrolls — so it is laid out
// against the width the terminal actually has, and a resize mid-scan reflows
// the lines that have not been written yet.
//
// That split is what lets both be right. A report that followed the window
// would produce a different artifact on a laptop and in CI; a progress display
// pinned to 78 columns would leave a third of a wide terminal empty and would
// mangle a narrow one.
//
// **Nothing here may write to stdout.** The stream is handed one io.Writer by
// the CLI and the CLI hands it stderr, which is what keeps `--format json` a
// document and nothing else — the same construction the scoring notice uses.

// Stream widths.
//
// **The ceiling is a judgement and worth naming as one.** Flush-right on a
// 240-column terminal puts the title at the far left and the verdict four feet
// away, and the eye cannot associate them — the column an operator scans stops
// being scannable. 120 is wide enough that nothing realistic truncates and
// close enough that the two halves of a row still read as one row.
//
// **The floor is not a layout width**, and an earlier version of this got that
// wrong. Laying out to 40 on a 30-column terminal does not protect the column;
// it produces 40-column rows that the terminal wraps, which destroys the column
// far more thoroughly than a short row would. So the layout follows the
// terminal all the way down, and what gives way instead is how much of the row
// is drawn — see the compact form in row. The floor is only a guard against
// arithmetic on an absurd number.
const (
	streamMinWidth = 20
	streamMaxWidth = 120

	// streamMinTitle is the narrowest a title may be squeezed to before the
	// row drops to its compact form. Below about this, a truncated sentence is
	// two letters and an ellipsis — it costs a third of the line and conveys
	// nothing that the check ID beside it does not convey better.
	streamMinTitle = 8

	// streamFallbackWidth is used only when the caller offers no width function
	// at all, which in practice is a test. A real caller that cannot measure
	// the terminal does not construct a Stream.
	streamFallbackWidth = 80
)

// DefaultPace is how long a row's title sits alone on the terminal before its
// verdict lands beside it.
//
// **This is a deliberate delay in a security tool and it deserves a straight
// explanation rather than a shrug.** The catalog evaluates 109 checks in about
// 1.3 ms. Printed at that speed the stream is not a stream: it is a wall of
// text that is already complete before the eye has fixed on anything, and an
// operator learns nothing from watching it that the closing two lines would not
// have told them faster. A row-by-row display is only worth having if a row can
// be read while it is on screen, and that is a property of the display, not of
// the work.
//
// 150 ms is where this settled. Below roughly 80 ms the column of brackets
// reads as flicker rather than as a sequence; above roughly 250 ms the wait
// stops feeling like a scan and starts feeling like a progress bar somebody
// forgot to finish. At 150 ms a hundred and twenty-odd rows — thirteen
// collectors and a hundred and nine checks on this host — take a little over
// eighteen seconds, which is the right order of magnitude for something calling
// itself an audit and short enough to sit through.
//
// **It is presentation and it is never mistaken for work.** Nothing is measured
// through it and nothing waits behind it: the pace is paid by the drawing
// goroutine, after the engine has already finished and moved on (see emit). It
// is charged only where a person is watching — a pipe, a redirect, a CI log and
// --quiet all skip the rows entirely and skip the delay with them — and
// `--pace 0` removes it for anybody who wants the answer rather than the show.
const DefaultPace = 150 * time.Millisecond

// Stream draws a scan as it happens: one line per collector and one per check,
// each with its verdict flush against the right edge of the terminal.
//
// It satisfies both observer interfaces — catalog.Observer for checks and
// collect.Observer for collectors — because they describe two halves of one
// scan and an operator watching wants one column of brackets, not two
// unrelated displays. The two are called from different concurrency regimes:
// checks come from one goroutine in deterministic order, collectors from
// several at once in whatever order they finish. Neither writes anything: both
// queue, under the mutex, and a single goroutine draws. That is what makes the
// interleaving safe — no line can be half-written by one goroutine and finished
// by another, because only one goroutine ever writes.
//
// **Nothing on the caller's side ever writes to the terminal.** Every method
// here queues an event and returns; one goroutine owns the writer and draws
// them in order, which is what lets a row be paced without the pace landing on
// whoever produced it. See emit.
type Stream struct {
	mu     sync.Mutex
	w      io.Writer
	colour bool

	// width is asked freshly for every line rather than cached, so a terminal
	// resized during a scan reflows from the next line. See
	// system.TerminalWidth for why this is not a SIGWINCH handler.
	width func() (int, bool)

	// quiet suppresses the per-row narration; tally adds the list of failures
	// by severity. They are independent, and between them they are the three
	// output modes (CLI-SPEC.md §7):
	//
	//	standard   quiet=false tally=false   the stream, then two lines
	//	--verbose  quiet=false tally=true    the stream, then the failures
	//	--quiet    quiet=true  tally=false   two lines
	//
	// Both are properties of the stream rather than branches at each call site,
	// because the counters have to keep counting either way: the closing block
	// is a tally of what was evaluated, not of what was printed.
	quiet bool
	tally bool

	// pace is the delay between the two halves of a row. See DefaultPace.
	pace time.Duration

	// The queue, and the single goroutine that empties it.
	//
	// **It is an unbounded slice and not a buffered channel, deliberately.** A
	// channel blocks its sender once its capacity is reached, and at 150 ms a
	// row the queue reaches the whole catalog's depth within a millisecond of
	// evaluation starting — so any capacity small enough to be worth writing
	// down would hand the delay straight back to the engine, which is the one
	// thing this structure exists to prevent. A capacity larger than the
	// catalog is a number somebody has to remember every time a check is added.
	// Unbounded has neither problem, and the bound that actually matters is
	// arithmetic rather than a constant: one event per collector, one per
	// check, both known and both small.
	//
	// work wakes the drawing goroutine when something is queued or when it is
	// told to stop; idle wakes Await when a row has finished being drawn.
	pending  []event
	queued   int
	drawn    int
	running  bool
	stopped  bool
	halt     chan struct{}
	finished chan struct{}
	work     *sync.Cond
	idle     *sync.Cond

	// Tallies, for the closing line. Kept here rather than recomputed from the
	// findings because the stream is a view of what it actually showed: if a
	// check never reached the stream, it is not in the stream's count, and a
	// discrepancy with the report is then visible rather than papered over.
	counts map[finding.Result]int
	failed []finding.Finding

	// hint is the closing line telling the operator where the detail is.
	hint string
}

// NewStream builds a stream writing to w.
//
// width is injected rather than read from w so that a test can lay out a line
// at eighteen columns without owning a terminal, and so that this package
// keeps its promise not to touch the OS. A nil width function means
// streamFallbackWidth.
func NewStream(w io.Writer, colour bool, width func() (int, bool)) *Stream {
	s := &Stream{
		w: w, colour: colour, width: width,
		counts: map[finding.Result]int{},
		halt:   make(chan struct{}),
	}
	s.work = sync.NewCond(&s.mu)
	s.idle = sync.NewCond(&s.mu)
	return s
}

// event is one thing the drawing goroutine has to put on the screen: a section
// header, or a row.
//
// The pace travels with the event rather than being read when the event is
// drawn, so that the field is written and read under the same lock and a scan
// cannot appear to change speed halfway down the screen.
type event struct {
	phase string
	row   row
	pace  time.Duration
}

// Pace sets the delay between a row's title and its verdict; zero draws as fast
// as the scan runs. It returns the stream so a caller can chain it, and belongs
// at construction — an event already queued carries the pace it was queued
// with.
func (s *Stream) Pace(d time.Duration) *Stream {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pace = d
	return s
}

// Quiet suppresses the per-row narration, leaving the closing block. It returns
// the stream so a caller can write NewStream(...).Quiet(flag).
func (s *Stream) Quiet(quiet bool) *Stream {
	if s == nil {
		return nil
	}
	s.quiet = quiet
	return s
}

// Tally adds the list of failures by severity to the closing block.
//
// **It is off by default and that is the whole point of this file.** The list
// is one line per failing check — eleven on a fixture, forty on a real host —
// and it lands after the stream, so on any ordinary terminal it is the only
// thing still on screen when the scan ends. The stream an operator asked to
// watch scrolls away above it. The count in the Result block already says how
// many failed; which ones is a question --verbose answers.
func (s *Stream) Tally(tally bool) *Stream {
	if s == nil {
		return nil
	}
	s.tally = tally
	return s
}

// Phase announces a section of the scan. It is the only line in the stream
// that is not a result.
//
// It goes through the queue like everything else, which is the only way it can
// stay above the rows it introduces: a header written directly would appear
// while the previous phase was still being drawn.
func (s *Stream) Phase(name string) {
	if s == nil {
		return
	}
	s.emit(event{phase: name})
}

// CollectorDone implements collect.Observer. It is called from the collector
// goroutines, concurrently.
func (s *Stream) CollectorDone(id string, status string, took time.Duration) {
	if s == nil {
		return
	}
	token, colour := collectorToken(status)

	// The elapsed time is shown only where it is information. Every collector
	// on a small host finishes in single-digit milliseconds and a column of
	// "(0ms)" is furniture; a walk that took forty seconds is the answer to
	// the question the operator is actually asking.
	label := ""
	if took >= time.Second {
		label = fmt.Sprintf(" (%ds)", int(took.Seconds()))
	}

	s.emit(event{row: row{
		head: "Collecting ", middle: id, tail: label,
		compact: id, token: token, colour: colour,
	}})
}

// CheckDone implements catalog.Observer. It is called from the evaluating
// goroutine, in deterministic order.
func (s *Stream) CheckDone(f finding.Finding) {
	if s == nil {
		return
	}
	token, colour := streamToken(f)

	// Counted here rather than in the drawing goroutine, because the closing
	// block is a tally of what was evaluated and has to be right even when the
	// rows were never drawn — --quiet, or a stream stopped by a Ctrl-C.
	s.mu.Lock()
	s.counts[f.Result]++
	if f.Result == finding.Fail {
		s.failed = append(s.failed, f)
	}
	s.mu.Unlock()

	// The title is the elastic part and the ID is not. A narrow terminal
	// shortens the sentence; it never shortens the identifier, because the ID
	// is what a suppression file matches on and what an operator types into
	// `plumbline explain`. A row that has lost its ID has lost the only part
	// of itself anybody can act on.
	s.emit(event{row: row{
		head: "Checking ", middle: f.Title, tail: " (" + f.CheckID + ")",
		compact: f.CheckID, token: token, colour: colour,
	}})
}

// emit queues one event and returns.
//
// **This is the method the whole asynchronous shape exists for.** It is called
// from the evaluating goroutine a hundred and nine times in about a
// millisecond, and from thirteen collector goroutines at once while they are
// doing real I/O. If drawing happened here, the pace would be charged to those
// callers: the engine would take eighteen seconds instead of 1.3 ms, a
// collector would sit in a sleep instead of reading the next file, and a
// timing figure the report prints would be measuring the display. So the cost
// of a row is an append under a mutex, and the display runs behind.
//
// The goroutine is started on the first event rather than in NewStream, so a
// stream that is constructed and never used — quiet mode, a test — costs
// nothing and has nothing to shut down.
func (s *Stream) emit(ev event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quiet || s.stopped {
		return
	}
	if !s.running {
		s.running = true
		s.finished = make(chan struct{})
		go s.drain()
	}
	ev.pace = s.pace
	s.pending = append(s.pending, ev)
	s.queued++
	s.work.Signal()
}

// drain is the drawing goroutine: the only thing in this package that writes to
// the stream's terminal, and the only thing that ever waits for the pace.
func (s *Stream) drain() {
	defer close(s.finished)
	for {
		ev, ok := s.next()
		if !ok {
			return
		}
		if ev.phase != "" {
			fmt.Fprintf(s.w, "\n%s\n", s.paint(ansiBold, "[*] "+ev.phase))
		} else {
			s.draw(ev.row, ev.pace)
		}

		s.mu.Lock()
		s.drawn++
		s.idle.Broadcast()
		s.mu.Unlock()
	}
}

// next takes the head of the queue, waiting if it is empty. ok is false when
// the stream has been stopped and there is nothing more to draw.
func (s *Stream) next() (event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.pending) == 0 && !s.stopped {
		s.work.Wait()
	}
	if s.stopped {
		return event{}, false
	}
	ev := s.pending[0]
	s.pending = s.pending[1:]
	return ev, true
}

// Await blocks until every event queued so far has reached the screen.
//
// **It is what keeps stderr in one order.** A scan writes two other kinds of
// line to the same descriptor — `bundle saved to ...` and the suppression
// notes — and with the drawing on its own goroutine those would otherwise land
// in the middle of the stream, several rows above where they belong. Calling
// this immediately before them costs whatever is left of the queue and buys a
// terminal that reads top to bottom.
func (s *Stream) Await() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.drawn < s.queued && !s.stopped {
		s.idle.Wait()
	}
}

// Stop ends the drawing goroutine, discards whatever is still queued, and
// returns once it has gone.
//
// **It exists for the interrupt.** With a pace the display outlives the work by
// a long way — a hundred and twenty rows at 150 ms is eighteen seconds during
// which the scan itself is already over — and a Ctrl-C inside that window has
// to be felt now rather than at the end of a display nobody is watching any
// more. The row being drawn finishes its line first, so the terminal is never
// left holding half of one.
//
// It is idempotent, safe on a stream that never started, and safe after Close.
func (s *Stream) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		s.pending = nil
		close(s.halt)
		s.work.Broadcast()
		s.idle.Broadcast()
	}
	done := s.finished
	s.mu.Unlock()

	// Outside the lock: the goroutine needs it to finish the line it is on.
	if done != nil {
		<-done
	}
}

// nap is the pace, cut short by Stop.
func (s *Stream) nap(d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.halt:
	}
}

// Close writes the stream's own tally: what it just showed, and what failed.
//
// It is deliberately short. The report on stdout carries posture, coverage, the
// dashboard and every remediation; repeating that here would be the same
// content twice on one terminal. What this adds is the thing the stream is for
// — a person who watched a hundred lines go past wants the count and the names,
// not the report again.
func (s *Stream) Close(sc score.Score) {
	if s == nil {
		return
	}
	// Two steps, and both are needed. Await puts every queued row on the screen
	// before the closing block, which is the order an operator reads. Stop then
	// retires the drawing goroutine, so that the writes below are the only
	// writes: handing one terminal to two goroutines is the single failure this
	// layout cannot survive, and "the queue is empty" is not the same claim as
	// "nobody else is writing".
	s.Await()
	s.Stop()

	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintln(s.w)
	if posture, ok := sc.Posture(); ok {
		coverage, _ := sc.Coverage()
		fmt.Fprintf(s.w, "%s  posture %s   coverage %s\n",
			s.paint(ansiBold, "[*] Result"),
			s.paint(postureColour(posture, coverage), fmt.Sprintf("%.1f", posture)),
			fmt.Sprintf("%.0f%%", coverage))
	} else {
		// Undefined is not zero. score.Score returns (value, ok) precisely so
		// that "nothing was evaluated" cannot be printed as "posture 0", and
		// the stream must not undo that at the last line.
		fmt.Fprintf(s.w, "%s  nothing was evaluated, so there is no posture to report\n",
			s.paint(ansiBold, "[*] Result"))
	}

	fmt.Fprintf(s.w, "    %d passed, %d failed, %d unknown, %d not applicable\n",
		s.counts[finding.Pass], s.counts[finding.Fail],
		s.counts[finding.Unknown], s.counts[finding.NotApplicable])

	if s.tally && len(s.failed) > 0 {
		// Most severe first, then by ID, so the order is stable for a person
		// reading two runs side by side even though nothing diffs this.
		failed := make([]finding.Finding, len(s.failed))
		copy(failed, s.failed)
		sortBySeverityThenID(failed)
		fmt.Fprintln(s.w)
		for _, f := range failed {
			fmt.Fprintf(s.w, "    %s  %s  %s\n",
				s.paint(ansiRed, "!"),
				s.paint(ansiDim, pad(strings.ToUpper(string(f.Severity)), 8)),
				fmt.Sprintf("%s  %s", f.CheckID, truncate(f.Title, s.columns()-24)))
		}
	}

	// The stream said what it saw; the report says what it means. An operator
	// looking at a screen with no detail on it has to be told where the detail
	// went, or the clean terminal reads as a tool that found nothing to say.
	if s.hint != "" {
		fmt.Fprintf(s.w, "\n%s\n", s.paint(ansiDim, "    "+s.hint))
	}
}

// Hint sets the closing line that says where the detail is. It is set by the
// caller rather than chosen here because only the caller knows whether the
// report was written to stdout, to a file, or withheld.
func (s *Stream) Hint(hint string) *Stream {
	if s == nil {
		return nil
	}
	s.hint = hint
	return s
}

// draw writes one right-aligned row, in two halves with the pace between them.
//
// **The split is the whole effect.** The left half goes out without a newline,
// so the terminal is left holding `[+] Checking a thing (X-0001)...` with the
// cursor sitting after it; the verdict then arrives beside it a beat later and
// reads as an answer to a question, rather than as text that was always there.
// Printing the assembled line in one call and sleeping afterwards would take
// exactly as long and show nothing.
//
// The layout is computed before the pause, not after, so a window dragged
// during the delay cannot leave the two halves of one line measured against two
// different widths. See layout.
func (s *Stream) draw(r row, pace time.Duration) {
	left, gap := s.layout(r)
	fmt.Fprint(s.w, left)
	s.nap(pace)
	fmt.Fprintf(s.w, "%s%s\n", spaces(gap), s.paint(r.colour, r.token))
}

// layout places one row against the terminal, in three segments: a fixed head,
// an elastic middle that may be shortened, and a fixed tail.
//
// The arithmetic is the whole of the alignment and it is four terms:
//
//	columns = clamp(terminal width, streamMinWidth, streamMaxWidth)
//	fixed   = "[+] " + head + tail + "..."
//	elastic = truncate(middle, columns - fixed - token - 1)
//	gap     = columns - fixed - elastic - token
//
// so that `[+] ` + head + elastic + tail + `...` + gap + token is exactly
// `columns` wide and every `]` lands on the same column for as long as the
// terminal keeps that width.
//
// **The gap is computed from visibleWidth, not len.** That is what makes a
// coloured token occupy the columns it draws rather than the bytes it costs —
// the same rule the report's status column obeys, for the same reason, and the
// reason this lives in this package rather than in a second one with its own
// idea of how wide green is.
//
// **Only the middle shrinks.** The check ID is in the tail, so a narrow
// terminal shortens the human sentence and never the identifier. The
// alternative — truncating the assembled string — silently eats the ID first,
// because the ID is at the end, and produces rows nobody can act on at exactly
// the moment the operator is squinting at a small window.
//
// The width is asked once per row, so the three segments of one line are always
// laid out against the same number even if the window is dragged mid-scan.
// Truncation is preferred to wrapping: a wrapped row puts the bracket under the
// middle of the next line and destroys the column, which is the only thing this
// layout is for.
func (s *Stream) layout(r row) (string, int) {
	columns := s.columns()

	fixed := visibleWidth(rowPrefix) + visibleWidth(r.head) + visibleWidth(r.tail) + visibleWidth(rowEllipsis)
	room := columns - fixed - visibleWidth(r.token) - 1

	left := rowPrefix + r.head + truncate(r.middle, room) + r.tail + rowEllipsis
	if room < streamMinTitle {
		// The compact form. It keeps the two things a row exists to carry —
		// which check, and what it said — and drops the sentence explaining
		// it, which at this width was three characters of nothing.
		left = rowPrefix + r.compact + rowEllipsis
	}

	gap := columns - visibleWidth(left) - visibleWidth(r.token)
	if gap < 1 {
		// Even the compact form does not fit. The row runs over rather than
		// being cut into punctuation: an over-long line is still readable and
		// wraps onto a second line the operator can follow, while `[+] CONT…`
		// beside no verdict at all is a row that has lost its point.
		gap = 1
	}
	return left, gap
}

// row is one line of the stream, in the segments the layout treats differently.
//
// head and tail are fixed and are never shortened; middle is the elastic human
// sentence; compact is the whole row's content when the terminal is too narrow
// for any of that. Splitting it this way is what keeps a check ID on screen at
// every width — the ID is in the tail, and the tail does not give.
type row struct {
	head    string
	middle  string
	tail    string
	compact string
	token   string
	colour  string
}

const (
	rowPrefix   = "[+] "
	rowEllipsis = "..."
)

// columns is the width this line is laid out against, clamped.
func (s *Stream) columns() int {
	if s.width == nil {
		return streamFallbackWidth
	}
	n, ok := s.width()
	if !ok {
		return streamFallbackWidth
	}
	switch {
	case n < streamMinWidth:
		return streamMinWidth
	case n > streamMaxWidth:
		return streamMaxWidth
	default:
		return n
	}
}

// paint applies an escape sequence when colour is on, and returns the string
// untouched when it is not. A stream on a pipe is plain text by construction
// rather than by a caller remembering.
func (s *Stream) paint(seq, text string) string {
	if !s.colour || seq == "" {
		return text
	}
	return seq + text + ansiReset
}

// streamToken is the bracketed word a live result is shown as, and the colour
// it is drawn in.
//
// **The word comes from statusToken, which is the report's.** An earlier
// version had its own vocabulary — PASS, FAIL, N/A — on the argument that a
// running commentary wants the verdict while a report wants the action. That
// was wrong in practice for one reason worth recording: the two appear in the
// same session, and an operator who watches `[ FAIL ]` scroll past and then
// greps the report for "FAIL" finds `[ WARNING ]` instead. One word per state,
// produced in one place, is the only arrangement in which they cannot drift.
//
// The colour is the stream's own, and differs from the report in exactly one
// state. The report dims NOT_APPLICABLE so that rows which carry no verdict do
// not compete with the three that do — right for a dense grouped page. In a
// scrolling stream the same rows read as failures of the display rather than as
// answers, so they get cyan: visibly a category of its own, and visibly not a
// warning.
func streamToken(f finding.Finding) (string, string) {
	return statusToken(f), streamColour(f)
}

func streamColour(f finding.Finding) string {
	if f.Suppression == nil && f.Result == finding.NotApplicable {
		return ansiCyan
	}
	return findingColor(f)
}

// collectorToken is the same for the collection half. The strings are
// collect.CollectorStatus values, taken as a plain string so that this package
// does not import a collector package — the render tree may not depend on the
// collection tree, and a status name is not worth breaking that for.
func collectorToken(status string) (string, string) {
	switch status {
	case "ok":
		return "[ DONE ]", ansiGreen
	case "failed":
		return "[ FAILED ]", ansiRed
	case "timeout":
		return "[ TIMEOUT ]", ansiRed
	case "skipped":
		return "[ SKIPPED ]", ansiYellow
	default:
		return "[ " + status + " ]", ansiDim
	}
}

// postureColour is the dashboard's band rule wearing the stream's palette, so
// that the number here and the number in the report are never two different
// colours on one screen. The rule — including the cap coverage puts on what
// posture is allowed to earn — is postureBandFor, in summary.go.
func postureColour(posture, coverage float64) string {
	switch postureBandFor(posture, coverage) {
	case bandFail:
		return ansiRed
	case bandWarn:
		return ansiYellow
	default:
		return ansiGreen
	}
}

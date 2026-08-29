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
// **100 ms is the third number this has had, and the two before it were both
// answers to the wrong question.** 150 ms was picked as the fastest cadence at
// which a column of brackets still reads as a sequence rather than as flicker;
// 500 ms as the slowest at which a hundred and twenty rows is still worth
// sitting through. Both were asking how long one row needs, in a display that
// was a flat list of a hundred and twenty of them — and a flat list of anything
// needs the pause, because the pause is the only structure it has.
//
// The list is no longer flat. Rows are grouped under module headings (see
// section), so the display has visual breaks of its own and the pace no longer
// has to supply them: what the eye lands on is the heading, and the rows below
// it read as a block rather than as a hundred and nine separate events. That
// buys back the time — a hundred and twenty-odd rows come in at about twelve
// seconds and the structure is legible throughout.
//
// **It is presentation and it is never mistaken for work.** Nothing is measured
// through it and nothing waits behind it: the pace is paid by the drawing
// goroutine, after the engine has already finished and moved on (see emit). It
// is charged only where a person is watching — a pipe, a redirect, a CI log and
// --quiet all skip the rows entirely and skip the delay with them — and
// `--pace 0` removes it for anybody who wants the answer rather than the show.
const DefaultPace = 100 * time.Millisecond

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

	// inflight is the collectors that are working the host right now, and when
	// each of them started. It is the heartbeat's subject.
	//
	// It is on the struct and under the mutex because — unlike the current
	// module, which is drain's alone — it is genuinely shared: written by the
	// thirteen collector goroutines and read by the drawing one. ticked is the
	// drawing goroutine's wake-up flag, set by the ticker.
	inflight map[string]time.Time
	ticked   bool

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
		counts:   map[finding.Result]int{},
		inflight: map[string]time.Time{},
		halt:     make(chan struct{}),
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

// CollectorStarted implements collect.Observer. It is called from the collector
// goroutines, concurrently, as each one begins working the host.
//
// **It draws nothing and starts nothing.** All it does is put the collector in
// the set the heartbeat describes, so that a display which is already running
// has something to say while it waits. A stream that has drawn nothing yet
// stays silent rather than opening with a heartbeat for a scan the operator has
// not been told has begun — the phase header is what says that, and it is
// queued like everything else.
func (s *Stream) CollectorStarted(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quiet || s.stopped {
		return
	}
	s.inflight[id] = time.Now()
}

// CollectorDone implements collect.Observer. It is called from the collector
// goroutines, concurrently.
func (s *Stream) CollectorDone(id string, status string, took time.Duration) {
	if s == nil {
		return
	}
	token, colour := collectorToken(status)

	// Out of the heartbeat's set before its row is queued, so that a tick
	// landing between the two cannot name a collector that has finished. When
	// this empties the set the heartbeat has nothing left to say and stops
	// drawing itself — and the row queued on the next line erases whatever is
	// still on screen, so the last thing collection leaves behind is a row.
	s.mu.Lock()
	delete(s.inflight, id)
	s.mu.Unlock()

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
		module: moduleOf(f.CheckID),
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

	// **The module the display is currently inside is a local variable, and
	// that is deliberate rather than incidental.**
	//
	// The obvious place to notice a module change is CheckDone — it is called
	// in catalog order, so the change is visible there — but that is the
	// producer, and it is the wrong side of the queue in two ways. It would
	// make the evaluating goroutine decide what the screen looks like, and it
	// would put a piece of display state in the struct, where CollectorDone's
	// thirteen concurrent callers can reach it and where it would need the
	// mutex to be safe. Here it needs nothing: drain is the only goroutine that
	// draws, so "which module is on screen" is by construction read and written
	// by one goroutine, cannot be raced, and cannot outlive the display it
	// describes.
	//
	// It is not a lookahead. A heading is printed when a row arrives carrying a
	// module that is not the one showing, which is the only rule that works for
	// a queue: the drawing goroutine has no idea what is queued behind the row
	// in its hand, and a scan interrupted after the last CRON row must not have
	// printed a FILESYS heading with nothing under it.
	module := ""

	// live is what the heartbeat has put on the terminal, and it is a local for
	// the same reason module is: only this goroutine draws, so only this
	// goroutine can know what is on the last line, and nothing outside needs to
	// ask. The deferred erase is registered after close(finished) so that it
	// runs *before* it — a Stop that returns while a heartbeat is still on the
	// screen hands the closing block a line that is not empty.
	var live beatline
	defer func() { s.erase(&live) }()
	defer s.tick()()

	for {
		ev, out := s.next()
		switch out {
		case halted:
			return
		case beat:
			s.heartbeat(&live)
			continue
		}

		// Every path that writes a line starts from column 0 of a clean line.
		// That is the whole of the cursor discipline: the heartbeat is the only
		// thing that ever leaves the cursor mid-line, and it is taken back here
		// before anything else is drawn.
		s.erase(&live)

		if ev.phase != "" {
			// A phase forgets the module, so that a heading is printed again
			// under a new phase rather than suppressed as a repeat.
			module = ""
			fmt.Fprintf(s.w, "\n%s\n", s.paint(ansiBold, "[*] "+ev.phase))
			s.show()
		} else {
			// "" never opens a section and never closes one. A collector row
			// carries no module and must neither print a heading nor make the
			// next check row reprint the one already showing.
			open := ""
			if m := ev.row.module; m != "" && m != module {
				module, open = m, m
			}
			s.draw(ev.row, ev.pace, open)
		}

		s.mu.Lock()
		s.drawn++
		s.idle.Broadcast()
		s.mu.Unlock()
	}
}

// section writes the heading a run of rows belongs under.
//
// It is not paced. The pace exists so that a row can be read while it is on
// screen; a heading is not a result, and waiting beside one buys nothing that
// the last row of the previous module has not already bought.
//
// columns is passed in rather than measured here so that a heading and the row
// it introduces are always laid out against the same terminal — see draw.
func (s *Stream) section(module string, columns int) {
	rule := moduleRule
	if columns < rule {
		rule = columns
	}
	fmt.Fprintf(s.w, "\n%s\n%s\n",
		s.paint(ansiBold, "[+] Module: "+module),
		s.paint(ansiDim, strings.Repeat("-", rule)))
	s.show()
}

// moduleOf is the family a check belongs to: the part of its ID before the
// hyphen, so AUTH-0001 is AUTH and CONTAINERS-0007 is CONTAINERS.
//
// An ID with no hyphen has no module rather than being its own, because the
// alternative is a heading per row for anything that ever escapes the catalog's
// naming convention — a display that fails loudly on a malformed ID, where this
// one simply does not group it.
func moduleOf(checkID string) string {
	module, _, ok := strings.Cut(checkID, "-")
	if !ok {
		return ""
	}
	return module
}

// outcome is what the drawing goroutine was woken for.
type outcome int

const (
	drawn  outcome = iota // an event to put on the screen
	beat                  // nothing queued; refresh the heartbeat
	halted                // the stream has been stopped
)

// next takes the head of the queue, waiting if it is empty.
//
// **A queued event always beats a pending tick**, and the tick is dropped
// rather than deferred. The heartbeat exists to cover a gap; if there is
// something real to draw there is no gap, and a beat honoured first would put a
// spinner on the screen for one frame and erase it again in the same
// millisecond.
func (s *Stream) next() (event, outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		switch {
		case s.stopped:
			return event{}, halted
		case len(s.pending) > 0:
			ev := s.pending[0]
			s.pending = s.pending[1:]
			s.ticked = false
			return ev, drawn
		case s.ticked:
			s.ticked = false
			return event{}, beat
		}
		s.work.Wait()
	}
}

// tick wakes the drawing goroutine on a fixed cadence, and returns the function
// that retires it.
//
// **The ticker does not draw and does not hold the writer.** It sets a flag and
// broadcasts, which is the whole of it — the single-writer rule that makes the
// rest of this file safe would be worth nothing if the heartbeat were a second
// goroutine with its own Fprint. What is multiplexed onto stderr is the
// *decision* to draw a heartbeat, not the drawing.
//
// sync.Cond has no timed Wait, which is why this exists at all rather than
// next() simply waiting with a deadline.
func (s *Stream) tick() func() {
	t := time.NewTicker(beatInterval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-t.C:
				s.mu.Lock()
				s.ticked = true
				s.mu.Unlock()
				s.work.Broadcast()
			case <-done:
				t.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
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

// show pushes what has just been written all the way to the screen.
//
// **The pace only works if the title is visible during it, and that is a
// property of the writer rather than of this code.** A row goes out in two
// writes with the delay between them, so anything that held the first write in
// memory until the second arrived would reproduce exactly the wall of text the
// pace exists to break up: the bytes would be right, the timing would be right,
// and the terminal would still show nothing until the verdict landed.
//
// What is underneath decides whether this call does anything:
//
//   - os.Stderr, which is what the CLI hands in, is an *os.File. Its Write is
//     one write(2) with no userspace buffer between it and the terminal, so the
//     title is on screen before Fprint returns and there is nothing here to
//     flush. That is measured rather than assumed — recording the pty with
//     script(1) gives one delivery per pace, each carrying one row's verdict
//     followed immediately by the next row's title, so the read boundary falls
//     *inside* a row, which can only happen if the two halves left the process
//     at different times.
//   - A *bufio.Writer, a *tabwriter.Writer, or any wrapper somebody adds later
//     does hold it, and would break the effect silently — no test would fail,
//     because the bytes would be identical. One type assertion per half-row
//     turns that from something a reviewer has to remember into something the
//     design cannot lose.
//
// Sync is deliberately not called. *os.File has it, so a type switch that
// listed it would fsync(2) the terminal twice a row: a syscall that means
// "commit this to storage", that returns EINVAL on a character device, and that
// has nothing to say about whether anything is on screen.
func (s *Stream) show() {
	if f, ok := s.w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
}

// beatline is what the heartbeat currently has on the terminal.
//
// It lives on drain's stack rather than on the Stream for the same reason the
// current module does: it describes the screen, only one goroutine draws the
// screen, and a field would invite a second one to reason about it.
type beatline struct {
	showing bool
	frame   int
}

// heartbeat draws or refreshes the line that says the scan has not died.
//
// **The cursor discipline is one rule: the heartbeat never ends a line.** It
// writes `\r`, erases the line the cursor is on, and writes its text without a
// newline — so the cursor finishes where it started, at column 0 of the last
// line, and the heartbeat occupies the line the *next* row is going to be drawn
// on. Erasing it is therefore `\r` and an erase again, with nothing to undo and
// nothing to remember.
//
// **There is deliberately no cursor-up.** The obvious alternative — print the
// heartbeat on its own line with a newline, then `\033[1A` back over it — is
// wrong on a terminal in three ways this one cannot be: the line wraps if it is
// wider than the window and one cursor-up then lands in the middle of it; the
// scroll region moves under the cursor when the heartbeat is drawn on the
// bottom row, so up is not where the line was; and anything else that writes to
// stderr in between leaves the cursor pointing at a line that has moved. Never
// leaving the line removes all three.
//
// **It cannot interleave with a row**, and that is structural rather than
// careful. drain draws it only between events, so the two halves of a paced row
// — the title, the pause, the verdict — are never separated by one: while draw
// is sleeping, drain is inside draw and is not here. The right-aligned brackets
// are laid out by layout against a fresh measurement, from column 0, on a line
// this function has already cleared.
//
// The text is truncated to the terminal because a heartbeat that wrapped would
// be two screen lines and the erase would only reach the second, leaving half a
// spinner above every row for the rest of the scan.
func (s *Stream) heartbeat(b *beatline) {
	id, took, others := s.outstanding()
	if id == "" {
		// Nothing is working: whatever was on the line is now stale.
		s.erase(b)
		return
	}

	line := fmt.Sprintf("[~] Still working: %s (%ds)", id, int(took.Seconds()))
	if others > 0 {
		line += fmt.Sprintf(" and %d more", others)
	}
	line += " " + beatFrames[b.frame%len(beatFrames)]
	b.frame++

	fmt.Fprint(s.w, ansiHome+ansiErase+s.paint(ansiDim, truncate(line, s.columns())))
	b.showing = true
	s.show()
}

// erase takes the heartbeat off the terminal, leaving the cursor at column 0 of
// an empty line — which is where every other line in this file starts.
//
// It is a no-op when nothing is showing, so that the common case (a scan whose
// collectors all finish quickly) writes no escape sequences at all.
func (s *Stream) erase(b *beatline) {
	if !b.showing {
		return
	}
	fmt.Fprint(s.w, ansiHome+ansiErase)
	b.showing = false
	s.show()
}

// outstanding is the collector that has been working longest, how long it has
// been at it, and how many others are still going.
//
// **The longest-running one is the answer to the question being asked.** An
// operator looking at a frozen screen wants to know what it is waiting for, and
// on this host that is one filesystem walk with a cold page cache while twelve
// cheap reads have long since finished. Ties break on the id so that two
// collectors started in the same nanosecond do not make the line flicker
// between them.
func (s *Stream) outstanding() (string, time.Duration, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		id    string
		since time.Time
	)
	for name, started := range s.inflight {
		if id == "" || started.Before(since) || (started.Equal(since) && name < id) {
			id, since = name, started
		}
	}
	if id == "" {
		return "", 0, 0
	}
	return id, time.Since(since), len(s.inflight) - 1
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
	s.show()
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
// so the terminal is left holding `  - Checking a thing (X-0001)...` with the
// cursor sitting after it; the verdict then arrives beside it a beat later and
// reads as an answer to a question, rather than as text that was always there.
// Printing the assembled line in one call and sleeping afterwards would take
// exactly as long and show nothing.
//
// The layout is computed before the pause, not after, so a window dragged
// during the delay cannot leave the two halves of one line measured against two
// different widths. See layout.
//
// The flush between the write and the pause is what makes the split an effect
// rather than an arrangement of bytes; see show.
//
// open is the module heading to write above this row, or "" for a row that
// continues the module already showing. It is drawn here rather than in drain
// so that the terminal is measured **once per row** and the heading, its rule
// and its first row are all laid out against the same number — the same reason
// the two halves of one row share a measurement.
func (s *Stream) draw(r row, pace time.Duration, open string) {
	columns := s.columns()
	if open != "" {
		s.section(open, columns)
	}

	left, gap := s.layout(r, columns)
	fmt.Fprint(s.w, left)
	s.show()
	s.nap(pace)
	fmt.Fprintf(s.w, "%s%s\n", spaces(gap), s.paint(r.colour, r.token))
	s.show()
}

// layout places one row against the terminal, in three segments: a fixed head,
// an elastic middle that may be shortened, and a fixed tail.
//
// The arithmetic is the whole of the alignment and it is four terms:
//
//	columns = clamp(terminal width, streamMinWidth, streamMaxWidth)
//	fixed   = "  - " + head + tail + "..."
//	elastic = truncate(middle, columns - fixed - token - 1)
//	gap     = columns - fixed - elastic - token
//
// so that `  - ` + head + elastic + tail + `...` + gap + token is exactly
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
// The width is asked once per row — by draw, and shared with any module heading
// that row opens — so the three segments of one line are always laid out
// against the same number even if the window is dragged mid-scan.
// Truncation is preferred to wrapping: a wrapped row puts the bracket under the
// middle of the next line and destroys the column, which is the only thing this
// layout is for.
func (s *Stream) layout(r row, columns int) (string, int) {
	fixed := visibleWidth(rowIndent) + visibleWidth(r.head) + visibleWidth(r.tail) + visibleWidth(rowEllipsis)
	room := columns - fixed - visibleWidth(r.token) - 1

	left := rowIndent + r.head + truncate(r.middle, room) + r.tail + rowEllipsis
	if room < streamMinTitle {
		// The compact form. It keeps the two things a row exists to carry —
		// which check, and what it said — and drops the sentence explaining
		// it, which at this width was three characters of nothing.
		left = rowIndent + r.compact + rowEllipsis
	}

	gap := columns - visibleWidth(left) - visibleWidth(r.token)
	if gap < 1 {
		// Even the compact form does not fit. The row runs over rather than
		// being cut into punctuation: an over-long line is still readable and
		// wraps onto a second line the operator can follow, while `  - CONT…`
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

	// module is the family this row belongs to, or "" for a row that belongs to
	// none — every collector row, since collectors are not checks. It is
	// carried on the row rather than resolved when the row is drawn because the
	// drawing goroutine must not have to know how a check ID is spelled.
	module string
}

// The row's furniture, and the module heading's.
//
// **`[+] ` used to mean two different things on one screen and now means one.**
// It is the report's module heading — `[+] SSHD  · 19 checks, 2 failing`, see
// group in text.go — and it was also every row of the stream, so an operator
// looking at a terminal that had shown both saw the same marker for "a family
// of checks" and for "one check". The stream's rows are now indented under
// their heading instead, which is both the Lynis shape and the one reading of
// `[+] ` that survives in either renderer.
const (
	rowIndent   = "  - "
	rowEllipsis = "..."

	// The two cursor sequences the heartbeat needs, and the only two in this
	// package. See heartbeat for why there is no cursor-up among them.
	//
	// They are not gated on colour. --no-color and NO_COLOR are statements
	// about colour, not about whether the terminal is a terminal, and a stream
	// only exists on one — a pipe or a CI log never builds a Stream at all.
	ansiHome  = "\r"      // to column 0 of the line the cursor is already on
	ansiErase = "\033[2K" // clear that line, wherever the cursor sits in it

	// moduleRule is how wide the line under a module heading is drawn, before
	// the terminal has its say. It is a fixed figure rather than the full width
	// because a rule that reaches the right margin competes with the column of
	// brackets it is supposed to be introducing — but it is clamped to the
	// terminal in section, because a rule that wraps is two rules.
	moduleRule = 51

	// beatInterval is how often the heartbeat redraws itself while the display
	// has nothing else to do. It is the spinner's frame rate and the resolution
	// of its clock, and 125 ms is fast enough that the line is visibly alive
	// and slow enough that a stalled scan is not spending its time on escape
	// sequences.
	beatInterval = 125 * time.Millisecond
)

// beatFrames is the spinner. ASCII rather than braille: the heartbeat appears
// on exactly the hosts whose terminals are least worth assuming about, and a
// row of missing-glyph boxes reads as a worse fault than the pause it is
// covering.
var beatFrames = [...]string{"|", "/", "-", "\\"}

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

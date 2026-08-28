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

// Stream draws a scan as it happens: one line per collector and one per check,
// each with its verdict flush against the right edge of the terminal.
//
// It satisfies both observer interfaces — catalog.Observer for checks and
// collect.Observer for collectors — because they describe two halves of one
// scan and an operator watching wants one column of brackets, not two
// unrelated displays. The two are called from different concurrency regimes:
// checks come from one goroutine in deterministic order, collectors from
// several at once in whatever order they finish. **Every method takes the
// mutex**, so the interleaving is safe and no line is ever half-written by one
// goroutine and finished by another.
type Stream struct {
	mu     sync.Mutex
	w      io.Writer
	colour bool

	// width is asked freshly for every line rather than cached, so a terminal
	// resized during a scan reflows from the next line. See
	// system.TerminalWidth for why this is not a SIGWINCH handler.
	width func() (int, bool)

	// Tallies, for the closing line. Kept here rather than recomputed from the
	// findings because the stream is a view of what it actually showed: if a
	// check never reached the stream, it is not in the stream's count, and a
	// discrepancy with the report is then visible rather than papered over.
	counts map[finding.Result]int
	failed []finding.Finding
}

// NewStream builds a stream writing to w.
//
// width is injected rather than read from w so that a test can lay out a line
// at eighteen columns without owning a terminal, and so that this package
// keeps its promise not to touch the OS. A nil width function means
// streamFallbackWidth.
func NewStream(w io.Writer, colour bool, width func() (int, bool)) *Stream {
	return &Stream{w: w, colour: colour, width: width, counts: map[finding.Result]int{}}
}

// Phase announces a section of the scan. It is the only line in the stream
// that is not a result.
func (s *Stream) Phase(name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, "\n%s\n", s.paint(ansiBold, "[*] "+name))
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

	s.mu.Lock()
	defer s.mu.Unlock()
	s.line(row{
		head: "Collecting ", middle: id, tail: label,
		compact: id, token: token, colour: colour,
	})
}

// CheckDone implements catalog.Observer. It is called from the evaluating
// goroutine, in deterministic order.
func (s *Stream) CheckDone(f finding.Finding) {
	if s == nil {
		return
	}
	token, colour := streamToken(f.Result)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[f.Result]++
	if f.Result == finding.Fail {
		s.failed = append(s.failed, f)
	}
	// The title is the elastic part and the ID is not. A narrow terminal
	// shortens the sentence; it never shortens the identifier, because the ID
	// is what a suppression file matches on and what an operator types into
	// `plumbline explain`. A row that has lost its ID has lost the only part
	// of itself anybody can act on.
	s.line(row{
		head: "Checking ", middle: f.Title, tail: " (" + f.CheckID + ")",
		compact: f.CheckID, token: token, colour: colour,
	})
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

	if len(s.failed) > 0 {
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
	// who watched this go past needs to know the detail is below and not that
	// this was the whole answer.
	fmt.Fprintf(s.w, "\n%s\n",
		s.paint(ansiDim, "    the full report, with evidence and remediation, follows on stdout"))
}

// line writes one right-aligned row, in three segments: a fixed head, an
// elastic middle that may be shortened, and a fixed tail.
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
func (s *Stream) line(r row) {
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
	fmt.Fprintf(s.w, "%s%s%s\n", left, spaces(gap), s.paint(r.colour, r.token))
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
// **These are not the report's tokens and the difference is intentional.** The
// report says `[ OK ]` and `[ WARNING ]`, because beside a finding with its
// remediation underneath, the useful word is the one that says what to do. The
// stream is a running commentary on evaluation, where the useful word is the
// verdict itself — an operator watching wants to see PASS and FAIL go past, and
// `N/A` is what a person calls a check that did not apply. Both vocabularies
// are defensible for their own half; carrying one into the other would make
// one of the two halves read wrong.
func streamToken(r finding.Result) (string, string) {
	switch r {
	case finding.Pass:
		return "[ PASS ]", ansiGreen
	case finding.Fail:
		return "[ FAIL ]", ansiRed
	case finding.Unknown:
		return "[ UNKNOWN ]", ansiYellow
	case finding.NotApplicable:
		return "[ N/A ]", ansiYellow
	case finding.Skipped:
		return "[ SKIPPED ]", ansiDim
	default:
		// A result from a newer catalog still gets a row rather than being
		// dropped, which is the same rule statusToken follows.
		return "[ " + string(r) + " ]", ansiDim
	}
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

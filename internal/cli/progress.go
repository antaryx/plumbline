package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/antaryx/plumbline/internal/system"
)

// Collection is the slow half of a scan and it used to be the silent half. A
// filesystem walk over a real server runs for tens of seconds with nothing on
// the terminal, which looks exactly like a hang — and a security tool that
// looks hung is one an operator interrupts and stops trusting.
//
// This file draws a transient indicator while that happens. Three properties
// make it safe to add to a tool whose output is a contract:
//
//  1. **It only ever writes to stderr.** CLI-SPEC.md §7 says stdout carries the
//     requested output and nothing else, and a findings document with a
//     spinner in it is not a findings document. Keying the indicator off
//     stderr rather than stdout also makes `plumbline scan > report.txt` work
//     the way an operator expects: the file stays clean and the terminal they
//     are watching still shows that something is happening.
//
//  2. **It erases itself before anything else is written.** Stop() blocks
//     until the drawing goroutine has cleared its line and exited, so no frame
//     can land after the report has started. A spinner that races the report
//     is worse than no spinner.
//
//  3. **It disables itself unless it is certain it is talking to a human.**
//     Four conditions, below. The default is off: every one of them has to say
//     yes.

// Frames and cadence.
//
// Braille dots because they are one cell wide in every terminal font that has
// them, so the message never shifts sideways as the frame changes. 80ms is
// about the slowest cadence that still reads as motion rather than as a
// character that keeps changing.
const (
	frameInterval = 80 * time.Millisecond
	spinnerFrames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
)

// elapsedAfter is how long a phase runs before the indicator starts showing
// how long it has been running.
//
// The number is not decoration and it is not shown from the start. "0s" tells
// an operator nothing; "47s" tells them the walk is on a large filesystem
// rather than wedged, which is the actual question behind "is this hung". It
// appears at roughly the moment somebody starts wondering.
const elapsedAfter = 3 * time.Second

// eraseLine returns the cursor to column zero and clears what was there.
//
// \r alone is not enough: the next line written may be shorter than the frame,
// which would leave the tail of the spinner on screen in front of it. EL (CSI
// K) erases from the cursor to the end of the line, which is what makes the
// indicator genuinely transient rather than merely overwritten.
const eraseLine = "\r\x1b[K"

// progress is one transient indicator. A nil *progress is a disabled one and
// every method on it is a no-op, so a caller writes
//
//	p := startProgress(stderr, "Collecting host evidence")
//	defer p.Stop()
//
// without a branch, and cannot forget the branch on some path.
type progress struct {
	w        io.Writer
	message  string
	interval time.Duration

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// startProgress begins an indicator on w if this run should have one, and
// returns nil if it should not.
func startProgress(w io.Writer, message string) *progress {
	if !progressAllowed(w) {
		return nil
	}
	p := newProgress(w, message, frameInterval)
	p.start()
	return p
}

// newProgress builds an indicator unconditionally. It is separate from
// startProgress so that the drawing can be tested against a buffer, which by
// construction is never a terminal and so could never satisfy the policy.
func newProgress(w io.Writer, message string, interval time.Duration) *progress {
	return &progress{
		w:        w,
		message:  message,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// progressAllowed decides whether this run gets an indicator.
//
// Every condition is a veto and the default is off, because the cost of the
// two answers is not symmetric. A missing spinner is a cosmetic loss on one
// run. A spinner in a place that cannot erase it is thousands of lines of
// half-drawn braille in a CI log that somebody has to scroll through six
// months later to find out why a build failed.
func progressAllowed(w io.Writer) bool {
	switch {
	// The operator said no. CLI-SPEC.md §8 reserved this variable before there
	// was anything to suppress; this is it.
	//
	// NO_COLOR is deliberately *not* consulted. That convention is about
	// colour, this indicator emits none, and quietly widening somebody else's
	// standard to mean "and also stop moving" is how a well-known variable
	// stops meaning one predictable thing.
	case os.Getenv("PLUMBLINE_NO_PROGRESS") != "":
		return false

	// Not a terminal: a pipe, a file, a test buffer, or a captured log. This
	// is the condition that keeps CI clean in every harness, named or not,
	// because a build agent capturing output does not give the process a tty.
	case !system.IsTerminal(w):
		return false

	// A terminal that will not tell us what it is cannot be assumed to
	// understand CSI K. \r would still work, but an indicator that can move
	// the cursor and not erase itself is the one failure mode this must not
	// have.
	case isDumbTerminal():
		return false

	// And a named CI system even when it *has* allocated a pty, which several
	// do. The pty makes the two previous checks say yes while the output is
	// still going to a log file nobody is watching live.
	case inCI():
		return false
	}
	return true
}

// isDumbTerminal reports a TERM this indicator must not draw on.
//
// Empty counts as dumb. An unset TERM on a character device is a terminal that
// has not identified itself, and guessing that it speaks ANSI is the guess
// that leaves escape sequences in somebody's scrollback.
func isDumbTerminal() bool {
	term := strings.TrimSpace(os.Getenv("TERM"))
	return term == "" || term == "dumb"
}

// ciMarkers are the environment variables that mean "this is a build, not a
// person".
//
// CI is the one nearly everything sets and would be enough on its own for the
// systems that set it. The rest are here because the ones that do not set CI
// are exactly the ones that also allocate a pty, which is the combination that
// defeats the terminal check.
//
// Presence is the signal, not value: a harness that exports CI= empty is still
// a harness, and treating CI=false as "not CI" is the kind of cleverness that
// produces a log full of braille.
var ciMarkers = []string{
	"CI",
	"CONTINUOUS_INTEGRATION",
	"BUILD_NUMBER",     // Jenkins, TeamCity
	"GITHUB_ACTIONS",   // GitHub
	"GITLAB_CI",        // GitLab
	"BUILDKITE",        // Buildkite, allocates a pty
	"TEAMCITY_VERSION", // TeamCity
	"TF_BUILD",         // Azure Pipelines
	"CIRCLECI",         // CircleCI, allocates a pty
	"DRONE",            // Drone
	"JENKINS_URL",      // Jenkins
}

func inCI() bool {
	for _, name := range ciMarkers {
		if _, set := os.LookupEnv(name); set {
			return true
		}
	}
	return false
}

// start launches the drawing goroutine.
func (p *progress) start() {
	go func() {
		defer close(p.done)

		began := time.Now()
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()

		// Painted before the first tick so that a phase shorter than one frame
		// still shows something, and so the indicator appears at the moment
		// the work starts rather than 80ms into it.
		p.paint(0, began)

		for frame := 1; ; frame++ {
			select {
			case <-p.stop:
				p.erase()
				return
			case <-ticker.C:
				p.paint(frame, began)
			}
		}
	}()
}

// Stop erases the indicator and waits for the drawing goroutine to finish.
//
// **The wait is the point.** Returning while that goroutine might still paint
// would put a frame on top of the first line of the report, and the operator
// would see a corrupted heading with no way to tell that a spinner did it.
// After Stop returns, the caller owns stderr again.
//
// Safe on a nil receiver — a disabled indicator — and safe to call twice.
func (p *progress) Stop() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		close(p.stop)
		<-p.done
	})
}

// paint draws one frame in place.
//
// Errors are dropped rather than reported. A terminal that will not accept a
// spinner frame is not a reason to fail a scan, and there is nowhere useful to
// report it to: the stream that failed is the one a report would go to.
func (p *progress) paint(frame int, began time.Time) {
	runes := []rune(spinnerFrames)
	glyph := runes[frame%len(runes)]

	line := fmt.Sprintf("\r%c %s", glyph, p.message)
	if elapsed := time.Since(began); elapsed >= elapsedAfter {
		line += fmt.Sprintf(" (%ds)", int(elapsed.Seconds()))
	}
	fmt.Fprint(p.w, line+"\x1b[K")
}

func (p *progress) erase() {
	fmt.Fprint(p.w, eraseLine)
}

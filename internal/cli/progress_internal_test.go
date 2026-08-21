// This file is package cli rather than cli_test for the reason
// format_internal_test.go is: the progress indicator's policy and its drawing
// are unexported and are not going to be exported. They are terminal
// behaviour, not surface, and asserting them through Execute would need a real
// pseudo-terminal and therefore a dependency this project will not take on for
// a test.
package cli

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// clearProgressEnv removes every variable that would veto an indicator, so a
// policy test asserts the rule it names rather than whatever the machine
// running it happens to export. CI is the obvious one: this suite runs on a
// GitHub runner, where every positive case would otherwise be vetoed by the
// environment and pass for the wrong reason.
//
// t.Setenv is called before os.Unsetenv purely for its bookkeeping — it
// registers a cleanup that restores the original value, including restoring it
// to unset — because there is no t.Unsetenv.
func clearProgressEnv(t *testing.T) {
	t.Helper()
	names := append([]string{"PLUMBLINE_NO_PROGRESS"}, ciMarkers...)
	for _, name := range names {
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
	t.Setenv("TERM", "xterm-256color")
}

// TestProgressAllowedRefusesEverythingItIsNotSureAbout.
//
// The two answers do not cost the same. A missing indicator is a cosmetic loss
// on one run; an indicator drawn somewhere it cannot be erased is thousands of
// lines of half-drawn braille in a CI log that somebody has to read months
// later to find out why a build failed. So every condition is a veto and the
// test that matters is the one for each false.
func TestProgressAllowedRefusesEverythingItIsNotSureAbout(t *testing.T) {
	t.Run("a terminal with a real TERM and no CI gets one", func(t *testing.T) {
		clearProgressEnv(t)
		if !progressAllowed(devNull(t)) {
			t.Error("an interactive terminal did not get a progress indicator")
		}
	})

	t.Run("PLUMBLINE_NO_PROGRESS vetoes", func(t *testing.T) {
		clearProgressEnv(t)
		t.Setenv("PLUMBLINE_NO_PROGRESS", "1")
		if progressAllowed(devNull(t)) {
			t.Error("PLUMBLINE_NO_PROGRESS was ignored; CLI-SPEC.md §8 promises it")
		}
	})

	t.Run("NO_COLOR does not veto", func(t *testing.T) {
		// Deliberate. NO_COLOR is a convention about colour and this indicator
		// emits none. Widening somebody else's standard to mean "and also stop
		// moving" is how a well-known variable stops meaning one thing;
		// PLUMBLINE_NO_PROGRESS is the control for this.
		clearProgressEnv(t)
		t.Setenv("NO_COLOR", "1")
		if !progressAllowed(devNull(t)) {
			t.Error("NO_COLOR suppressed the progress indicator; it governs colour, not motion")
		}
	})

	t.Run("a pipe does not get one", func(t *testing.T) {
		clearProgressEnv(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		if progressAllowed(w) {
			t.Error("a pipe got a progress indicator; `plumbline scan 2>log` would collect frames")
		}
	})

	t.Run("a buffer does not get one", func(t *testing.T) {
		clearProgressEnv(t)
		if progressAllowed(&bytes.Buffer{}) {
			t.Error("a non-file writer got a progress indicator")
		}
	})

	t.Run("TERM=dumb vetoes", func(t *testing.T) {
		clearProgressEnv(t)
		t.Setenv("TERM", "dumb")
		if progressAllowed(devNull(t)) {
			t.Error("TERM=dumb got a progress indicator it cannot erase")
		}
	})

	t.Run("an unset TERM vetoes", func(t *testing.T) {
		clearProgressEnv(t)
		t.Setenv("TERM", "")
		_ = os.Unsetenv("TERM")
		if progressAllowed(devNull(t)) {
			t.Error("a terminal that did not identify itself was assumed to speak ANSI")
		}
	})

	// Named separately from the terminal check because several of these
	// allocate a pty, which makes system.IsTerminal say yes while the output
	// is still going to a log file nobody is watching live.
	for _, marker := range ciMarkers {
		t.Run(marker+" vetoes even on a pty", func(t *testing.T) {
			clearProgressEnv(t)
			t.Setenv(marker, "")
			if progressAllowed(devNull(t)) {
				t.Errorf("%s did not suppress the indicator; presence is the signal, not value", marker)
			}
		})
	}
}

// frameSink records what the indicator writes and lets a test wait for frames
// without sleeping for a fixed period.
//
// The channel is buffered and the send is non-blocking on purpose: a test that
// stops draining must not wedge the drawing goroutine inside Write, because a
// wedged goroutine never reaches its stop case and Stop would hang forever.
type frameSink struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes chan struct{}
}

func newFrameSink() *frameSink {
	return &frameSink{writes: make(chan struct{}, 256)}
}

func (s *frameSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	select {
	case s.writes <- struct{}{}:
	default:
	}
	return n, err
}

func (s *frameSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitForWrites blocks until n writes have landed, or fails the test.
func (s *frameSink) waitForWrites(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-s.writes:
		case <-deadline:
			t.Fatalf("only %d of %d frames were drawn within the deadline", i, n)
		}
	}
}

// TestProgressErasesItselfBeforeReturning is the property the whole feature
// rests on.
//
// The report is written by the caller the instant Stop returns. If the drawing
// goroutine could paint once more after that, the operator would see a frame
// on top of the first line of their report and nothing would tell them a
// spinner had done it. Stop therefore waits for the goroutine to erase and
// exit, and the assertion here is that the last bytes written are the erase.
func TestProgressErasesItselfBeforeReturning(t *testing.T) {
	sink := newFrameSink()
	p := newProgress(sink, "Collecting host evidence", time.Millisecond)
	p.start()

	sink.waitForWrites(t, 3)
	p.Stop()

	got := sink.String()
	if !strings.HasSuffix(got, eraseLine) {
		t.Errorf("the last thing written was %q, not the erase sequence %q", tail(got, 12), eraseLine)
	}
	// Nothing may follow the erase, which HasSuffix already proves, but the
	// count guards the subtler bug: an erase in the middle, a frame after it,
	// and a second erase at the end would still pass a suffix check.
	if n := strings.Count(got, eraseLine); n != 1 {
		t.Errorf("the indicator erased its line %d times; it should erase exactly once, at the end", n)
	}
}

// TestProgressAnimatesInPlace. Every write starts with a carriage return, so
// the indicator occupies one line for its whole life rather than scrolling.
func TestProgressAnimatesInPlace(t *testing.T) {
	const message = "Collecting host evidence"

	sink := newFrameSink()
	p := newProgress(sink, message, time.Millisecond)
	p.start()
	sink.waitForWrites(t, 4)
	p.Stop()

	got := sink.String()
	if strings.Contains(got, "\n") {
		t.Error("the indicator wrote a newline; it must stay on one line so it can erase itself")
	}
	if !strings.Contains(got, message) {
		t.Errorf("the indicator never wrote its message %q", message)
	}
	if !strings.HasPrefix(got, "\r") {
		t.Error("the first frame did not begin with a carriage return")
	}

	// At least two distinct glyphs, or it is a static character rather than an
	// indication that something is still happening.
	seen := map[rune]bool{}
	for _, r := range spinnerFrames {
		if strings.ContainsRune(got, r) {
			seen[r] = true
		}
	}
	if len(seen) < 2 {
		t.Errorf("only %d distinct frame(s) were drawn; the indicator is not animating", len(seen))
	}
}

// TestProgressElapsedIsWithheldUntilItMeansSomething. "0s" answers nothing.
// The number exists to distinguish a walk on a large filesystem from a wedged
// one, and that question does not arise in the first second.
func TestProgressElapsedIsWithheldUntilItMeansSomething(t *testing.T) {
	sink := newFrameSink()
	p := newProgress(sink, "Collecting host evidence", time.Millisecond)
	p.start()
	sink.waitForWrites(t, 4)
	p.Stop()

	if strings.Contains(sink.String(), "(0s)") {
		t.Error("the indicator reported an elapsed time of zero")
	}
}

// TestProgressShowsElapsedOnceItMatters is the other half of the rule above.
//
// paint is called directly rather than through the drawing goroutine, which
// takes its start time from time.Now: a test that waited for the real
// threshold would be a test that sleeps for three seconds on every run.
func TestProgressShowsElapsedOnceItMatters(t *testing.T) {
	sink := newFrameSink()
	p := newProgress(sink, "Collecting host evidence", time.Hour)
	p.paint(0, time.Now().Add(-47*time.Second))

	if got := sink.String(); !strings.Contains(got, "(47s)") {
		t.Errorf("a phase running for 47s did not report it: %q", got)
	}
}

// TestProgressStopIsSafeOnANilAndOnASecondCall. startProgress returns nil for
// a run that must not have an indicator, and every call site is written as
// `defer startProgress(...).Stop()` with no branch. That is only correct if a
// nil receiver is a working no-op — and the double call is what a caller who
// stops early and also defers will do.
func TestProgressStopIsSafeOnANilAndOnASecondCall(t *testing.T) {
	var nilProgress *progress
	nilProgress.Stop()
	nilProgress.Stop()

	sink := newFrameSink()
	p := newProgress(sink, "Collecting host evidence", time.Millisecond)
	p.start()
	sink.waitForWrites(t, 1)
	p.Stop()
	p.Stop()

	if n := strings.Count(sink.String(), eraseLine); n != 1 {
		t.Errorf("two Stop calls erased %d times; Stop must be idempotent", n)
	}
}

// TestStartProgressReturnsNilWhenItMustNotDraw ties the policy to the
// mechanism: the nil is what makes every call site branch-free.
func TestStartProgressReturnsNilWhenItMustNotDraw(t *testing.T) {
	clearProgressEnv(t)

	if p := startProgress(nil, "Collecting host evidence"); p != nil {
		p.Stop()
		t.Error("a nil stream produced an indicator")
	}
	if p := startProgress(&bytes.Buffer{}, "Collecting host evidence"); p != nil {
		p.Stop()
		t.Error("a buffer produced an indicator")
	}
}

// TestAScanThroughExecuteWritesNoTerminalControl is the end-to-end guard on
// the claim that matters to every other test in this package.
//
// The report streams to stdout and the indicator draws on stderr, and both are
// buffers here — never terminals — so a correct build writes no control bytes
// to either. The assertion is a regression tripwire: it fires the day somebody
// makes the indicator unconditional, which would corrupt a findings document
// on stdout and put frames into every stderr assertion in cli_test.go.
func TestAScanThroughExecuteWritesNoTerminalControl(t *testing.T) {
	clearProgressEnv(t)

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"scan", "--json", "--root", "../../testdata/fixtures/cli-host"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("scan exited %d\nstderr: %s", code, stderr.String())
	}

	for _, stream := range []struct {
		name string
		got  string
	}{
		{"stdout", stdout.String()},
		{"stderr", stderr.String()},
	} {
		if strings.Contains(stream.got, "\x1b") {
			t.Errorf("%s carries an ANSI escape; neither stream is a terminal here", stream.name)
		}
		if strings.Contains(stream.got, "\r") {
			t.Errorf("%s carries a carriage return; the indicator drew where it must not", stream.name)
		}
	}
	for _, frame := range spinnerFrames {
		if strings.ContainsRune(stdout.String(), frame) {
			t.Fatalf("a spinner frame reached stdout; a findings document with one in it is not a findings document")
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

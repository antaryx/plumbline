package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

// The mode tests in this file drive the real cobra command over a real
// pseudo-terminal, and they exist because the previous test of the same
// property did not.
//
// **What went wrong.** TestStandardModeEndsWithinAScreenOfTheStream constructed
// a text.Stream directly, did not call Tally, and asserted the closing block was
// short. That proves the Stream honours tally=false. It cannot prove that the
// scan command *sets* tally=false, because the command was never run — the one
// line that decides the mode, `Tally(verbose)` in scan.go, was outside the test
// entirely. A wiring regression would have left it green.
//
// The same blind spot covers every other mode decision, and they all live in
// the command rather than in the renderer: streamPresenter's four conditions,
// reportDestination's terminal test, the hint. None of them can be reached
// through a bytes.Buffer, because a buffer is not a character device and the
// stream is never built for one.
//
// **So the test needs a terminal.** A pty gives a real character device that
// system.IsTerminal answers yes to, that TIOCGWINSZ reports a size for, and
// that a test can read back. Both stdout and stderr are pointed at the same
// slave, which is what a person sees when they type `plumbline scan`; the
// assertion is then made against the one interleaved stream they would be
// looking at.

// pty is a pseudo-terminal pair. Writes to the slave are readable from the
// master, so the CLI can be handed a genuine terminal whose output a test can
// still see.
type pty struct {
	master *os.File
	slave  *os.File

	mu  sync.Mutex
	buf bytes.Buffer
	wg  sync.WaitGroup
}

// openPTY allocates one. The three ioctls are the standard Linux sequence:
// unlock the slave, ask which slave it is, then open it.
func openPTY(t *testing.T) *pty {
	t.Helper()

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx on this system: %v", err)
	}

	var unlock int32
	if err := ioctl(master, syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		master.Close()
		t.Skipf("unlockpt: %v", err)
	}

	var n uint32
	if err := ioctl(master, syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		master.Close()
		t.Skipf("ptsname: %v", err)
	}

	// A fixed window size, so the layout under test does not depend on
	// whatever the machine running the tests happens to be.
	ws := struct{ rows, cols, x, y uint16 }{rows: 40, cols: ptyColumns}
	if err := ioctl(master, syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		master.Close()
		t.Skipf("set window size: %v", err)
	}

	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Skipf("open slave: %v", err)
	}

	p := &pty{master: master, slave: slave}

	// Drained continuously rather than read at the end. A pty's buffer is a
	// few kilobytes and a scan writes rather more than that, so a test that
	// read only after the command returned would deadlock against a CLI
	// blocked on write — which is a hang, not a failure, and the worst shape
	// of flaky test there is.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		chunk := make([]byte, 4096)
		for {
			n, err := master.Read(chunk)
			if n > 0 {
				p.mu.Lock()
				p.buf.Write(chunk[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		slave.Close()
		master.Close()
		p.wg.Wait()
	})
	return p
}

const ptyColumns = 100

func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// output returns everything written to the terminal so far, with the escape
// sequences and the pty's own carriage returns removed.
//
// The slave is closed first so the CLI's writes have certainly been flushed
// through and the reader has certainly seen them: without that, a test can
// assert on a prefix of the output and pass for the wrong reason.
func (p *pty) output(t *testing.T) string {
	t.Helper()
	p.slave.Close()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.ReplaceAll(stripANSI(p.buf.String()), "\r", "")
}

func stripANSI(s string) string {
	var out strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// terminalRun executes the real command line with both stdout and stderr
// pointed at a terminal, and returns what a person would have seen.
func terminalRun(t *testing.T, args ...string) (int, string) {
	t.Helper()

	// The stream draws only when it is certain a human is watching, and two of
	// its four conditions are environmental. A test that did not control them
	// would pass or fail according to where it ran.
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("PLUMBLINE_NO_NOTICES", "1")
	unsetCIMarkers(t)

	term := openPTY(t)
	code := Execute(args, term.slave, term.slave)
	return code, term.output(t)
}

// unsetCIMarkers removes the variables progressAllowed treats as "this is a
// build, not a person", restoring them afterwards. t.Setenv cannot unset, and
// setting them to empty is not the same thing: inCI tests presence.
func unsetCIMarkers(t *testing.T) {
	t.Helper()
	for _, name := range ciMarkers {
		if old, set := os.LookupEnv(name); set {
			os.Unsetenv(name)
			t.Cleanup(func() { os.Setenv(name, old) })
		}
	}
	// Also the one the operator sets deliberately.
	if old, set := os.LookupEnv("PLUMBLINE_NO_PROGRESS"); set {
		os.Unsetenv("PLUMBLINE_NO_PROGRESS")
		t.Cleanup(func() { os.Setenv("PLUMBLINE_NO_PROGRESS", old) })
	}
}

// resultTail is everything the terminal showed after the `[*] Result` heading.
// It is what an operator is left looking at when a scan ends, and in standard
// mode it is the whole subject of this file.
func resultTail(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "[*] Result")
	if i < 0 {
		t.Fatalf("no result block in the terminal output:\n%s", out)
	}
	return out[i:]
}

// TestStandardModeShowsTheStreamAndNothingButASummary.
//
// The real command, a real terminal, no flags. Three claims:
//
//   - the stream is there — collection rows and evaluation rows both;
//   - after the Result heading there is nothing but the counts and the hint;
//   - in particular no severity tally, no check IDs, and none of the detailed
//     report's section headings.
//
// The third is asserted by naming what may appear rather than by listing what
// may not, because a list of forbidden strings is a list somebody has to
// remember to extend.
func TestStandardModeShowsTheStreamAndNothingButASummary(t *testing.T) {
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	if !strings.Contains(out, "[+] Collecting ") {
		t.Error("no collection rows: the stream did not run")
	}
	if !strings.Contains(out, "[+] Checking ") {
		t.Error("no evaluation rows: the stream did not run")
	}

	tail := resultTail(t, out)
	for _, line := range strings.Split(strings.TrimSpace(tail), "\n") {
		switch text := strings.TrimSpace(line); {
		case text == "",
			strings.HasPrefix(text, "[*] Result"),
			strings.Contains(text, "passed,") && strings.Contains(text, "failed,"),
			text == "Run again with --verbose for detailed evidence and remediation.":
			// The four lines standard mode is allowed.
		default:
			t.Errorf("standard mode printed this after the result block:\n  %q\nfull tail:\n%s",
				text, tail)
		}
	}
}

// TestVerboseModeAddsTheTallyAndTheDetail, so that the assertion above is
// pinning a mode rather than an absence — a suppression that suppressed
// everywhere would pass the standard-mode test and be just as broken.
func TestVerboseModeAddsTheTallyAndTheDetail(t *testing.T) {
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host", "--verbose")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	tail := resultTail(t, out)
	if !strings.Contains(tail, "!  HIGH") {
		t.Errorf("--verbose lost the severity tally:\n%s", tail)
	}
	if !strings.Contains(out, "Warnings and suggestions") {
		t.Error("--verbose lost the detailed report")
	}
	if !strings.Contains(out, "Remedy") {
		t.Error("--verbose lost the remediation blocks it exists for")
	}
	// And it does not repeat the scan phase the stream just drew.
	if strings.Contains(out, "[+] AUTH") {
		t.Error("--verbose repeated the report's grouped scan phase after streaming it")
	}
}

// TestQuietModeIsTheResultBlockAlone.
func TestQuietModeIsTheResultBlockAlone(t *testing.T) {
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host", "--quiet")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	for _, forbidden := range []string{"[+] Checking ", "[+] Collecting ", "[*] Collecting", "!  HIGH", "Warnings and suggestions"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("--quiet printed %q:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "[*] Result") {
		t.Errorf("--quiet lost the result block it exists to print:\n%s", out)
	}
	// No hint either: it is the mode that asked for less.
	if strings.Contains(out, "--verbose for detailed") {
		t.Errorf("--quiet printed the hint:\n%s", out)
	}
}

// TestARedirectedRunOnATerminalStillWritesTheWholeReport.
//
// The other half of reportDestination, and the one a person actually relies on:
// `plumbline scan > report.txt` in a terminal must play the stream *and* write
// the complete document, scan phase included. stderr is the terminal, stdout is
// not.
func TestARedirectedRunOnATerminalStillWritesTheWholeReport(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("PLUMBLINE_NO_NOTICES", "1")
	unsetCIMarkers(t)

	term := openPTY(t)
	var file bytes.Buffer
	code := Execute([]string{"scan", "--root", "../../testdata/fixtures/cli-host"}, &file, term.slave)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}

	screen := term.output(t)
	if !strings.Contains(screen, "[+] Checking ") {
		t.Error("the stream did not play on the terminal")
	}
	if !strings.Contains(file.String(), "[+] AUTH") {
		t.Error("the redirect lost the report's scan phase")
	}
	if !strings.Contains(file.String(), "Warnings and suggestions") {
		t.Error("the redirect lost the detailed report")
	}
}

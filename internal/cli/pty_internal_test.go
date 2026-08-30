package cli

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
	code := Execute(unpaced(args), term.slave, term.slave)
	return code, term.output(t)
}

// unpaced pins the stream's artificial delay off, unless the test is about the
// delay.
//
// scan's default is a tenth of a second a row (rendertext.DefaultPace), which
// is what makes the display readable on a terminal and what would make every
// mode test in this file wait twelve seconds for a property none of them is
// asserting.
// TestThePaceFlagSlowsTheStream is the one that pays for it.
func unpaced(args []string) []string {
	for _, a := range args {
		if a == "--pace" || strings.HasPrefix(a, "--pace=") {
			return args
		}
	}
	return append(append([]string{}, args...), "--pace", "0")
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

	if !strings.Contains(out, "  - Collecting ") {
		t.Error("no collection rows: the stream did not run")
	}
	if !strings.Contains(out, "  - Checking ") {
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
	if !strings.Contains(out, "Details: ") {
		t.Error("--verbose lost the details line the warnings list exists for")
	}
	// And the warnings list is still the two-line form, not the field dump it
	// replaced. These are the labels that used to follow every entry.
	for _, dumped := range []string{"- Evidence ", "- Caution ", "- Effort ", "- Severity "} {
		if strings.Contains(out, dumped) {
			t.Errorf("--verbose is dumping %q into the terminal report again", dumped)
		}
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

	for _, forbidden := range []string{"  - Checking ", "  - Collecting ", "[+] Module: ", "[*] Collecting", "!  HIGH", "Warnings and suggestions"} {
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
	code := Execute([]string{"scan", "--root", "../../testdata/fixtures/cli-host", "--pace", "0"}, &file, term.slave)
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}

	screen := term.output(t)
	if !strings.Contains(screen, "  - Checking ") {
		t.Error("the stream did not play on the terminal")
	}
	if !strings.Contains(file.String(), "[+] AUTH") {
		t.Error("the redirect lost the report's scan phase")
	}
	if !strings.Contains(file.String(), "Warnings and suggestions") {
		t.Error("the redirect lost the detailed report")
	}
}

// TestVerboseKeepsTheStreamAboveTheResultAndTheDetail.
//
// **This pins the claim the verbose mode test above was not making.** It
// asserted the tally and the detail and said nothing about the rows, so a
// regression that dropped the stream from --verbose would have left it green.
//
// The mode is also the one that most easily *looks* broken without being
// broken: --verbose appends the whole report, which is fourteen hundred lines
// on a real host, so by the time the command returns the stream has scrolled
// well out of the window. Hence two assertions rather than one — the rows are
// there, and they are in the right order relative to everything after them.
func TestVerboseKeepsTheStreamAboveTheResultAndTheDetail(t *testing.T) {
	_, plain := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host")
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host", "--verbose")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	// Not "some rows", but every row standard mode drew. A stream that lost
	// half its checks to --verbose is as broken as one that lost all of them.
	if got, want := strings.Count(out, "  - Checking "), strings.Count(plain, "  - Checking "); got != want {
		t.Errorf("--verbose streamed %d evaluation rows, standard mode streamed %d", got, want)
	}
	if got, want := strings.Count(out, "  - Collecting "), strings.Count(plain, "  - Collecting "); got != want {
		t.Errorf("--verbose streamed %d collection rows, standard mode streamed %d", got, want)
	}

	// Order: the collection rows, then the evaluation rows, then the Result
	// block, then the detailed report. Each of these is an index into one
	// string, which is the whole point of putting both descriptors on one
	// terminal — it is the order a person actually sees.
	for _, step := range []struct {
		name  string
		first string
		then  string
	}{
		{"collection before evaluation", "  - Collecting ", "  - Checking "},
		{"the stream before the result block", "  - Checking ", "[*] Result"},
		{"the result block before the detail", "[*] Result", "Warnings and suggestions"},
	} {
		if i, j := strings.Index(out, step.first), strings.Index(out, step.then); i < 0 || j < 0 || i > j {
			t.Errorf("%s: %q at %d, %q at %d", step.name, step.first, i, step.then, j)
		}
	}
}

// TestThePaceFlagSlowsTheStream.
//
// The only end-to-end proof that --pace reaches the renderer. Every other test
// in this file runs with --pace 0, so without this one the flag could be
// unwired — or wired to a stream that is never built — and nothing would say
// so.
//
// The bound is deliberately loose. A scheduler under `go test -race` is not a
// stopwatch, and the claim being made is "the rows waited", not "the rows waited
// for exactly this long": half the nominal time is far above anything an unpaced
// run could take and far below anything a paced one could miss.
func TestThePaceFlagSlowsTheStream(t *testing.T) {
	const pace = 5 * time.Millisecond

	start := time.Now()
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host",
		"--pace", pace.String())
	elapsed := time.Since(start)
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	rows := strings.Count(out, "  - ")
	if rows < 50 {
		t.Fatalf("only %d rows streamed; the timing below would prove nothing", rows)
	}
	if want := time.Duration(rows) * pace / 2; elapsed < want {
		t.Errorf("%d rows at %s each finished in %s, under the %s floor: --pace is not reaching the stream",
			rows, pace, elapsed, want)
	}
}

// TestTheStreamGroupsTheCatalogByModule.
//
// The end-to-end shape, on a real terminal, from the real catalog: a heading
// per module and every check indented under the heading for its own family.
//
// **The claim worth testing is the second half.** That headings appear at all
// is a renderer property already covered in internal/render/text; what only a
// full run can show is that the heading a row lands under is the row's own
// module — which depends on the catalog evaluating in an order that keeps a
// module contiguous. Nothing declares that ordering, so nothing but a scan can
// check it, and a catalog reordered by an unrelated change would otherwise
// scatter AUTH checks under three headings with every unit test still green.
func TestTheStreamGroupsTheCatalogByModule(t *testing.T) {
	code, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host")
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	var (
		module   string
		seen     []string
		rows     int
		reopened []string
	)
	for _, line := range strings.Split(out, "\n") {
		// A slow collector leaves a heartbeat on the line a row is then drawn
		// over, so a row can arrive behind a carriage return and an erase. On
		// the terminal the row is alone on the line; here the sequences have to
		// come off before the line is read.
		line = strings.Trim(strings.ReplaceAll(line, "\033[2K", ""), "\r")
		switch {
		case strings.HasPrefix(line, "[+] Module: "):
			module = strings.TrimSpace(strings.TrimPrefix(line, "[+] Module: "))
			if slices.Contains(seen, module) {
				reopened = append(reopened, module)
			}
			seen = append(seen, module)

		case strings.HasPrefix(line, "  - Checking "):
			rows++
			id, ok := checkIDIn(line)
			if !ok {
				continue
			}
			want, _, _ := strings.Cut(id, "-")
			if want != module {
				t.Errorf("%s is drawn under the %q heading", id, module)
			}
		}
	}

	if rows == 0 {
		t.Fatal("no evaluation rows: the stream did not run")
	}
	if len(seen) < 2 {
		t.Errorf("the whole catalog streamed under %d heading(s); it has more than one module", len(seen))
	}
	// A module opened twice means the catalog stopped evaluating its families
	// contiguously. The renderer draws that faithfully rather than hiding it
	// (see TestAModuleIsReopenedRatherThanMisfiled), so the complaint belongs
	// here.
	if len(reopened) > 0 {
		t.Errorf("these modules were opened more than once, so the catalog no longer evaluates them contiguously: %v", reopened)
	}
}

// checkIDIn pulls the check ID out of a streamed row, which carries it in
// parentheses at the end of the title — `  - Checking a thing (AUTH-0001)...`.
// A row narrow enough to have dropped to its compact form has the ID and
// nothing else, and is not what this is parsing.
func checkIDIn(row string) (string, bool) {
	open := strings.LastIndex(row, "(")
	closed := strings.LastIndex(row, ")")
	if open < 0 || closed < open {
		return "", false
	}
	return row[open+1 : closed], true
}

// TestTheReportFollowsTheTerminalAndAFileKeepsTheGrid.
//
// **Two layouts, one measurement, no flag.** The warnings section's prose is
// wrapped to the terminal so a wide window is not folded at 78 columns; a file
// or a pipe gets the fixed grid so two nightly runs of an unchanged host still
// diff to nothing. What separates them is `system.TerminalWidth` of the
// *destination writer* — the same ioctl answers for a terminal and fails for a
// file — which is why a redirect cannot pick up the operator's window size by
// accident.
//
// Both halves are asserted in one test because either alone is satisfied by a
// renderer that ignores the width entirely.
func TestTheReportFollowsTheTerminalAndAFileKeepsTheGrid(t *testing.T) {
	const grid = 78

	widest := func(out string) int {
		w := 0
		for _, raw := range strings.Split(out, "\n") {
			line := strings.Trim(strings.ReplaceAll(raw, "\033[2K", ""), "\r")
			if !strings.HasPrefix(line, "      Details: ") &&
				!strings.HasPrefix(line, "               ") {
				continue
			}
			if n := len([]rune(stripEscapes(line))); n > w {
				w = n
			}
		}
		return w
	}

	t.Run("a terminal", func(t *testing.T) {
		_, out := terminalRun(t, "scan", "--root", "../../testdata/fixtures/cli-host", "--verbose")
		got := widest(out)
		if got <= grid {
			t.Errorf("the widest details line is %d columns on a %d-column terminal; it is still folded at the %d-column grid",
				got, ptyColumns, grid)
		}
		if got > ptyColumns {
			t.Errorf("a details line is %d columns on a %d-column terminal", got, ptyColumns)
		}
	})

	t.Run("a redirect", func(t *testing.T) {
		t.Setenv("TERM", "xterm-256color")
		t.Setenv("PLUMBLINE_NO_NOTICES", "1")
		unsetCIMarkers(t)

		// stdout to a buffer, stderr to the pty: the stream still plays on the
		// terminal, and the report still goes somewhere that has no width.
		term := openPTY(t)
		var file bytes.Buffer
		if code := Execute([]string{"scan", "--root", "../../testdata/fixtures/cli-host",
			"--verbose", "--pace", "0"}, &file, term.slave); code != ExitOK {
			t.Fatalf("exit %d", code)
		}

		if got := widest(file.String()); got > grid {
			t.Errorf("a redirected details line is %d columns; a file keeps the %d-column grid so the artifact stays diffable",
				got, grid)
		}
		if !strings.Contains(file.String(), "Details: ") {
			t.Fatal("the redirect carries no warnings section, so this proves nothing")
		}
	})
}

// stripEscapes removes SGR sequences so a line can be measured in the columns a
// terminal would draw rather than in bytes.
func stripEscapes(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				esc = false
			}
		case r == '\033':
			esc = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestTheReportIsPacedOnATerminal.
//
// The end-to-end proof that --pace reaches the *report*, which is a different
// wire from the one TestThePaceFlagSlowsTheStream covers: the pace travels from
// the flag through renderAndGate into rendertext.Input.Pace, and the terminal
// test it is gated on is a TIOCGWINSZ taken on stdout rather than the stream's
// on stderr. Either could be unwired without the other noticing, and the
// schedule tests in internal/render/text cannot see this half at all — they
// construct an Input directly, which is the one thing this file exists to stop
// being the only coverage.
//
// **The live stream is switched off for the measurement**, which is what makes
// this affordable. PLUMBLINE_NO_PROGRESS leaves stream nil, so the hundred and
// twelve rows are neither drawn nor paced and the only artificial delay left in
// the run is the report's own. The report is still rendered in full, because
// nothing narrated it.
//
// The floor is read off the document that was produced rather than hardcoded,
// so it stays correct as sections and findings are added, and it is halved for
// the reason the stream's is: a scheduler under `go test -race` is not a
// stopwatch, and the claim is "the report waited", not "it waited for exactly
// this long".
func TestTheReportIsPacedOnATerminal(t *testing.T) {
	const pace = 20 * time.Millisecond

	paced, out := unstreamedRun(t, pace.String())
	sections, entries := pacedPoints(out)
	if sections < 2 || entries < 5 {
		t.Fatalf("%d sections and %d entries in the report; the timing below would prove nothing:\n%s",
			sections, entries, out)
	}

	want := (time.Duration(sections)*pace*6 + time.Duration(entries)*pace*8/10) / 2
	if paced < want {
		t.Errorf("a report of %d sections and %d entries at --pace %s finished in %s, under the %s floor: the pace is not reaching the report",
			sections, entries, pace, paced, want)
	}

	// And the off switch, on the same document. Without this the test above
	// would pass just as well against a report that paced itself regardless of
	// what the operator asked for.
	instant, _ := unstreamedRun(t, "0")
	if instant >= want {
		t.Errorf("--pace 0 took %s, at or over the %s floor: the delays are not being switched off", instant, want)
	}
}

// unstreamedRun renders a full report to a terminal with no live stream in
// front of it, and returns how long the whole command took.
func unstreamedRun(t *testing.T, pace string) (time.Duration, string) {
	t.Helper()

	t.Setenv("TERM", "xterm-256color")
	t.Setenv("PLUMBLINE_NO_NOTICES", "1")
	t.Setenv("PLUMBLINE_NO_PROGRESS", "1")
	unsetCIMarkers(t)

	term := openPTY(t)
	start := time.Now()
	code := Execute([]string{"scan", "--root", "../../testdata/fixtures/cli-host",
		"--verbose", "--pace", pace}, term.slave, term.slave)
	elapsed := time.Since(start)

	out := term.output(t)
	if code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	return elapsed, out
}

// pacedPoints counts the two things the report pauses at: a section heading at
// column 0, and an entry headline in the warnings, unknown or accepted blocks.
// A scan-phase row wears the same bullet and is deliberately not paced, which
// is why the severity tag is part of the match.
func pacedPoints(out string) (sections, entries int) {
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "[=] "):
			sections++
		case strings.HasPrefix(l, "  - ["), strings.HasPrefix(l, "  * "):
			entries++
		}
	}
	return sections, entries
}

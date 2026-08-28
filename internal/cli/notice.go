package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/version"
)

// A check that changes what it reports changes users' scores, and VERSIONING
// §2.4 forbids that happening quietly: a correction likely to move results on
// more than roughly 10% of hosts "also carries a `plumbline scan` startup
// warning for one minor cycle". This file is that warning.
//
// The problem it solves is narrow and real. Posture is severity-weighted, so
// re-rating a check moves the number on a host nobody touched. An operator who
// sees 65 where yesterday's report said 62 has two explanations available —
// the host changed, or the tool did — and only one of them is worth
// investigating. Without something on the terminal saying which, the honest
// operator wastes an afternoon and the tired one stops trusting the number.
//
// Four properties make this safe to add to a tool whose output is a contract:
//
//  1. **It writes to stderr and nothing else writes it.** CLI-SPEC.md §7 gives
//     stdout to the requested output alone. The notice never sees the stdout
//     writer: reportScoringNotices takes one io.Writer and scan hands it
//     stderr, so no format — json, sarif, terminal — can put a byte of this in
//     a document a pipeline parses.
//
//  2. **It expires without anyone remembering to remove it.** Each entry names
//     the first tool version that stops showing it. A notice nobody expires is
//     a banner everyone learns to scroll past, which is the same as no banner
//     at all and costs a line of everybody's terminal forever.
//
//  3. **It is drawn whether or not a human is watching.** This is the opposite
//     of the progress indicator's policy (progress.go) and deliberately so.
//     That indicator is an animation, useless in a log and actively harmful in
//     one that cannot erase it. This is one static block, and CI is precisely
//     where an unexplained score movement breaks a threshold gate at three in
//     the morning. Terminal detection would suppress it exactly where it is
//     most needed.
//
//  4. **The operator can turn it off, and only the operator.** One environment
//     variable, honoured on presence, weakening nothing (CLI-SPEC.md §8).

// scoringNotice is one entry in the register below: a change that moved scores,
// stated in the terms of the question an operator actually has, which is "why
// is this number different from last week's".
type scoringNotice struct {
	// ID is a stable, greppable identifier. It is not shown, but it is what a
	// changelog entry, a test and a support conversation can all name without
	// quoting prose that may be reworded.
	ID string

	// Catalog is the catalog version that carried the change. It is shown,
	// because it is the number `plumbline diff` refuses to compare across
	// (VERSIONING §3.1) and therefore the one that answers "which of my two
	// reports predates this".
	Catalog int

	// Until is the first tool version that no longer shows this notice —
	// exclusive, so "1.2.0" means every 1.1.x build shows it and 1.2.0 does
	// not. VERSIONING §2.4 asks for one minor cycle, so this is normally the
	// next minor after the one the change shipped in.
	Until string

	// Headline is one line naming what changed. Detail is the body, one
	// element per rendered line.
	//
	// Wrapping is the author's, not the renderer's. These lines are written
	// once and read on an 80-column terminal; hand-set breaks let a sentence
	// end where its clause does, and they cannot be surprised by a width this
	// code has no way to measure on a stderr that may not be a terminal at all.
	Headline string
	Detail   []string
}

// scoringNotices is the register. Adding a scoring change is adding an entry;
// removing an expired one is optional, because Until already stopped it being
// shown — the entry stays until someone tidies it, and does nothing.
//
// Ordered oldest catalog first, so an operator who skipped several versions
// reads the changes in the order they happened.
var scoringNotices = []scoringNotice{
	{
		ID:       "kernel-0004-dmesg-severity",
		Catalog:  27,
		Until:    "1.2.0",
		Headline: "KERNEL-0004 (kernel.dmesg_restrict) was re-rated LOW to HIGH.",
		Detail: []string{
			"The old rating read the ring buffer as untidy logging. It holds kernel and",
			"module load addresses, so on a host where kernel.kptr_restrict is not 2 an",
			"unprivileged `dmesg` defeats KASLR outright. Hosts that leave the buffer",
			"world-readable — the default on most builds — lose posture accordingly.",
		},
	},
	{
		ID:       "kernel-0005-suid-dumpable-2",
		Catalog:  32,
		Until:    "1.2.0",
		Headline: "KERNEL-0005 accepts fs.suid_dumpable = 2 as a PASS.",
		Detail: []string{
			"2 is \"suidsafe\": the dump goes to the core-dump handler rather than to a",
			"file the invoking user can read, which is how systemd-coredump captures a",
			"setuid crash. It used to fail. Hosts running systemd-coredump gain a PASS",
			"they were owed, and KERNEL-0029 stops contradicting this check on the same",
			"value in the same report.",
		},
	},
	{
		ID:       "kernel-persistence-runtime-tiering",
		Catalog:  32,
		Until:    "1.2.0",
		Headline: "Persistence checks no longer report a secure running kernel at full severity.",
		Detail: []string{
			"KERNEL-0017 through -0031 fail at LOW, not their base severity, when the",
			"only thing missing is the file: every parameter they require is running at",
			"a value they accept, so nothing is exposed today. A parameter running",
			"exposed, one whose running value could not be read, and any file setting a",
			"wrong value all keep full severity.",
			"No verdict changed — a FAIL is still a FAIL, and the detail still says the",
			"setting may not survive a reboot. Posture rises on most hosts anyway,",
			"because severity weights the score.",
		},
	},
	{
		ID:       "kernel-runtime-persistence-alignment",
		Catalog:  33,
		Until:    "1.2.0",
		Headline: "Six KERNEL checks were re-rated so each parameter has one severity.",
		Detail: []string{
			"A persistence check used to sit one band above the runtime check for the",
			"same parameter, on an argument that catalog 32's tiering retired. The gap",
			"is closed: KERNEL-0002, -0005, -0006, -0009 and -0010 rise MEDIUM to HIGH,",
			"and KERNEL-0020 falls HIGH to MEDIUM.",
			"KERNEL-0018 also stops failing a configured kernel.kptr_restrict = 1, which",
			"KERNEL-0002 passes on the same host: 1 hides pointers from unprivileged",
			"readers, and 2 is now a recommendation in the verdict rather than a",
			"requirement. Hosts shipping 1 — Ubuntu, Debian and the RPM family all do —",
			"gain a PASS.",
		},
	},
}

// noticeEnvVar disables the block. Honoured on presence rather than value, the
// way NO_COLOR and PLUMBLINE_NO_PROGRESS are: a variable somebody went out of
// their way to export means what it says, and reading PLUMBLINE_NO_NOTICES=0
// as "notices please" is how a setting stops being obeyed.
const noticeEnvVar = "PLUMBLINE_NO_NOTICES"

// reportScoringNotices writes the startup block for the running build.
//
// This is the whole call site: one line at the top of a command, taking the
// stream to write on. A caller cannot accidentally hand it stdout without
// having typed the word.
func reportScoringNotices(w io.Writer, colour bool) {
	if os.Getenv(noticeEnvVar) != "" {
		return
	}
	writeScoringNotices(w, activeNotices(scoringNotices, version.Version), colour)
}

// activeNotices selects the entries a build of version tool still shows.
func activeNotices(all []scoringNotice, tool string) []scoringNotice {
	var out []scoringNotice
	for _, n := range all {
		if toolVersionBefore(tool, n.Until) {
			out = append(out, n)
		}
	}
	return out
}

// writeScoringNotices renders the block. Separate from reportScoringNotices so
// that the rendering can be tested against a buffer with a chosen register,
// rather than against whatever the register happens to hold this month.
func writeScoringNotices(w io.Writer, notices []scoringNotice, colour bool) {
	if len(notices) == 0 {
		return
	}

	bold := func(s string) string {
		if !colour {
			return s
		}
		return noticeBold + s + noticeReset
	}

	rule := strings.Repeat("─", 74)
	fmt.Fprintln(w, rule)
	// The "plumbline:" prefix is on the header alone. Every other line of this
	// block is indented under it, which is what makes the block read as one
	// message rather than as several unrelated warnings — and `grep plumbline:`
	// still finds that it happened.
	fmt.Fprintf(w, "plumbline: %s — %s\n", bold("SCORING NOTICE"), noticeSummary(len(notices)))
	fmt.Fprintln(w)

	for _, n := range notices {
		fmt.Fprintf(w, "  %s  %s\n", bold(fmt.Sprintf("catalog %d", n.Catalog)), n.Headline)
		for _, line := range n.Detail {
			fmt.Fprintf(w, "      %s\n", line)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "  Posture is severity-weighted, so these moved scores on hosts that did not")
	fmt.Fprintln(w, "  change. Reports from before them are not directly comparable; `plumbline")
	fmt.Fprintln(w, "  diff` refuses to compare across catalog versions for the same reason.")
	fmt.Fprintf(w, "  Set %s to silence this.\n", noticeEnvVar)
	fmt.Fprintln(w, rule)
}

// noticeSummary is the header's right-hand half. It counts rather than
// enumerating, because the enumeration is the next twenty lines.
func noticeSummary(n int) string {
	if n == 1 {
		return "1 recent change moved posture scores"
	}
	return fmt.Sprintf("%d recent changes moved posture scores", n)
}

// Bold only. This block competes with nothing for attention — it is the first
// thing on the terminal and there is one of it — and colour that means
// "severity" everywhere else in this tool would be borrowing a vocabulary it
// does not belong to.
const (
	noticeBold  = "\033[1m"
	noticeReset = "\033[0m"
)

// toolVersionBefore reports whether the running tool version is older than the
// version a notice expires at.
//
// An unparseable version shows the notice. That is the direction to fail in:
// a build with no release identity — `go run`, a test binary, `git describe`
// on a repository with no tags — has demonstrably not passed any expiry, and
// the cost of the two mistakes is not symmetric. A stale notice is a few lines
// somebody skims. A missing one is the silent score change VERSIONING §2.4
// exists to prevent.
func toolVersionBefore(cur, until string) bool {
	c, ok := parseSemver(cur)
	if !ok {
		return true
	}
	u, ok := parseSemver(until)
	if !ok {
		return true
	}
	for i := range c {
		if c[i] != u[i] {
			return c[i] < u[i]
		}
	}
	return false
}

// parseSemver reads major.minor.patch, tolerating what the Makefile actually
// produces. VERSION comes from `git describe --tags --always --dirty`, so a
// real build may be "v1.1.0-4-gabc1234" or "v1.1.0-dirty" or a bare hash. The
// first two are 1.1.0 for this purpose; the third has no version at all and
// says so by failing.
func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

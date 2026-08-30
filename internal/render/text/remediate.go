package text

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// RemediationInput is the proposed-remediation block.
//
// It takes a rendered script rather than a plan, because internal/render may
// not import internal/remediate for the same reason it may not import
// internal/collect: a renderer that knew how a fix was built is a renderer that
// would eventually build one. The joint between the two is the CLI, which is
// already allowed to know about both.
type RemediationInput struct {
	// Color enables ANSI escape sequences.
	Color bool
	// Covered is how many failing checks the script fixes.
	Covered int
	// Uncovered is how many failing checks have no fix in this build.
	Uncovered int
	// Script is the shell to display, verbatim.
	Script string
	// SavedTo is where the script was also written, or "" for print-only. It
	// is stated inside the block as well as on stderr, because the two go to
	// different places and an operator redirecting one loses the other.
	SavedTo string

	// Width is the destination's measured terminal width, 0 for a file or a
	// pipe. **It is not a layout parameter** — the script below is printed
	// verbatim at whatever width it was generated at, and must be — and is
	// carried only so that the decision to pace this block is made by the same
	// function, on the same evidence, as the report's. A second terminal test
	// here would be a second place for the two to disagree.
	Width int
	// Pace is the live stream's per-row delay. 0 prints the script at once.
	Pace time.Duration
}

// RenderRemediation writes the proposed-remediation block.
//
// **The script is printed verbatim and unindented, which is a deliberate break
// from every other block in this file.** Everything else here is laid out to be
// read; this is laid out to be *taken* — selected, pasted into an editor, run.
// Two leading spaces on every line would survive the paste and would have to be
// stripped by hand from a file the operator is about to run as root, and a
// mistake made stripping them is a mistake made in a root shell.
//
// **Nothing here has been executed and the heading says so.** A block that
// looked like a log of work done would be the worst possible ambiguity in a
// tool that also could have done it; the wording is chosen so that the first
// line an operator reads is the one that settles the question.
func RenderRemediation(w io.Writer, in RemediationInput) error {
	p := &printer{w: w, color: in.Color, width: reportWidth, pace: newPacer(in.Width, in.Pace)}

	p.blank()
	p.section("Proposed remediation script")
	p.blank()

	p.line("  " + p.paint(ansiBold, "Nothing below has been run."))
	p.line("  " + p.paint(ansiDim, fmt.Sprintf(
		"%s covered by this script; review it, then run it as root.", checkCount(in.Covered))))

	if in.Uncovered > 0 {
		// **Said every time, and not only when the number is large.** A block
		// that listed four fixes and stayed silent about the other thirty-two
		// failures would read as the whole of what is wrong with the host,
		// which is the most damaging thing a security tool can imply.
		p.line("  " + p.paint(ansiYellow, fmt.Sprintf(
			"%s still failing with no automated fix; see the warnings above.", checkCount(in.Uncovered))))
	}

	if in.SavedTo != "" {
		p.line("  " + p.paint(ansiDim, "Saved to "+in.SavedTo+" (0700)."))
	}

	p.blank()
	for _, l := range strings.Split(strings.TrimRight(in.Script, "\n"), "\n") {
		p.line(l)
		// A line at a time, at a fifth of the beat an entry gets. The script is
		// the one block here that is *output of a generator*, and watching it
		// assemble is what tells an operator it was assembled — from this
		// host's findings, a command at a time — rather than pasted in whole
		// from somewhere. It is also the block most likely to be long, which is
		// why the delay is the smallest of the three.
		p.pause(p.pace.line)
	}
	p.blank()

	return p.err
}

func checkCount(n int) string {
	if n == 1 {
		return "1 check"
	}
	return fmt.Sprintf("%d checks", n)
}

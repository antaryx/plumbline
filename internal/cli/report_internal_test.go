package cli

import (
	"bytes"
	"strings"
	"testing"

	rendertext "github.com/antaryx/plumbline/internal/render/text"
)

// devNull (format_internal_test.go) is the stand-in for a terminal: a character
// device, which is what system.IsTerminal tests for. It exercises the branch a
// bytes.Buffer never can, and a test that cannot reach the branch deciding
// whether the report is written is a test of nothing.

// TestTheReportIsWithheldOnlyFromATerminalThatWatchedTheScan.
//
// This is the one place in the CLI where stdout's content depends on what
// stdout is, so every case is spelled out rather than left to a reader to
// derive. The rule: the detailed report is withheld exactly when a live stream
// already put the whole scan on the same terminal, and the operator did not ask
// for it anyway.
func TestTheReportIsWithheldOnlyFromATerminalThatWatchedTheScan(t *testing.T) {
	stream := rendertext.NewStream(&bytes.Buffer{}, false, nil)
	tty := devNull(t)
	pipe := &bytes.Buffer{}

	cases := []struct {
		name    string
		verbose bool
		live    *rendertext.Stream
		out     outputFlags
		stdout  interface{ Write([]byte) (int, error) }
		want    bool
	}{
		{"a terminal that watched the scan", false, stream, outputFlags{}, tty, false},

		{"--verbose overrides everything", true, stream, outputFlags{}, tty, true},
		{"no stream ran, so nothing else said anything", false, nil, outputFlags{}, tty, true},
		{"--output names a file to keep", false, stream, outputFlags{output: "r.txt"}, tty, true},
		{"stdout is redirected or piped", false, stream, outputFlags{}, pipe, true},

		// The combination worth naming: the stream plays on the terminal and
		// the full report lands in the file. Both behaviours at once, which is
		// what `plumbline scan > report.txt` should do.
		{"stream on the terminal, report into the redirect", false, stream, outputFlags{}, pipe, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reportDestination(c.verbose, c.live, c.out, c.stdout); got != c.want {
				t.Errorf("reportDestination = %v, want %v", got, c.want)
			}
		})
	}
}

// TestTheClosingHintAlwaysSaysWhereTheDetailWent.
//
// A clean terminal is the point and it is also the one hazard: a screen with no
// detail on it reads as a tool that had nothing to say. Every path ends with a
// sentence naming where the rest is, and the withheld path names the flag that
// brings it back.
func TestTheClosingHintAlwaysSaysWhereTheDetailWent(t *testing.T) {
	cases := []struct {
		wrote  bool
		output string
		want   string
	}{
		{false, "", "--verbose"},
		{true, "", "stdout"},
		{true, "report.txt", "report.txt"},
	}
	for _, c := range cases {
		got := reportHint(c.wrote, c.output)
		if got == "" {
			t.Errorf("wrote=%v output=%q produced no hint", c.wrote, c.output)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("wrote=%v output=%q: hint %q does not mention %q", c.wrote, c.output, got, c.want)
		}
	}
}

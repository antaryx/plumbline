package text_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/diff"
	"github.com/antaryx/plumbline/internal/finding"
	rendertext "github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
)

func df(checkID string, r finding.Result) finding.Finding {
	return finding.Finding{
		CheckID: checkID, Module: "SSHD", Title: checkID + " does the thing",
		Result: r, Severity: finding.High, BaseSeverity: finding.High,
		Fingerprint: finding.Fingerprint(checkID, ""),
	}
}

func dfAccepted(in finding.Finding, why string) finding.Finding {
	in.Suppression = &finding.Suppression{
		Justification: why, ExpiresAt: "2026-06-30T00:00:00Z", OriginalResult: in.Result,
	}
	in.Result = finding.Skipped
	return in
}

// diffSample moves one finding in each direction, so every category is present
// in one render.
func diffSample() rendertext.DiffInput {
	old := []finding.Finding{
		df("SSHD-0002", finding.Fail),                              // resolved
		df("SSHD-0003", finding.Pass),                              // new failure
		df("SSHD-0004", finding.Fail),                              // newly suppressed
		dfAccepted(df("SSHD-0005", finding.Fail), "was temporary"), // regressed
		df("SSHD-0006", finding.Fail),                              // verdict changed
	}
	next := []finding.Finding{
		df("SSHD-0002", finding.Pass),
		df("SSHD-0003", finding.Fail),
		dfAccepted(df("SSHD-0004", finding.Fail), "bastion, SEC-4471"),
		df("SSHD-0005", finding.Fail),
		df("SSHD-0006", finding.Unknown),
	}
	return rendertext.DiffInput{
		Tool:     rendertext.Tool{Name: "plumbline", Version: "0.4.0-dev"},
		Old:      rendertext.DiffSide{Path: "monday.plb"},
		New:      rendertext.DiffSide{Path: "tuesday.plb"},
		Result:   diff.Compare(old, next),
		OldScore: score.Compute(old, 13),
		NewScore: score.Compute(next, 13),
	}
}

func renderDiff(t *testing.T, in rendertext.DiffInput) string {
	t.Helper()
	var buf bytes.Buffer
	if err := rendertext.RenderDiff(&buf, in); err != nil {
		t.Fatalf("RenderDiff: %v", err)
	}
	return buf.String()
}

// TestEveryCategoryIsRendered. A category computed and not printed is a change
// the operator never sees.
func TestEveryCategoryIsRendered(t *testing.T) {
	out := renderDiff(t, diffSample())
	for _, want := range []string{
		"NEW FAILURE", "REGRESSED", "VERDICT CHANGED", "NEWLY SUPPRESSED", "RESOLVED",
		"SSHD-0002", "SSHD-0003", "SSHD-0004", "SSHD-0005", "SSHD-0006",
		"bastion, SEC-4471",            // the reason an acceptance was made
		"expired 2026-06-30T00:00:00Z", // and the reason one lapsed
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the diff omits %q:\n%s", want, out)
		}
	}
}

// TestCategoriesCarryTheColoursWP30Specified.
func TestCategoriesCarryTheColoursWP30Specified(t *testing.T) {
	in := diffSample()
	in.Color = true
	out := renderDiff(t, in)

	for _, c := range []struct{ category, code string }{
		{"RESOLVED", "\033[32m"},         // green
		{"NEW FAILURE", "\033[31m"},      // red
		{"NEWLY SUPPRESSED", "\033[36m"}, // cyan
		{"REGRESSED", "\033[33m"},        // yellow
	} {
		if !strings.Contains(out, c.code+c.category) {
			t.Errorf("%s is not painted %q", c.category, c.code)
		}
	}
}

// TestThePostureDeltaIsShownWithACoverageDelta. Posture rising because four
// checks stopped being able to tell is not an improvement, and the two numbers
// side by side are the only way to see it. This is the same invariant the scan
// report enforces.
func TestThePostureDeltaIsShownWithACoverageDelta(t *testing.T) {
	out := renderDiff(t, diffSample())

	posture := strings.Index(out, "posture")
	coverage := strings.Index(out, "coverage")
	if posture < 0 || coverage < 0 {
		t.Fatalf("the summary is missing one of the two figures:\n%s", out)
	}
	if coverage < posture {
		t.Error("coverage is printed before posture; they must read as a pair")
	}
	if !strings.Contains(out, "→") {
		t.Errorf("the deltas do not show both ends:\n%s", out)
	}
}

// TestNoChangeSaysSo rather than printing an empty report, which reads as the
// command having failed.
func TestNoChangeSaysSo(t *testing.T) {
	same := []finding.Finding{df("SSHD-0002", finding.Pass)}
	out := renderDiff(t, rendertext.DiffInput{
		Tool:     rendertext.Tool{Name: "plumbline", Version: "0.4.0-dev"},
		Result:   diff.Compare(same, same),
		OldScore: score.Compute(same, 13),
		NewScore: score.Compute(same, 13),
	})
	if !strings.Contains(out, "No change") {
		t.Errorf("an empty diff does not say so:\n%s", out)
	}
	if !strings.Contains(out, "(no change)") {
		t.Errorf("a zero delta is not stated as one:\n%s", out)
	}
}

// TestTheDiffGridHolds. The transition token is the widest bracket this tool
// prints — "[ SUPPRESSED → UNKNOWN ]" — so it is the one most likely to push a
// line past the right edge.
func TestTheDiffGridHolds(t *testing.T) {
	for _, colour := range []bool{false, true} {
		in := diffSample()
		in.Color = colour
		for _, raw := range strings.Split(renderDiff(t, in), "\n") {
			line := stripANSI(raw)
			if !strings.HasPrefix(line, "  - ") {
				continue
			}
			if n := len([]rune(line)); n != reportWidth {
				t.Errorf("colour=%v: a change line is %d columns, grid is %d:\n%s",
					colour, n, reportWidth, line)
			}
		}
	}
}

// TestDiffRenderIsDeterministic.
func TestDiffRenderIsDeterministic(t *testing.T) {
	for _, colour := range []bool{false, true} {
		in := diffSample()
		in.Color = colour
		first := renderDiff(t, in)
		for i := 0; i < 20; i++ {
			if got := renderDiff(t, in); got != first {
				t.Fatalf("colour=%v: render %d differs from the first", colour, i)
			}
		}
	}
}

// TestNoDiffLineHasTrailingWhitespace. A diff is something people paste into a
// ticket and diff against last week's; trailing spaces make both worse.
func TestNoDiffLineHasTrailingWhitespace(t *testing.T) {
	for _, raw := range strings.Split(renderDiff(t, diffSample()), "\n") {
		if raw != strings.TrimRight(raw, " \t") {
			t.Errorf("trailing whitespace: %q", raw)
		}
	}
}

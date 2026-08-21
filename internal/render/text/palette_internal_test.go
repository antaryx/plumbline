// This file is package text rather than text_test, for the reason
// format_internal_test.go in internal/cli is: the palette is not surface. The
// exact bytes a result is painted with are an implementation detail that will
// be tuned, and a test outside the package could only pin them by copying them
// — which is how a palette change turns into a test that asserts the old
// palette in two places.
//
// What is pinned here is the part that is a promise rather than a detail:
// which state gets which colour, and that the two halves of the report agree
// about what those colours are.
package text

import (
	"fmt"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/diff"
	"github.com/antaryx/plumbline/internal/finding"
)

// TestTheTwoHalvesOfTheReportAgreeOnTheirColours.
//
// The check lines are painted with the ANSI constants in text.go; the summary
// dashboard is painted by lipgloss from the hex constants in summary.go. They
// are two mechanisms rendering one report, and nothing but this test stops
// somebody tuning one green and leaving the other — which nobody would notice
// in review and everybody would notice on a terminal.
func TestTheTwoHalvesOfTheReportAgreeOnTheirColours(t *testing.T) {
	for _, c := range []struct {
		what string
		ansi string
		hex  string
	}{
		{"pass", ansiGreen, hexPass},
		{"fail", ansiRed, hexFail},
		{"unknown", ansiYellow, hexUnknown},
	} {
		if got := hexOf(c.ansi); !strings.EqualFold(got, c.hex) {
			t.Errorf("%s: the check lines paint %s and the dashboard paints %s; "+
				"one palette was changed and the other was not", c.what, got, c.hex)
		}
	}
}

// hexOf recovers the colour from a 24-bit SGR sequence, so the comparison is
// between two colours rather than between two strings that happen to encode
// one. "\033[1;38;2;34;197;94m" -> "#22C55E".
func hexOf(seq string) string {
	i := strings.Index(seq, "38;2;")
	if i < 0 {
		return seq
	}
	var r, g, b int
	if _, err := fmt.Sscanf(seq[i+len("38;2;"):], "%d;%d;%dm", &r, &g, &b); err != nil {
		return seq
	}
	return fmt.Sprintf("#%02X%02X%02X", r, g, b)
}

// TestEveryVerdictColourIsDistinct. Three states an operator has to tell apart
// at a glance, and the whole argument of this tool is that UNKNOWN is not a
// PASS — which it visibly is if the two are painted the same.
func TestEveryVerdictColourIsDistinct(t *testing.T) {
	seen := map[string]finding.Result{}
	for _, r := range []finding.Result{finding.Pass, finding.Fail, finding.Unknown} {
		c := resultColor(r)
		if c == "" {
			t.Errorf("%s is painted with nothing", r)
			continue
		}
		if other, dup := seen[c]; dup {
			t.Errorf("%s and %s are painted identically (%q)", r, other, c)
		}
		seen[c] = r
	}
}

// TestEveryDiffCategoryColourIsDistinct. WP-30 specified four categories in
// four colours, and the point of the colour is that an operator scanning a
// nightly diff can tell a regression from a fix without reading either.
func TestEveryDiffCategoryColourIsDistinct(t *testing.T) {
	seen := map[string]diff.Category{}
	for _, cat := range diff.Categories {
		c := diffColor(cat)
		if c == "" {
			t.Errorf("%s is painted with nothing", cat)
			continue
		}
		if other, dup := seen[c]; dup {
			t.Errorf("%s and %s are painted identically (%q)", cat, other, c)
		}
		seen[c] = cat
	}
}

// TestColourOffEmitsNoEscapes covers the whole report, both mechanisms.
//
// It matters more than it looks. --output writes a file an operator reads
// months later in something that is not a terminal, and a dashboard border is
// no excuse for escape sequences in it. lipgloss is given the Ascii profile
// for exactly this and the assertion is that it honoured it.
func TestColourOffEmitsNoEscapes(t *testing.T) {
	s := newStyles(false)

	rendered := s.card.Render("PASS\n74") + s.gauge.Render("posture 96.6") +
		s.pass.Render("x") + s.fail.Render("x") + s.unknown.Render("x") +
		s.muted.Render("x") + s.label.Render("x") +
		bar(s, s.filled, 42)

	if strings.Contains(rendered, "\033") {
		t.Errorf("the dashboard emitted an escape sequence with colour off:\n%q", rendered)
	}
	// The boxes must still be drawn: degrading gracefully means losing the
	// colour, not losing the layout.
	if !strings.Contains(rendered, "╭") || !strings.Contains(rendered, "│") {
		t.Error("the dashboard lost its borders with colour off; only the colour should go")
	}
}

// TestColourOnEmitsTwentyFourBitColour is the other half: the hex palette
// reaches the terminal rather than being silently downsampled to nothing by a
// renderer that probed an environment it should never have looked at.
func TestColourOnEmitsTwentyFourBitColour(t *testing.T) {
	s := newStyles(true)

	if got := s.pass.Render("74"); !strings.Contains(got, "38;2;34;197;94") {
		t.Errorf("PASS did not render as 24-bit #22C55E: %q", got)
	}
}

// TestTheDashboardFitsTheGrid is the test this file exists for as much as the
// palette is.
//
// The first draft of the dashboard assumed lipgloss.Width was the total width
// of a box. It is the *inner* width and the border is added on top, so every
// box ran two columns over the grid — invisible on a wide terminal and a
// wrapped mess on the eighty-column one the grid exists for, which is where
// nobody was looking. Arithmetic that is checked by eye on the developer's own
// terminal is arithmetic that is not checked.
func TestTheDashboardFitsTheGrid(t *testing.T) {
	s := newStyles(false)

	for _, block := range []struct {
		what string
		got  string
	}{
		{"a card", s.card.Render("UNKNOWN\n42\nnot passes")},
		{"the gauge", s.gauge.Render("posture 100.0\n" + strings.Repeat("x", barWidth))},
	} {
		for i, line := range strings.Split(block.got, "\n") {
			if w := visibleWidth(line) + dashIndent; w > reportWidth {
				t.Errorf("%s line %d is %d columns wide; the grid is %d",
					block.what, i+1, w, reportWidth)
			}
		}
	}

	// And the four cards side by side, which is the constraint the per-card
	// width was solved for.
	row := cardCount*(cardWidth+borderCols) + (cardCount-1)*cardGap + dashIndent
	if row > reportWidth {
		t.Errorf("four cards plus their gaps are %d columns; the grid is %d", row, reportWidth)
	}
}

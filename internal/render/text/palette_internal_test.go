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

// TestTheSGRConstantsEncodeTheDeclaredPalette.
//
// The palette is declared in hex in summary.go, because that is the form a
// designer reads and the form the documentation quotes. What the terminal
// actually receives is the SGR constants in text.go, hand-written escape
// sequences with six decimal numbers in them. Nothing but this test says the
// two are the same colour, and a transposed digit in "38;2;34;197;94" is
// invisible in review and wrong on every terminal.
func TestTheSGRConstantsEncodeTheDeclaredPalette(t *testing.T) {
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
			t.Errorf("%s: the escape sequence encodes %s but the palette declares %s; "+
				"one was changed and the other was not", c.what, got, c.hex)
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
// no excuse for escape sequences in it.
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
// reaches the terminal rather than being lost somewhere between the constant
// and the box.
func TestColourOnEmitsTwentyFourBitColour(t *testing.T) {
	s := newStyles(true)

	if got := s.pass.Render("74"); !strings.Contains(got, "38;2;34;197;94") {
		t.Errorf("PASS did not render as 24-bit #22C55E: %q", got)
	}
}

// TestTheDashboardFitsTheGrid is the test this file exists for as much as the
// palette is.
//
// An earlier draft got the box arithmetic wrong by two columns per box —
// invisible on a wide terminal and a wrapped mess on the eighty-column one the
// grid exists for, which is where nobody was looking. Arithmetic that is
// checked by eye on the developer's own terminal is arithmetic that is not
// checked, and the drawing is now this package's own so there is no library
// left to blame for the convention.
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

// TestTheGaugeColoursItsBands pins the claim the posture gauge makes about
// what a number means: green from 90, amber from 70, red below it.
//
// And the rule that overrides all three — **coverage caps the colour posture is
// allowed to wear.** A score of 95 over 40% coverage is arithmetically correct
// and, painted green, is a lie an operator will act on: that is not a host
// which is nearly perfect, it is a host which was nearly not examined. The cap
// is the reason this is a test rather than three constants nobody reads.
func TestTheGaugeColoursItsBands(t *testing.T) {
	s := newStyles(true)

	for _, c := range []struct {
		what     string
		posture  float64
		coverage float64
		want     style
	}{
		{"a clean host", 96.6, 100, s.pass},
		{"exactly at the green band", 90, 100, s.pass},
		{"just below green", 89.9, 100, s.unknown},
		{"exactly at the amber band", 70, 100, s.unknown},
		{"just below amber", 69.9, 100, s.fail},
		{"a poor host", 12, 100, s.fail},

		// The cap. Each of these would be green or amber on posture alone.
		{"a high score over thin coverage", 99, 40, s.fail},
		{"a high score over partial coverage", 99, 75, s.unknown},
	} {
		got := gaugeTone(s, c.posture, c.coverage)
		if got != c.want {
			t.Errorf("%s (posture %.1f, coverage %.1f): tone %q, want %q",
				c.what, c.posture, c.coverage, got.code, c.want.code)
		}
	}
}

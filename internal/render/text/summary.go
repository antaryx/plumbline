package text

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// The scan summary is a dashboard: a posture gauge across the grid and four
// count cards beneath it.
//
// ── why this is hand-drawn ──────────────────────────────────────────────────
//
// It was lipgloss for one release. What that library contributed here was a
// box border, a horizontal join and a hex-to-terminal downsample; what it cost
// was thirteen modules — termenv, go-colorful, go-runewidth, uniseg, terminfo,
// x/ansi, x/cellbuf, colorprofile and the rest — in a binary that runs as
// root, two of them pinned to untagged commits. Four direct and indirect
// dependencies became seventeen for a presentation-layer feature.
//
// That is the wrong trade for this program. CONTRIBUTING.md rule 7 says every import
// is supply-chain surface and the standard library is the default; a security
// auditor that asks to be trusted with root is the last place to spend that
// budget on decoration. The three things the library did are the three
// functions below, and this package already had the hard part — visibleWidth,
// which measures a string containing SGR escapes, and which is the thing
// text/tabwriter cannot do.
//
// The library also had to be actively restrained. Its package-level styles go
// through a global renderer that inspects os.Stdout at first use, which
// violates the OS seam and makes output depend on what the terminal answered.
// Nothing here can do that, because there is nothing here but strings.
//
// ── what does not move ──────────────────────────────────────────────────────
//
// Every width comes from reportWidth. The grid does not read $COLUMNS, so two
// scans of an unchanged host stay byte-identical and a nightly diff shows
// nothing. Colour flows through the same switch every other line in this
// package uses, so --no-color, NO_COLOR, a non-terminal stdout and --output all
// reach the dashboard through one decision rather than two.

// The palette, declared once in hex and mirrored by the SGR constants in
// text.go. TestTheSGRConstantsEncodeTheDeclaredPalette holds the two in step.
//
// Hex rather than the sixteen ANSI names, because the sixteen are whatever the
// user's theme says they are: "red" in one Solarized variant is a brown that
// disappears against the background, and a FAIL an operator cannot see is a
// FAIL that does not exist.
const (
	hexPass    = "#22C55E"
	hexFail    = "#EF4444"
	hexUnknown = "#F59E0B"
	hexMuted   = "#6B7280"
	hexBorder  = "#4B5563"
	hexText    = "#E5E7EB"
)

// Box-drawing characters. Rounded corners because the report is a summary
// rather than a table, and because every terminal font that has the sharp ones
// has these.
const (
	boxTopLeft     = "╭"
	boxTopRight    = "╮"
	boxBottomLeft  = "╰"
	boxBottomRight = "╯"
	boxHorizontal  = "─"
	boxVertical    = "│"
	barFull        = "█"
	barEmpty       = "░"
)

// Widths, all derived from the grid and none of them from the terminal.
const (
	dashIndent = 2
	dashWidth  = reportWidth - dashIndent // 76

	// borderCols is what a box costs beyond its inner width: one column of
	// border on each side. Stated once because the arithmetic below is solved
	// against it, and because getting it wrong is invisible on a wide terminal
	// and a wrapped mess on the eighty-column one the grid exists for.
	borderCols = 2
	// padCols is the single column of padding inside each border.
	padCols = 2

	cardGap   = 1
	cardCount = 4
	// Total per card is cardWidth+borderCols; four of those plus three gaps
	// must fit dashWidth. TestTheDashboardFitsTheGrid holds the arithmetic.
	cardWidth = (dashWidth - (cardCount-1)*cardGap - cardCount*borderCols) / cardCount

	gaugeWidth = dashWidth - borderCols
	// barWidth is what is left inside the gauge box once its padding is spent.
	barWidth = gaugeWidth - padCols
)

// Gauge colour bands. Named rather than inline because they are a claim about
// what a number means, and a claim like that should be findable and testable
// rather than buried in a switch. TestTheGaugeColoursItsBands pins them.
const (
	postureGreen = 90.0
	postureAmber = 70.0

	// Coverage caps the colour posture is allowed to wear, whatever the
	// posture is. A score of 95 over 40% coverage is not a host that is nearly
	// perfect, it is a host that was nearly not examined, and painting it green
	// is a lie an operator will act on.
	coverageRed   = 50.0
	coverageAmber = 90.0
)

// style is a colour, applied or not. It is the same switch paint() uses; the
// type exists so the dashboard reads as a set of named styles rather than as a
// scatter of escape constants.
type style struct {
	code  string
	color bool
}

func (s style) Render(text string) string {
	if !s.color || s.code == "" || text == "" {
		return text
	}
	return s.code + text + ansiReset
}

// box draws a rounded rectangle of a fixed inner width around a body.
type box struct {
	width  int // inner width, excluding the border
	border style
}

// Render frames body. Lines are padded or truncated to the text area, so a box
// is exactly the width it declares whatever it is given — a card whose note
// grew by a word must not push the row past the grid.
func (b box) Render(body string) string {
	text := b.width - padCols

	var out strings.Builder
	rule := strings.Repeat(boxHorizontal, b.width)
	out.WriteString(b.border.Render(boxTopLeft + rule + boxTopRight))

	for _, line := range strings.Split(body, "\n") {
		if visibleWidth(line) > text {
			line = truncate(line, text)
		}
		out.WriteString("\n")
		out.WriteString(b.border.Render(boxVertical))
		out.WriteString(" " + pad(line, text) + " ")
		out.WriteString(b.border.Render(boxVertical))
	}

	out.WriteString("\n")
	out.WriteString(b.border.Render(boxBottomLeft + rule + boxBottomRight))
	return out.String()
}

// joinHorizontal places rendered blocks side by side, separated by gap spaces.
//
// Blocks are aligned at the top and short ones are extended with blank lines of
// their own width, so a taller neighbour cannot drag the rest out of alignment.
// Every block here is the same height today; saying so keeps that true when one
// of them grows a second line of note.
func joinHorizontal(gap int, blocks ...string) string {
	if len(blocks) == 0 {
		return ""
	}

	split := make([][]string, len(blocks))
	widths := make([]int, len(blocks))
	tallest := 0
	for i, b := range blocks {
		split[i] = strings.Split(b, "\n")
		if len(split[i]) > tallest {
			tallest = len(split[i])
		}
		for _, l := range split[i] {
			if w := visibleWidth(l); w > widths[i] {
				widths[i] = w
			}
		}
	}

	var out strings.Builder
	for row := 0; row < tallest; row++ {
		if row > 0 {
			out.WriteString("\n")
		}
		for i, lines := range split {
			if i > 0 {
				out.WriteString(spaces(gap))
			}
			line := ""
			if row < len(lines) {
				line = lines[row]
			}
			out.WriteString(pad(line, widths[i]))
		}
	}
	return out.String()
}

// styles is the dashboard's palette, resolved once per report.
type styles struct {
	color bool

	card  box
	gauge box

	label   style
	muted   style
	value   style
	pass    style
	fail    style
	unknown style
	skipped style
	filled  style
	empty   style
}

func newStyles(color bool) *styles {
	s := func(code string) style { return style{code: code, color: color} }
	border := s(ansiDim)
	return &styles{
		color:   color,
		card:    box{width: cardWidth, border: border},
		gauge:   box{width: gaugeWidth, border: border},
		label:   s(ansiDim),
		muted:   s(ansiDim),
		value:   s(ansiBold),
		pass:    s(ansiGreen),
		fail:    s(ansiRed),
		unknown: s(ansiYellow),
		skipped: s(ansiDim),
		filled:  s(ansiGreen),
		empty:   s(ansiDim),
	}
}

func (p *printer) summary(in Input) {
	c := in.Score.Counts()
	s := newStyles(p.color)

	p.section("Scan summary")
	p.blank()

	p.block(p.gauge(s, in.Score))
	p.blank()
	p.block(p.cards(s, c, in.Findings))
	p.blank()

	p.line("  " + s.muted.Render(fmt.Sprintf("%d checks evaluated · catalog %d",
		c.Total, in.Score.CatalogVersion())))

	for _, note := range summaryNotes(in) {
		p.blank()
		for _, l := range wrap(note.text, detailWidth) {
			p.line("  " + note.style(s).Render(l))
		}
	}
	p.blank()
}

// block writes a multi-line rendered box at the report's indent.
func (p *printer) block(s string) {
	for _, l := range strings.Split(s, "\n") {
		p.line(spaces(dashIndent) + l)
	}
}

// gauge is the posture bar.
//
// **Posture is never drawn without coverage beside it**, which is the same
// invariant the JSON renderer enforces and for the same reason: a posture with
// no scale is a number that flatters an unexamined host. When either is
// undefined the box says so in words instead of drawing a bar, because an
// empty bar reads as zero and "nothing that carries weight was evaluated" is
// not zero.
func (p *printer) gauge(s *styles, sc score.Score) string {
	posture, hasPosture := sc.Posture()
	coverage, hasCoverage := sc.Coverage()

	if !hasPosture || !hasCoverage {
		return s.gauge.Render(s.muted.Render(
			"posture   undefined — nothing that carries weight was evaluated,\n" +
				"          which is not the same as zero"))
	}

	tone := gaugeTone(s, posture, coverage)
	fill := style{code: tone.code, color: s.color}

	coverTone := s.muted
	switch {
	case coverage < coverageRed:
		coverTone = s.fail
	case coverage < coverageAmber:
		coverTone = s.unknown
	}

	head := s.label.Render("posture") + "  " +
		tone.Render(fmt.Sprintf("%5.1f", posture)) + "   " +
		coverTone.Render(fmt.Sprintf("coverage %.1f%%", coverage)) +
		s.muted.Render(" of applicable checks")

	return s.gauge.Render(head + "\n" + bar(s, fill, posture))
}

// gaugeTone is the colour the posture number and its bar are drawn in.
//
// Green at 90 and above, amber from 70, red below it. The bands are a judgement
// about what an operator should feel on seeing the number, and they are
// deliberately harsh: a host at 85 has one in seven of its applicable checks
// failing, which is not a green situation.
//
// **Coverage then caps whatever posture earned.** A score of 95 over 40%
// coverage is arithmetically correct and, painted green, is a lie an operator
// will act on: that is not a host which is nearly perfect, it is a host which
// was nearly not examined. The cap only ever moves the colour downward.
//
// It is a separate function from the box it is drawn in so the rule can be
// tested as a rule, rather than by reading colours back out of rendered bytes.
func gaugeTone(s *styles, posture, coverage float64) style {
	switch postureBandFor(posture, coverage) {
	case bandFail:
		return s.fail
	case bandWarn:
		return s.unknown
	default:
		return s.pass
	}
}

// postureBand is which of the three the gauge colour rule lands on.
type postureBand int

const (
	bandPass postureBand = iota
	bandWarn
	bandFail
)

// postureBandFor is the rule itself, separated from the styles it is drawn
// with so that the live stream and the dashboard cannot disagree about what
// green means on one screen. Two implementations of a colour band would be two
// answers about the same number, which is the mistake this package spends its
// palette comment arguing against.
func postureBandFor(posture, coverage float64) postureBand {
	band := bandPass
	switch {
	case posture < postureAmber:
		band = bandFail
	case posture < postureGreen:
		band = bandWarn
	}

	switch {
	case coverage < coverageRed:
		return bandFail
	case coverage < coverageAmber:
		if band == bandPass {
			return bandWarn
		}
	}
	return band
}

// bar draws the filled proportion. The two block characters are full and light
// shade rather than a colour difference alone, so the bar is still readable
// with colour off, in a screenshot, and to anyone who cannot distinguish the
// two hues.
func bar(s *styles, fill style, posture float64) string {
	filled := int(posture / 100 * float64(barWidth))
	switch {
	case filled < 0:
		filled = 0
	case filled > barWidth:
		filled = barWidth
	}
	return fill.Render(strings.Repeat(barFull, filled)) +
		s.empty.Render(strings.Repeat(barEmpty, barWidth-filled))
}

// cards is the PASS / FAIL / UNKNOWN / SKIPPED row.
//
// NOT_APPLICABLE is deliberately not a card. It is the largest number on most
// hosts and the least actionable — a check whose subject is not installed —
// and giving it equal visual weight to FAIL would be the report arguing that
// they matter equally. It keeps its place in the note beneath.
func (p *printer) cards(s *styles, c score.Counts, findings []finding.Finding) string {
	type card struct {
		label string
		n     int
		style style
		note  string
	}
	cards := []card{
		{"PASS", c.Pass, s.pass, ""},
		{"FAIL", c.Fail, s.fail, ""},
		{"UNKNOWN", c.Unknown, s.unknown, unknownCardNote(c.Unknown)},
		{"SKIPPED", c.Skipped, s.skipped, skippedCardNote(findings)},
	}

	// A note row is added to every card or to none of them, so the four boxes
	// stay the same height. One taller card would drag the row's baseline and
	// leave the other three floating.
	hasNotes := false
	for _, cd := range cards {
		hasNotes = hasNotes || cd.note != ""
	}

	boxes := make([]string, 0, len(cards))
	for _, cd := range cards {
		// Header and number in one colour. They were a dim header over a
		// coloured number, which reads as two unrelated things stacked: the eye
		// lands on the word, finds it grey, and concludes the card is inactive.
		// One colour makes the card a single object that means one thing.
		body := cd.style.Render(cd.label) + "\n" + cd.style.Render(strconv.Itoa(cd.n))
		if hasNotes {
			body += "\n" + s.muted.Render(cd.note)
		}
		boxes = append(boxes, s.card.Render(body))
	}

	// Joined at the top so the boxes share a first row whatever their height.
	// They are all the same height here; saying so keeps that true if a note
	// ever wraps to a second line.
	row := joinHorizontal(cardGap, boxes...)

	// Footnotes carry what will not fit in a sixteen-column card, and they use
	// the enum spelling — NOT_APPLICABLE, not "not applicable" — because that
	// is the word in the JSON, in the schema and in the glossary. A report that
	// renamed the states for the sake of the layout would make an operator
	// translate between the screen and the document it came from.
	var notes []string
	if c.NotApplicable > 0 {
		notes = append(notes, fmt.Sprintf("  NOT_APPLICABLE %3d   the subject is not on this host", c.NotApplicable))
	}
	if c.Unknown > 0 {
		notes = append(notes, "  UNKNOWN is not a pass; the scan could not tell")
	}
	if n := acceptedCount(findings); n > 0 {
		notes = append(notes, fmt.Sprintf("  %d accepted risk(s) — see [=] Accepted risks above", n))
	}
	for _, n := range notes {
		row += "\n" + s.muted.Render(n)
	}
	return row
}

// acceptedCount is how many findings are SKIPPED because somebody accepted the
// risk, as opposed to being out of profile.
func acceptedCount(in []finding.Finding) int {
	n := 0
	for _, f := range in {
		if f.Suppression != nil {
			n++
		}
	}
	return n
}

func unknownCardNote(n int) string {
	if n == 0 {
		return ""
	}
	return "not passes"
}

// skippedCardNote splits the SKIPPED count into the two things it can mean.
// Without it a team that accepted twenty risks reads the same as a team whose
// profile filtered twenty checks out.
func skippedCardNote(in []finding.Finding) string {
	var accepted, outOfProfile int
	for _, f := range in {
		switch {
		case f.Suppression != nil:
			accepted++
		case f.SkippedBy != "":
			outOfProfile++
		}
	}
	switch {
	case accepted > 0 && outOfProfile > 0:
		return fmt.Sprintf("%d accepted", accepted)
	case accepted > 0:
		return fmt.Sprintf("%d accepted", accepted)
	case outOfProfile > 0:
		return "out of profile"
	default:
		return ""
	}
}

// summaryNote is a paragraph printed beneath the dashboard.
type summaryNote struct {
	text  string
	style func(*styles) style
}

func summaryNotes(in Input) []summaryNote {
	var out []summaryNote

	if n := in.Score.Counts().OutOfProfile; n > 0 {
		out = append(out, summaryNote{
			text: fmt.Sprintf(
				"Coverage is measured against profile %q, which selects %d of the %d checks in this "+
					"catalog. The %d outside it were not evaluated and are not counted against this host.",
				in.Scan.Profile, in.Score.Counts().Applicable(), in.Score.Counts().Total, n),
			style: func(s *styles) style { return s.muted },
		})
	}
	if in.Degraded {
		out = append(out, summaryNote{
			text: "This scan completed degraded: a collector could not gather a fact it was asked for, " +
				"so part of this host was never examined. The verdicts above are about what could be seen.",
			style: func(s *styles) style { return s.unknown },
		})
	}
	return out
}

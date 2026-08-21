package text

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// The scan summary is a dashboard: a posture gauge across the grid and four
// count cards beneath it. lipgloss draws the boxes and joins the cards
// horizontally; everything about *how wide* they are comes from this package.
//
// ── the renderer is explicit, and that is the whole trick ───────────────────
//
// lipgloss's package-level styles go through a global renderer that inspects
// os.Stdout at first use: it probes for a colour profile, reads $TERM and
// $COLORTERM, and on some terminals writes an OSC query and waits for the
// reply. None of that may happen here. Two rules this project is built on
// forbid it:
//
//   - **Only internal/system touches the OS** (CLAUDE.md rule 1). A library
//     that stats stdout at init is doing exactly what the seam exists to
//     prevent, and doing it somewhere --root could never reach.
//   - **A report is byte-identical across two runs of an unchanged host.**
//     That is what makes a nightly scan diff to nothing. Output that depends
//     on what the terminal answered is not that.
//
// So every style in this file comes from a renderer built over io.Discard with
// its profile passed in, which means lipgloss never probes anything and never
// writes anywhere. The bytes it produces are a pure function of the colour
// decision this package already made in useColor, and of nothing else.
//
// The same reasoning bans lipgloss.Width(terminal) and every automatic sizing
// helper. Widths here are derived from reportWidth, as everything in this
// package is.

// styles is one renderer's worth of pre-built styles.
//
// Built once per report rather than per row: a Style carries a pointer to its
// renderer, and constructing them in a loop would be both wasteful and a place
// for one row to end up on a different renderer from the rest.
type styles struct {
	r *lipgloss.Renderer

	card    lipgloss.Style
	gauge   lipgloss.Style
	label   lipgloss.Style
	muted   lipgloss.Style
	value   lipgloss.Style
	pass    lipgloss.Style
	fail    lipgloss.Style
	unknown lipgloss.Style
	skipped lipgloss.Style
	filled  lipgloss.Style
	empty   lipgloss.Style
}

// Hex rather than the sixteen ANSI names, because the sixteen are whatever the
// user's theme says they are: "red" in one Solarized variant is a brown that
// disappears against the background, and a FAIL an operator cannot see is a
// FAIL that does not exist. These are fixed, legible on both light and dark
// grounds, and downsampled by termenv for anything that cannot show them.
const (
	hexPass    = "#22C55E"
	hexFail    = "#EF4444"
	hexUnknown = "#F59E0B"
	hexMuted   = "#6B7280"
	hexBorder  = "#4B5563"
	hexText    = "#E5E7EB"
)

// newStyles builds the style set for one report.
//
// profile is Ascii when colour is off, which makes lipgloss strip every
// sequence it would otherwise emit — borders still draw, nothing is coloured.
// That is the graceful degradation path, and it is the same switch --no-color,
// NO_COLOR, a non-terminal stdout and --output already flow through, so there
// is exactly one decision about colour in this package rather than two.
func newStyles(color bool) *styles {
	profile := termenv.Ascii
	if color {
		profile = termenv.TrueColor
	}
	// io.Discard, not the report's writer. The renderer is used only to build
	// strings; it must never write, and giving it somewhere to write is how it
	// would end up probing what it was given.
	r := lipgloss.NewRenderer(discard{}, termenv.WithProfile(profile))
	r.SetColorProfile(profile)

	border := lipgloss.RoundedBorder()
	base := r.NewStyle().
		Border(border).
		BorderForeground(lipgloss.Color(hexBorder)).
		Padding(0, 1)

	return &styles{
		r:       r,
		card:    base.Width(cardWidth),
		gauge:   base.Width(gaugeWidth),
		label:   r.NewStyle().Foreground(lipgloss.Color(hexMuted)),
		muted:   r.NewStyle().Foreground(lipgloss.Color(hexMuted)),
		value:   r.NewStyle().Foreground(lipgloss.Color(hexText)).Bold(true),
		pass:    r.NewStyle().Foreground(lipgloss.Color(hexPass)).Bold(true),
		fail:    r.NewStyle().Foreground(lipgloss.Color(hexFail)).Bold(true),
		unknown: r.NewStyle().Foreground(lipgloss.Color(hexUnknown)).Bold(true),
		skipped: r.NewStyle().Foreground(lipgloss.Color(hexMuted)).Bold(true),
		filled:  r.NewStyle().Foreground(lipgloss.Color(hexPass)),
		empty:   r.NewStyle().Foreground(lipgloss.Color(hexBorder)),
	}
}

// discard is io.Discard as a concrete type, so that nothing can type-assert
// the renderer's writer back into something writable.
type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }

// Widths, all derived from the grid and none of them from the terminal.
//
// The dashboard sits at the same two-column indent as the rest of the report.
// Four cards with a single column between them have to fit what is left, and
// lipgloss counts the border and the padding as part of Width, so the number
// below is the whole card including both.
const (
	dashIndent = 2
	dashWidth  = reportWidth - dashIndent // 76

	// **lipgloss.Width sets the inner width and adds the border on top.** The
	// first draft of this file assumed it was the total and every box ran two
	// columns over the grid — invisible on a wide terminal and a wrapped mess
	// on an eighty-column one, which is the width the grid exists for.
	// borderCols is that difference, stated once.
	borderCols = 2

	cardGap   = 1
	cardCount = 4
	// Total per card is cardWidth+borderCols; four of those plus three gaps
	// must fit dashWidth. TestTheDashboardFitsTheGrid holds the arithmetic.
	cardWidth = (dashWidth - (cardCount-1)*cardGap - cardCount*borderCols) / cardCount

	gaugeWidth = dashWidth - borderCols
	// barWidth is what is left inside the gauge box once its padding is spent.
	barWidth = gaugeWidth - 2
)

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

	tone := s.pass
	fill := s.filled.Foreground(lipgloss.Color(hexPass))
	switch {
	case posture < 60:
		tone, fill = s.fail, s.filled.Foreground(lipgloss.Color(hexFail))
	case posture < 85:
		tone, fill = s.unknown, s.filled.Foreground(lipgloss.Color(hexUnknown))
	}

	// **Coverage caps the colour posture is allowed to wear.** A posture of 86
	// over 17% coverage is arithmetically correct and, painted green, is a lie
	// an operator will act on: that is not a host which is mostly fine, it is a
	// host which was mostly not examined.
	coverTone := s.muted
	switch {
	case coverage < 50:
		coverTone, tone = s.fail, s.fail
		fill = s.filled.Foreground(lipgloss.Color(hexFail))
	case coverage < 90:
		coverTone = s.unknown
		if posture >= 85 {
			tone = s.unknown
			fill = s.filled.Foreground(lipgloss.Color(hexUnknown))
		}
	}

	head := s.label.Render("posture") + "  " +
		tone.Render(fmt.Sprintf("%5.1f", posture)) + "   " +
		coverTone.Render(fmt.Sprintf("coverage %.1f%%", coverage)) +
		s.muted.Render(" of applicable checks")

	return s.gauge.Render(head + "\n" + bar(s, fill, posture))
}

// bar draws the filled proportion. The two block characters are full and light
// shade rather than a colour difference alone, so the bar is still readable
// with colour off, in a screenshot, and to anyone who cannot distinguish the
// two hues.
func bar(s *styles, fill lipgloss.Style, posture float64) string {
	filled := int(posture / 100 * float64(barWidth))
	switch {
	case filled < 0:
		filled = 0
	case filled > barWidth:
		filled = barWidth
	}
	return fill.Render(strings.Repeat("█", filled)) +
		s.empty.Render(strings.Repeat("░", barWidth-filled))
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
		style lipgloss.Style
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
		body := s.label.Render(cd.label) + "\n" + cd.style.Render(strconv.Itoa(cd.n))
		if hasNotes {
			body += "\n" + s.muted.Render(cd.note)
		}
		boxes = append(boxes, s.card.Render(body))
	}

	// Joined at the top so the boxes share a first row whatever their height.
	// They are all the same height here; saying so keeps that true if a note
	// ever wraps to a second line.
	row := lipgloss.JoinHorizontal(lipgloss.Top, interleave(boxes, spaces(cardGap))...)

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

func interleave(in []string, sep string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in)*2-1)
	for i, s := range in {
		if i > 0 {
			out = append(out, sep)
		}
		out = append(out, s)
	}
	return out
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
	style func(*styles) lipgloss.Style
}

func summaryNotes(in Input) []summaryNote {
	var out []summaryNote

	if n := in.Score.Counts().OutOfProfile; n > 0 {
		out = append(out, summaryNote{
			text: fmt.Sprintf(
				"Coverage is measured against profile %q, which selects %d of the %d checks in this "+
					"catalog. The %d outside it were not evaluated and are not counted against this host.",
				in.Scan.Profile, in.Score.Counts().Applicable(), in.Score.Counts().Total, n),
			style: func(s *styles) lipgloss.Style { return s.muted },
		})
	}
	if in.Degraded {
		out = append(out, summaryNote{
			text: "This scan completed degraded: a collector could not gather a fact it was asked for, " +
				"so part of this host was never examined. The verdicts above are about what could be seen.",
			style: func(s *styles) lipgloss.Style { return s.unknown },
		})
	}
	return out
}

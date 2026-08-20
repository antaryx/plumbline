package text

import (
	"fmt"
	"io"

	"github.com/antaryx/plumbline/internal/diff"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/score"
)

// DiffInput is everything a comparison report is made of.
//
// The two scores are passed whole for the reason every other renderer in this
// package takes them whole: posture is never shown without coverage, and
// making that a property of the type is what stops it being a rule somebody
// has to remember.
type DiffInput struct {
	Tool     Tool
	Old      DiffSide
	New      DiffSide
	Result   diff.Result
	OldScore score.Score
	NewScore score.Score
	Color    bool
}

// DiffSide describes one of the two bundles being compared.
type DiffSide struct {
	Path string
	Scan Scan
}

// diffColor maps a category to its escape sequence. The four the operator acts
// on are coloured; the fifth is not good news or bad news on its own.
func diffColor(c diff.Category) string {
	switch c {
	case diff.Resolved:
		return ansiGreen
	case diff.NewFailure:
		return ansiRed
	case diff.NewlySuppressed:
		return ansiCyan
	case diff.Regressed:
		return ansiYellow
	default:
		return ansiDim
	}
}

// RenderDiff writes a comparison of two evaluations.
//
// The layout is the scan report's, deliberately: the same 78-column grid, the
// same `[+]` and `[=]` markers, the same bracketed status flush right. An
// operator who has learned to read one should not have to learn the other.
func RenderDiff(w io.Writer, in DiffInput) error {
	p := &printer{w: w, color: in.Color}

	p.diffHeader(in)
	p.diffChanges(in.Result)
	p.diffSummary(in)

	return p.err
}

func (p *printer) diffHeader(in DiffInput) {
	name := in.Tool.Name
	if name == "" {
		name = "plumbline"
	}
	p.line(p.paint(ansiBold, fmt.Sprintf("%s %s", name, in.Tool.Version)) +
		p.paint(ansiDim, fmt.Sprintf("   catalog %d   diff", in.NewScore.CatalogVersion())))
	p.blank()
	p.line("  " + p.paint(ansiDim, pad("old", 8)) + p.describeSide(in.Old))
	p.line("  " + p.paint(ansiDim, pad("new", 8)) + p.describeSide(in.New))
	p.blank()
	// Said once, at the top, because it is the reason the comparison means
	// anything: both sides were judged by the same code.
	p.line("  " + p.paint(ansiDim,
		fmt.Sprintf("Both bundles were re-evaluated with catalog %d, so every change below is a", in.NewScore.CatalogVersion())))
	p.line("  " + p.paint(ansiDim, "change in the host rather than a change in the tool."))
}

func (p *printer) describeSide(s DiffSide) string {
	out := s.Path
	if !s.Scan.Started.IsZero() {
		out += p.paint(ansiDim, "   "+s.Scan.Started.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if s.Scan.Host != nil && s.Scan.Host.Hostname != "" {
		out += p.paint(ansiDim, "   "+s.Scan.Host.Hostname)
	}
	return out
}

// diffChanges prints one group per category, skipping the empty ones.
func (p *printer) diffChanges(r diff.Result) {
	if r.Empty() {
		p.blank()
		p.line("  " + p.paint(ansiDim, "No change. Every check reached the same verdict in both bundles."))
		return
	}

	// Measured across the whole report so the bracket column holds from the
	// first group to the last, exactly as the scan phase does.
	sw := diffStatusWidth(r)
	titleWidth := reportWidth - scanIndent - statusGap - sw
	if titleWidth < 16 {
		titleWidth = 16
	}

	for _, cat := range diff.Categories {
		changes := r.Of(cat)
		if len(changes) == 0 {
			continue
		}
		p.blank()
		p.line(p.paint(ansiBold, "[+] "+string(cat)) + "  " +
			p.paint(ansiDim, fmt.Sprintf("· %d", len(changes))))

		for _, c := range changes {
			f := c.Finding()
			p.printf("  - %s%s%s\n",
				pad(truncate(cell(f.Title), titleWidth), titleWidth),
				spaces(statusGap),
				p.paint(diffColor(cat), padLeft(transition(c), sw)))
			p.diffDetail(c)
			p.flush()
		}
	}
}

// diffDetail is the one line under a change that says which finding it was and
// why it moved. The check ID is here rather than in the title column because a
// diff is what an operator pastes into a ticket, and a title without an ID is
// not something anyone can look up.
func (p *printer) diffDetail(c Change) {
	f := c.Finding()
	line := "      " + p.paint(ansiDim, "- ") + p.paint(ansiBold, f.CheckID)
	if subject := cell(f.Subject); subject != "" {
		line += p.paint(ansiDim, "  ·  ") + truncate(subject, 40)
	}
	p.line(line)

	// A newly suppressed finding states the reason it was accepted; an
	// acceptance nobody can read is the thing suppression was built not to be.
	if c.Category == diff.NewlySuppressed && c.New != nil && c.New.Suppression != nil {
		for _, l := range wrap(c.New.Suppression.Justification, fieldWidth) {
			p.line(spaces(8) + p.paint(ansiDim, l))
		}
	}
	// A regression says what lapsed, so it is obvious the host may not have
	// changed at all.
	if c.Category == diff.Regressed && c.Old != nil && c.Old.Suppression != nil {
		note := "the acceptance is no longer in force"
		if c.Old.Suppression.ExpiresAt != "" {
			note = "the acceptance expired " + c.Old.Suppression.ExpiresAt
		}
		p.line(spaces(8) + p.paint(ansiDim, note))
	}
}

// Change is aliased so this file does not import diff twice under two names.
type Change = diff.Change

// transition is the bracketed token for one change: what it was, what it is.
//
// Both ends are shown rather than just the new state, because "RESOLVED" alone
// does not distinguish a check that started passing from one whose subject
// stopped existing — and on a host audit those are very different pieces of
// news.
func transition(c Change) string {
	return "[ " + sideLabel(c.Old) + " → " + sideLabel(c.New) + " ]"
}

// sideLabel names one side of a transition, or says the finding was not there.
func sideLabel(f *finding.Finding) string {
	if f == nil {
		return "ABSENT"
	}
	if f.Suppression != nil {
		return "SUPPRESSED"
	}
	return string(f.Result)
}

func diffStatusWidth(r diff.Result) int {
	w := 0
	for _, c := range r.Changes {
		if n := len(transition(c)); n > w {
			w = n
		}
	}
	return w
}

// diffSummary is the posture delta, which is the number somebody screenshots.
func (p *printer) diffSummary(in DiffInput) {
	p.section("Change summary")
	p.blank()

	for _, cat := range diff.Categories {
		if n := len(in.Result.Of(cat)); n > 0 {
			p.line("  " + p.paint(diffColor(cat), pad(string(cat), 18)) + padLeft(fmt.Sprint(n), 4))
		}
	}
	if in.Result.Empty() {
		p.line("  " + p.paint(ansiDim, "no changes"))
	}

	p.blank()
	p.line("  " + pad("posture", 18) + p.deltaLine(in.OldScore, in.NewScore))
	p.line("  " + pad("coverage", 18) + p.coverageDeltaLine(in.OldScore, in.NewScore))
	p.blank()
}

// deltaLine renders "86.4 → 92.1 (+5.7)", or explains why there is no number.
//
// **A posture delta is never shown without the coverage delta beneath it**,
// which is the same invariant the scan report enforces and for the same
// reason: posture rising because four checks stopped being able to tell is not
// an improvement, and the two numbers side by side are the only way to see it.
func (p *printer) deltaLine(oldS, newS score.Score) string {
	before, hadBefore := oldS.Posture()
	after, hasAfter := newS.Posture()
	if !hadBefore || !hasAfter {
		return p.paint(ansiDim, "undefined on one side — nothing that carries weight was evaluated there")
	}
	return fmt.Sprintf("%.1f → %.1f   %s", before, after, p.delta(after-before))
}

func (p *printer) coverageDeltaLine(oldS, newS score.Score) string {
	before, hadBefore := oldS.Coverage()
	after, hasAfter := newS.Coverage()
	if !hadBefore || !hasAfter {
		return p.paint(ansiDim, "undefined on one side — no check applied to that host")
	}
	return fmt.Sprintf("%.1f%% → %.1f%%   %s", before, after, p.delta(after-before))
}

// delta formats a signed change, coloured by direction and left plain when
// nothing moved. A "+0.0" painted green would report an improvement that did
// not happen.
func (p *printer) delta(d float64) string {
	switch {
	case d > 0.05:
		return p.paint(ansiGreen, fmt.Sprintf("(+%.1f)", d))
	case d < -0.05:
		return p.paint(ansiRed, fmt.Sprintf("(%.1f)", d))
	default:
		return p.paint(ansiDim, "(no change)")
	}
}

package text

import (
	"fmt"
	"io"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// ExplainInput is one catalog entry, rendered for a person.
//
// It takes the fields rather than a catalog.Check because this package must
// not import the catalog: internal/catalog imports internal/finding, and a
// renderer that reached back into the catalog would make the dependency run
// both ways. The caller flattens; the shape below is the contract.
type ExplainInput struct {
	ID           string
	Module       string
	Title        string
	Description  string
	BaseSeverity finding.Severity
	Tags         []string
	// Requires names the facts the check reads. Rendered because it is the
	// honest answer to "why did this come back UNKNOWN on my host" — a check
	// whose facts were not collected cannot reach a verdict, and the runner
	// says so automatically.
	Requires    []string
	Remediation *finding.Remediation
	Mappings    []finding.ControlRef
	References  []finding.Reference

	SinceCatalog int
	// Deprecated is the reason and replacement when a check is on its way out.
	// A check that still runs but should not be relied on has to say so where
	// somebody reading about it will see it.
	Deprecated        string
	DeprecatedSince   int
	DeprecatedReplace []string

	Color bool
}

// stepIndent is how far a numbered remediation step sits from the margin.
const stepIndent = 4

// RenderExplain writes a catalog entry in the manner of a man page.
//
// **This is where remediation steps and commands live.** The scan report
// deliberately prints only a remediation summary — a block running to forty
// lines per finding is one an operator scrolls past — and the full procedure
// has to be somewhere an operator can ask for it by ID. That somewhere is
// here.
//
// The layout reuses the scan report's 78-column grid and its `[=]` section
// markers on purpose: an operator who has learned to read one report should
// not have to learn a second.
func RenderExplain(w io.Writer, in ExplainInput) error {
	p := &printer{w: w, color: in.Color}

	p.explainHeader(in)
	p.explainDescription(in)
	p.explainFacts(in)
	p.explainRemediation(in)
	p.explainReferences(in)

	return p.err
}

func (p *printer) explainHeader(in ExplainInput) {
	// The title rides beside the ID when it fits and drops beneath it when it
	// does not. Truncating is wrong here in a way it is not in the scan
	// report: this page *is* the reference for the check, and a reference that
	// clips the sentence describing its subject has failed at its one job.
	id := p.paint(ansiBold, in.ID)
	title := cell(in.Title)
	if len(in.ID)+2+visibleWidth(title) <= reportWidth {
		p.line(id + "  " + title)
	} else {
		p.line(id)
		for _, l := range wrap(title, reportWidth-2) {
			p.line("  " + p.paint(ansiBold, l))
		}
	}
	p.blank()

	row := func(label, value string) {
		if value == "" {
			return
		}
		p.line("  " + p.paint(ansiDim, pad(label, 10)) + value)
	}
	row("module", in.Module)
	row("severity", p.severityWord(in.BaseSeverity))
	if in.SinceCatalog > 0 {
		row("since", fmt.Sprintf("catalog %d", in.SinceCatalog))
	}
	if len(in.Tags) > 0 {
		row("tags", strings.Join(in.Tags, ", "))
	}

	if in.Deprecated != "" {
		p.blank()
		head := "DEPRECATED"
		if in.DeprecatedSince > 0 {
			head += fmt.Sprintf(" since catalog %d", in.DeprecatedSince)
		}
		p.line("  " + p.paint(ansiYellow, head))
		for _, l := range wrap(in.Deprecated, detailWidth) {
			p.line("  " + p.paint(ansiYellow, l))
		}
		if len(in.DeprecatedReplace) > 0 {
			p.line("  " + p.paint(ansiYellow, "replaced by "+strings.Join(in.DeprecatedReplace, ", ")))
		}
	}
}

// severityWord colours by impact, matching the scan report so the same word
// means the same thing in both places.
func (p *printer) severityWord(s finding.Severity) string {
	code := ""
	switch s {
	case finding.Critical, finding.High:
		code = ansiRed
	case finding.Medium:
		code = ansiYellow
	}
	return p.paint(code, string(s)) + p.paint(ansiDim, "  (before any context adjustment)")
}

func (p *printer) explainDescription(in ExplainInput) {
	blocks := wrapBlocks(in.Description, detailWidth)
	if len(blocks) == 0 {
		return
	}
	p.section("What this checks")
	for _, block := range blocks {
		p.blank()
		for _, l := range block {
			p.line("  " + l)
		}
	}
}

func (p *printer) explainFacts(in ExplainInput) {
	if len(in.Requires) == 0 {
		return
	}
	p.section("Facts it reads")
	p.blank()
	for _, f := range in.Requires {
		p.line("  " + p.paint(ansiDim, "- ") + cell(f))
	}
	p.blank()
	for _, l := range wrap("If any of these was not collected — a file this scan could not read, "+
		"a collector that failed — the check reports UNKNOWN rather than guessing. "+
		"That is the runner's doing, not the check's: it never sees a missing fact.",
		detailWidth) {
		p.line("  " + p.paint(ansiDim, l))
	}
}

func (p *printer) explainRemediation(in ExplainInput) {
	r := in.Remediation
	if r == nil {
		return
	}
	title := "Remediation"
	if r.Effort != "" {
		title += fmt.Sprintf(" (effort %s)", r.Effort)
	}
	p.section(title)
	p.blank()

	for _, l := range wrap(r.Summary, detailWidth) {
		p.line("  " + l)
	}

	if len(r.Steps) > 0 {
		p.blank()
		p.line("  " + p.paint(ansiDim, "steps"))
		for i, step := range r.Steps {
			prefix := fmt.Sprintf("%d. ", i+1)
			// The width is what the grid has left after the indent and the
			// number, not detailWidth minus a guess: a step is indented four
			// columns further than prose and the numbering eats three more.
			lines := wrap(step, reportWidth-stepIndent-len(prefix))
			for j, l := range lines {
				if j == 0 {
					p.line(spaces(stepIndent) + p.paint(ansiDim, prefix) + l)
					continue
				}
				p.line(spaces(stepIndent+len(prefix)) + l)
			}
		}
	}

	if len(r.Commands) > 0 {
		p.blank()
		p.line("  " + p.paint(ansiDim, "commands"))
		for _, c := range r.Commands {
			// Not wrapped. A command broken across lines is a command that
			// does something else when pasted, and this is the one place in
			// the tool whose output an operator is expected to run.
			p.line("    " + p.paint(ansiDim, "$ ") + cell(c))
		}
		p.blank()
		for _, l := range wrap("Plumbline never runs these. It reports and explains; "+
			"applying a change is the operator's decision and the operator's hand.", detailWidth) {
			p.line("  " + p.paint(ansiDim, l))
		}
	}

	if r.Caution != "" {
		p.blank()
		for _, l := range wrap("CAUTION: "+r.Caution, detailWidth) {
			p.line("  " + p.paint(ansiYellow, l))
		}
	}
}

func (p *printer) explainReferences(in ExplainInput) {
	if len(in.Mappings) == 0 && len(in.References) == 0 {
		return
	}
	p.section("References")
	p.blank()

	if len(in.Mappings) > 0 {
		for _, m := range in.Mappings {
			p.line("  " + p.paint(ansiDim, pad(cell(m.Framework), 22)) + cell(m.Control))
		}
	}
	if len(in.References) > 0 {
		if len(in.Mappings) > 0 {
			p.blank()
		}
		for _, r := range in.References {
			// The title is prose and wraps. The URL never does: a wrapped URL
			// is one an operator cannot click or copy, which is the whole
			// reason it is printed.
			for _, l := range wrap(r.Title, reportWidth-2) {
				p.line("  " + l)
			}
			if r.URL != "" {
				p.line("    " + p.paint(ansiDim, cell(r.URL)))
			}
		}
	}
	p.blank()
}

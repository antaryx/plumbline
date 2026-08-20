// Package text renders findings for a person reading a terminal.
//
// It is the default output and it is not the API. `findings/v1` is the API
// (ADR-0007); this package is free to change layout in a patch release, and
// nothing may parse it. Anything that needs to be read by a program asks for
// `--format json`, which is why the two renderers are separate packages over
// the same model rather than one renderer with a mode flag.
//
// The report is in two phases, in the manner of lynis. The **scan phase** is a
// status column and nothing else: one line per check, its title on the left and
// a bracketed verdict flush against the right edge of a fixed grid. The
// **suggestion phase** at the bottom carries every detail, every piece of
// evidence and every remediation, gathered together. Interleaving the two —
// which is what this package used to do — puts forty lines of advice between
// two check results and destroys the one thing the layout is for, which is a
// column of brackets an operator can run their eye down.
//
// Four properties are load-bearing, and each exists because the obvious
// implementation gets it wrong.
//
// **UNKNOWN is never quiet.** A tool that lists failures and buries what it
// could not determine is reporting a cleaner host than it actually saw. Every
// UNKNOWN gets the same entry a FAIL gets under its own heading in the
// suggestion phase, the summary states the count on its own line, and coverage
// is printed beside posture every single time — because 100 over two checks out
// of two hundred is not a clean host, it is an unexamined one. Moving the
// detail to the bottom was a change of layout and must never become a change of
// emphasis.
//
// **The grid is fixed, not terminal-derived.** Two reports of an unchanged host
// have to be byte-identical or a nightly diff is noise. See reportWidth.
//
// **Colour is a decision the caller makes, not one this package infers.** It
// takes a bool. The three rules that produce that bool — --no-color, NO_COLOR,
// and stdout not being a terminal — live in internal/cli where the flags and
// the environment are, and the seam's system.IsTerminal answers the third.
//
// **text/tabwriter measures a cell in runes, and an escape sequence is runes.**
// The consequence is narrower than "never colour a table", and getting it
// exactly right is what keeps the report aligned: a column stays aligned as
// long as every cell in it carries the *same* escape sequences, because they
// all inflate by the same amount and so does the maximum the padding is
// computed from. A column with some cells coloured and some not is the broken
// case, and it is broken silently. This package therefore obeys one rule —
// **a tabwriter column is either entirely uncoloured or uniformly coloured** —
// and where a column genuinely holds mixed colours, as the results do, it pads
// by hand with a width function that skips escape sequences instead.
package text

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/sanitize"
	"github.com/antaryx/plumbline/internal/score"
)

// ANSI escape sequences. Deliberately the plain SGR set: these are what every
// terminal emulator written since 1979 understands, and a report an operator
// cannot read on a serial console is not a better report for being prettier.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

// Tool identifies the binary that produced the report.
type Tool struct {
	Name    string
	Version string
	Commit  string
}

// Host describes the machine. Absent or partial under --redact, and the
// renderer says "(redacted)" rather than printing an empty field, because a
// blank where a hostname should be reads as a bug.
type Host struct {
	Hostname  string
	OSVersion string
	Kernel    string
	Arch      string
}

// Scan records the conditions the findings were produced under.
type Scan struct {
	Started  time.Time
	Finished time.Time
	Root     string
	EUID     int
	Profile  string
	Host     *Host
}

// Input is everything a report is made of.
//
// Score is passed whole rather than as two numbers, for the reason the JSON
// renderer takes it whole: it is what makes "posture is never shown without
// coverage" a property of the type rather than a rule someone has to remember.
type Input struct {
	Tool       Tool
	Scan       Scan
	Score      score.Score
	Findings   []finding.Finding
	FactErrors []fact.Error
	// Degraded reports that a collector failed, which is what makes coverage
	// less than complete. It corresponds to exit code 4.
	Degraded bool
	// Color enables ANSI escape sequences. See the package comment.
	Color bool
}

// Render writes a human-readable report to w.
//
// The output is deterministic for a given Input and Color: findings are sorted
// rather than ranged over from a map, so two reports of an unchanged host are
// byte-identical and diff to nothing.
func Render(w io.Writer, in Input) error {
	p := &printer{w: w, color: in.Color}

	p.header(in)
	p.scanPhase(in.Findings)
	p.factErrors(in.FactErrors)
	p.warningsAndSuggestions(in.Findings)
	p.accepted(in.Findings)
	p.summary(in)

	return p.err
}

// printer accumulates the first write error rather than checking every call.
// A report is written to a terminal or to a file; if the descriptor has gone
// away, every subsequent write fails too and the first error is the one worth
// reporting.
type printer struct {
	w     io.Writer
	color bool
	err   error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

func (p *printer) line(s string) { p.printf("%s\n", s) }
func (p *printer) blank()        { p.printf("\n") }

// flusher is implemented by a buffered writer. The scan phase calls flush
// after every check line so the report appears as it is produced rather than
// arriving all at once when the process exits.
//
// This is not an animation and there is no sleep anywhere in this package. A
// deliberate delay would be a lie about how long the work took, and on a host
// with 79 checks it would turn a 2 ms scan into a 2 s one for the sake of
// looking busy. What it does is remove *buffering* as a reason for the report
// to arrive in one lump: os.Stdout is already unbuffered, so in the real CLI
// every line is a write syscall the moment it is formatted, and this hook
// makes that true as well for a caller that wraps the writer.
type flusher interface{ Flush() error }

func (p *printer) flush() {
	if p.err != nil {
		return
	}
	if f, ok := p.w.(flusher); ok {
		p.err = f.Flush()
	}
}

// paint wraps s in an escape sequence, or returns it untouched when colour is
// off. Every colour in this package goes through here; there is no second path
// that could forget the switch.
func (p *printer) paint(code, s string) string {
	if !p.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

// ---------------------------------------------------------------------------
// header
// ---------------------------------------------------------------------------

// The report is laid out on a fixed grid, and every width in this package is
// derived from reportWidth rather than from the terminal.
//
// **The grid does not read $COLUMNS, and that is deliberate.** A report has to
// be byte-identical across two runs of an unchanged host — that is what makes
// a nightly scan diff to nothing and stay worth reading. A layout that follows
// the window would make the same host produce a different report on a laptop
// and in CI, and the diff between them would be noise about furniture.
// Eighty columns is the width every terminal, serial console and CI log pane
// agrees on, so the grid is two narrower than that to leave room for a pager's
// gutter.
const reportWidth = 78

// rule is computed rather than typed out, because a box-drawing character is
// three bytes and one accidentally missing from a literal is invisible in
// review and misaligns the report by a column.
var rule = strings.Repeat("─", reportWidth)

// section is a top-level report heading: `[=] Warnings and suggestions`.
//
// `[+]` marks a group of checks being run and `[=]` marks a conclusion drawn
// from them, which is the distinction Lynis draws and the reason the two
// markers exist rather than one.
func (p *printer) section(title string) {
	p.blank()
	p.line(p.paint(ansiBold, "[=] "+title))
	p.line(p.paint(ansiDim, rule))
}

// group is a module heading inside the scan phase: `[+] sshd`.
//
// The module's own identifier is printed rather than a prose name like "SSH
// configuration". A display-name table here would be a second place where the
// catalog's modules are enumerated, and the moment a module is added and the
// table is not updated the report starts lying about what it ran. The
// identifier is also what `--module` takes, so what is printed is what an
// operator can type back.
func (p *printer) group(name, tally string) {
	p.blank()
	p.line(p.paint(ansiBold, "[+] "+name) + "  " + p.paint(ansiDim, tally))
}

func (p *printer) header(in Input) {
	name := in.Tool.Name
	if name == "" {
		name = "plumbline"
	}
	p.line(p.paint(ansiBold, fmt.Sprintf("%s %s", name, in.Tool.Version)) +
		p.paint(ansiDim, fmt.Sprintf("   catalog %d", in.Score.CatalogVersion())))
	p.blank()

	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	row := func(label, value string) {
		if p.err != nil || value == "" {
			return
		}
		// The label is dimmed and the value is plain. Both are final-or-plain
		// cells, so tabwriter's rune counting is not being asked to measure an
		// escape sequence in a column anything else lines up against.
		_, p.err = fmt.Fprintf(tw, "  %s\t%s\n", p.paint(ansiDim, label), value)
	}

	row("host", p.describeHost(in.Scan.Host))
	row("root", displayRoot(in.Scan.Root))
	row("started", in.Scan.Started.UTC().Format("2006-01-02 15:04:05 UTC")+p.paint(ansiDim, elapsed(in.Scan)))
	row("euid", describeEUID(in.Scan.EUID))
	row("profile", in.Scan.Profile)

	if p.err == nil {
		p.err = tw.Flush()
	}
}

// describeHost renders the machine, saying "(redacted)" rather than printing
// nothing. A blank where a hostname belongs reads as a bug in the tool; an
// explicit note reads as the flag the operator passed.
func (p *printer) describeHost(h *Host) string {
	if h == nil || (h.Hostname == "" && h.OSVersion == "") {
		return p.paint(ansiDim, "(not recorded — --redact, or /etc/hostname was unreadable)")
	}
	name := h.Hostname
	if name == "" {
		name = p.paint(ansiDim, "(redacted)")
	}
	if h.OSVersion == "" {
		return name
	}
	return name + p.paint(ansiDim, "   "+h.OSVersion)
}

// displayRoot names the scan root. An empty root is a live scan of "/", and
// saying so is worth a word: the difference between auditing this machine and
// auditing a mounted image is the single most important piece of context in
// the header.
func displayRoot(root string) string {
	if root == "" || root == "/" {
		return "/  (live host)"
	}
	return root + "  (mounted image or container filesystem)"
}

// describeEUID says what the number means. "euid 1000" tells an operator
// nothing about why half the report is UNKNOWN; "not root" tells them exactly.
func describeEUID(euid int) string {
	if euid == 0 {
		return "0  (root)"
	}
	return fmt.Sprintf("%d  (not root — checks needing privileged reads will be UNKNOWN)", euid)
}

func elapsed(s Scan) string {
	if s.Started.IsZero() || s.Finished.IsZero() || s.Finished.Before(s.Started) {
		return ""
	}
	return fmt.Sprintf("   elapsed %s", s.Finished.Sub(s.Started).Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// results by module
// ---------------------------------------------------------------------------

// resultColor maps a result to its escape sequence.
//
// NOT_APPLICABLE and SKIPPED are dimmed rather than coloured. They are not
// good news and not bad news — they are the report saying this rule did not
// apply here — and giving them a colour of their own would put them in
// competition with the three states that carry a verdict.
func resultColor(r finding.Result) string {
	switch r {
	case finding.Pass:
		return ansiGreen
	case finding.Fail:
		return ansiRed
	case finding.Unknown:
		return ansiYellow
	default:
		return ansiDim
	}
}

// findingColor is resultColor with the suppression case folded in. A
// suppressed finding is dimmed rather than coloured: it is a decision the
// operator already made, and it should not compete for attention with the
// findings they have not yet dealt with.
func findingColor(f finding.Finding) string {
	if f.Suppression != nil {
		return ansiDim
	}
	return resultColor(f.Result)
}

// statusToken is the bracketed word a result is shown as.
//
// The mapping is not one-to-one with finding.Result, and the two places it
// bends are worth stating.
//
// **FAIL shows as WARNING.** The result state is still FAIL everywhere it
// matters — in the JSON, in the exit code, in the score — but the word an
// operator reads beside a check is the word that describes what to do about
// it, and "warning" is that word.
//
// **NOT_APPLICABLE and SKIPPED do not collapse into one token.** They are
// different facts: NOT_APPLICABLE means the subject is not on this host, and
// SKIPPED means the subject may well be here and the check was deliberately
// not run. Printing both as SKIPPED would tell an operator that a check was
// declined when in truth there was nothing to check, and the whole argument of
// this tool is that those states stay distinct.
func statusToken(f finding.Finding) string {
	// A suppressed finding is SKIPPED like any other, but it did not get there
	// the same way: somebody looked at a failure and accepted it. Giving it
	// its own token is what stops "we accepted this" reading identically to
	// "the profile did not run it".
	if f.Suppression != nil {
		return "[ SUPPRESSED ]"
	}
	switch f.Result {
	case finding.Pass:
		return "[ OK ]"
	case finding.Fail:
		return "[ WARNING ]"
	case finding.Unknown:
		return "[ UNKNOWN ]"
	case finding.NotApplicable:
		return "[ SKIPPED ]"
	case finding.Skipped:
		return "[ DISABLED ]"
	default:
		// An unrecognised result still gets a row. Dropping it would be the
		// worst possible response to a report from a newer catalog.
		return "[ " + string(f.Result) + " ]"
	}
}

// statusWidth is the width the status column occupies: the widest token
// actually present, not the widest that exists.
//
// Measuring the input rather than the enum keeps the common report tight — a
// host with no SKIPPED results should not carry four columns of padding on
// every line for the sake of a token that is not there — and it is still
// perfectly deterministic, because the width is a pure function of the
// findings. Two reports of an unchanged host stay byte-identical.
func statusWidth(in []finding.Finding) int {
	w := 0
	for _, f := range in {
		if n := len(statusToken(f)); n > w {
			w = n
		}
	}
	return w
}

// The scan-phase line is a fixed four-column grid:
//
//   - Root login is disabled over SSH ....................... [ OK ]
//     └┬┘└──────────────────── title ────────────────────────┘ └status┘
//     indent                                                 gap
//
// and the arithmetic that keeps the closing bracket flush right is one line:
//
//	titleWidth = reportWidth - scanIndent - statusGap - statusWidth(findings)
//
// so that indent + titleWidth + gap + statusWidth == reportWidth exactly. The
// title is left-padded to titleWidth and the status token is **right**-padded
// into statusWidth, which is what puts every `]` on the same column while the
// tokens themselves stay their natural width. Padding the word *inside* the
// brackets would align both brackets but produce `[ OK      ]`, which reads as
// a rendering bug rather than a status.
//
// Both pads go through visibleWidth, so a coloured token occupies exactly the
// columns it draws and the grid does not move when --no-color is dropped.
// TestColumnsAlignWithColourOn is the gate on that.
const (
	scanIndent = 4 // "  - "
	statusGap  = 1 // at least one space before the bracket
)

func (p *printer) scanPhase(findings []finding.Finding) {
	if len(findings) == 0 {
		return
	}

	// Measured across the whole report rather than per module, so the bracket
	// column holds from the first module to the last. A table that re-aligns
	// itself every few lines is harder to scan than a slightly wider one.
	sw := statusWidth(findings)
	titleWidth := reportWidth - scanIndent - statusGap - sw
	if titleWidth < 16 {
		// Only reachable if reportWidth is ever lowered below what a status
		// token needs. Sixteen columns of title is not useful, but a wrapped
		// grid is worse than a wide one.
		titleWidth = 16
	}

	for _, m := range modulesOf(findings) {
		p.group(m.name, p.moduleTally(m.findings))

		for _, f := range m.findings {
			title := truncate(cell(f.Title), titleWidth)
			p.printf("  - %s%s%s\n",
				pad(title, titleWidth),
				strings.Repeat(" ", statusGap),
				p.paint(findingColor(f), padLeft(statusToken(f), sw)))
			// Line by line, so a slow terminal shows the audit progressing
			// instead of sitting blank and then printing everything at once.
			p.flush()
		}
	}
}

// moduleTally summarises one module in the form an operator scans for: what
// went wrong, then what could not be told, then the rest.
func (p *printer) moduleTally(in []finding.Finding) string {
	var c score.Counts
	for _, f := range in {
		c.Total++
		switch f.Result {
		case finding.Pass:
			c.Pass++
		case finding.Fail:
			c.Fail++
		case finding.Unknown:
			c.Unknown++
		case finding.NotApplicable:
			c.NotApplicable++
		case finding.Skipped:
			c.Skipped++
		}
	}

	parts := []string{fmt.Sprintf("%d checks", c.Total)}
	if c.Fail > 0 {
		parts = append(parts, fmt.Sprintf("%d failing", c.Fail))
	}
	if c.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", c.Unknown))
	}
	if c.NotApplicable > 0 {
		parts = append(parts, fmt.Sprintf("%d n/a", c.NotApplicable))
	}
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", c.Skipped))
	}
	return "· " + strings.Join(parts, ", ")
}

type moduleGroup struct {
	name     string
	findings []finding.Finding
}

// modulesOf groups findings by module, sorting both the modules and the
// findings inside each one. Nothing here ranges over a map in output order:
// two reports of an unchanged host have to be byte-identical.
func modulesOf(in []finding.Finding) []moduleGroup {
	byModule := map[string][]finding.Finding{}
	for _, f := range in {
		byModule[f.Module] = append(byModule[f.Module], f)
	}

	names := make([]string, 0, len(byModule))
	for name := range byModule {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]moduleGroup, 0, len(names))
	for _, name := range names {
		group := byModule[name]
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].CheckID != group[j].CheckID {
				return group[i].CheckID < group[j].CheckID
			}
			return group[i].Subject < group[j].Subject
		})
		out = append(out, moduleGroup{name: name, findings: group})
	}
	return out
}

// ---------------------------------------------------------------------------
// the blocks that matter
// ---------------------------------------------------------------------------

// warningsAndSuggestions is the whole of the detail, gathered at the end.
//
// The scan phase above is a status column and nothing else: no detail, no
// evidence, no remediation. That is the point of the restructure — a report
// that interleaves forty lines of advice between check results is one an
// operator scrolls through rather than reads, and the run of brackets down the
// right-hand side is unreadable if something breaks it up every few rows.
//
// **UNKNOWN is here, under its own heading, at the same weight as a warning.**
// Moving detail to the bottom of the report was a change of layout and must
// not become a change of emphasis: a check that could not tell is not a check
// that passed, and a tool that lists failures in full while summarising its
// unknowns is describing a cleaner host than the one it examined. Both groups
// get the same entry shape, and the unknown group carries the sentence saying
// so in as many words.
func (p *printer) warningsAndSuggestions(findings []finding.Finding) {
	fails := withResult(findings, finding.Fail)
	unknowns := withResult(findings, finding.Unknown)
	if len(fails) == 0 && len(unknowns) == 0 {
		return
	}

	p.section("Warnings and suggestions")

	if len(fails) > 0 {
		sortBySeverityThenID(fails)
		p.blank()
		p.line("  " + p.paint(ansiRed, fmt.Sprintf("Warnings (%d)", len(fails))) +
			p.paint(ansiDim, "  ·  a check read the value and it does not meet the requirement"))
		for _, f := range fails {
			p.entry(f)
		}
	}

	if len(unknowns) > 0 {
		p.blank()
		p.line("  " + p.paint(ansiYellow, fmt.Sprintf("Could not determine (%d)", len(unknowns))) +
			p.paint(ansiDim, "  ·  these are not passes"))
		p.blank()
		p.line("  " + p.paint(ansiDim, "Each one is a question this scan could not answer, with the reason it"))
		p.line("  " + p.paint(ansiDim, "could not. Treat them as findings until they are resolved."))
		for _, f := range unknowns {
			p.entry(f)
		}
	}
}

// accepted lists the findings an operator suppressed, with the reason each one
// was accepted.
//
// This section is not optional decoration. A suppression file makes findings
// stop appearing in the warnings list, and a report that did not say so would
// let a host look clean because somebody wrote a JSON file — which is the
// exact failure mode this feature has to avoid. What went quiet, why, and what
// it would otherwise have said, all in one place.
func (p *printer) accepted(findings []finding.Finding) {
	var sup []finding.Finding
	for _, f := range findings {
		if f.Suppression != nil {
			sup = append(sup, f)
		}
	}
	if len(sup) == 0 {
		return
	}
	sort.SliceStable(sup, func(i, j int) bool {
		if sup[i].CheckID != sup[j].CheckID {
			return sup[i].CheckID < sup[j].CheckID
		}
		return sup[i].Subject < sup[j].Subject
	})

	p.section(fmt.Sprintf("Accepted risks (%d)", len(sup)))
	p.blank()
	p.line("  " + p.paint(ansiDim, "These are not passes either. Each one is a finding an operator accepted,"))
	p.line("  " + p.paint(ansiDim, "with the result it would otherwise have carried. They are excluded from"))
	p.line("  " + p.paint(ansiDim, "posture and from --fail-on, and they reduce coverage like any SKIPPED check."))

	for _, f := range sup {
		s := f.Suppression
		p.blank()
		id := "[" + f.CheckID + "]"
		title := truncate(cell(f.Title), reportWidth-4-1-visibleWidth(id))
		p.line("  " + p.paint(ansiDim, "*") + " " + title + " " + p.paint(ansiBold, id))
		p.field("Would be", p.paint(resultColor(s.OriginalResult), string(s.OriginalResult)))
		p.field("Severity", p.severityLabel(f))
		if subject := cell(f.Subject); subject != "" {
			p.fieldWrapped("Subject", f.Subject)
		}
		p.fieldWrapped("Accepted", s.Justification)
		if s.ExpiresAt != "" {
			p.field("Expires", s.ExpiresAt)
		}
		p.field("Fingerprint", p.paint(ansiDim, f.Fingerprint))
	}
}

// entry is one finding in full, in the shape Lynis uses for a suggestion: a
// starred headline carrying the check ID, then labelled detail lines beneath.
//
// The check ID is on the headline rather than buried, because it is the one
// field a suppression file matches on and the one an operator pastes into
// `docs/checks/<ID>.md`. It is never truncated for the same reason.
func (p *printer) entry(f finding.Finding) {
	p.blank()

	// "  * " + title + " " + "[ID]" must fit the grid. The ID is never the
	// part that gives, so the title absorbs the whole shortfall.
	id := "[" + f.CheckID + "]"
	title := truncate(cell(f.Title), reportWidth-4-1-visibleWidth(id))
	p.line("  " + p.paint(resultColor(f.Result), "*") + " " +
		title + " " + p.paint(ansiBold, id))

	p.field("Severity", p.severityLabel(f))
	if f.UnknownReason != "" {
		p.field("Reason", p.paint(ansiYellow, string(f.UnknownReason)))
	}
	p.fieldWrapped("Subject", f.Subject)
	p.fieldWrapped("Detail", f.Detail)

	if len(f.Evidence) > 0 {
		for i, e := range f.Evidence[:min(len(f.Evidence), maxEvidence)] {
			label := "Evidence"
			if i > 0 {
				label = ""
			}
			p.evidence(label, e)
		}
		if extra := len(f.Evidence) - maxEvidence; extra > 0 {
			p.continuation(p.paint(ansiDim,
				fmt.Sprintf("… and %d more; --json carries all of it", extra)))
		}
	}

	if f.Remediation != nil {
		p.remediation(*f.Remediation)
	}
}

// fieldLabel is the width of the label column in an entry. Every labelled line
// is "      - Label      : value", so the values line up down the entry and the
// labels can be skimmed without reading them.
// 11 rather than 10 because "Fingerprint" is the longest label any entry
// uses, and a label that overflows its column shifts that one line's value out
// of alignment with every other.
const fieldLabel = 11

func (p *printer) field(label, value string) {
	if value == "" {
		return
	}
	p.line("      " + p.paint(ansiDim, "- "+pad(label, fieldLabel)+": ") + value)
}

// continuation is a value line with no label, aligned under the values above
// it: 6 indent + 2 dash + label + 2 for ": ".
func (p *printer) continuation(value string) {
	p.line(strings.Repeat(" ", 6+2+fieldLabel+2) + value)
}

func (p *printer) fieldWrapped(label, value string) {
	lines := wrap(value, fieldWidth)
	for i, l := range lines {
		if i == 0 {
			p.field(label, l)
			continue
		}
		p.continuation(l)
	}
}

// severityLabel colours by impact. CRITICAL and HIGH are red because they are
// what an operator acts on today; MEDIUM is yellow; LOW and INFO are left
// plain, because colouring everything is the same as colouring nothing.
func (p *printer) severityLabel(f finding.Finding) string {
	code := ""
	switch f.Severity {
	case finding.Critical, finding.High:
		code = ansiRed
	case finding.Medium:
		code = ansiYellow
	}
	label := p.paint(code, string(f.Severity))
	if f.BaseSeverity != "" && f.BaseSeverity != f.Severity {
		label += p.paint(ansiDim, fmt.Sprintf(" (adjusted from %s)", f.BaseSeverity))
	}
	return label
}

// maxEvidence caps the excerpts one block prints.
//
// The cap is on the *display*, never on the verdict or the count: the line
// after it states how many were held back and where to get them, so the report
// never understates the thing it is summarising. A host with four hundred
// world-writable files produces a finding nobody reads if every one is listed.
const maxEvidence = 5

func (p *printer) evidence(label string, e finding.Evidence) {
	where := cell(e.Source)
	if where == "" {
		where = "(no source)"
	}
	if e.Line > 0 {
		where += fmt.Sprintf(":%d", e.Line)
	}
	if label != "" {
		p.field(label, p.paint(ansiDim, where))
	} else {
		p.continuation(p.paint(ansiDim, where))
	}
	for _, l := range wrap(e.Excerpt, fieldWidth) {
		p.continuation(l)
	}
}

func (p *printer) remediation(r finding.Remediation) {
	p.fieldWrapped("Remedy", r.Summary)
	if r.Effort != "" {
		p.field("Effort", r.Effort)
	}
	if r.Caution != "" {
		lines := wrap(r.Caution, fieldWidth)
		for i, l := range lines {
			if i == 0 {
				p.field("Caution", p.paint(ansiYellow, l))
				continue
			}
			p.continuation(p.paint(ansiYellow, l))
		}
	}
	// Steps and commands are deliberately not printed. A block that runs to
	// forty lines per finding is a block an operator scrolls past, and the
	// full remediation — every step, every command, every caution — is in the
	// JSON and in docs/checks/<ID>.md. What belongs here is enough to decide
	// whether to act now.
}

func withResult(in []finding.Finding, want finding.Result) []finding.Finding {
	var out []finding.Finding
	for _, f := range in {
		if f.Result == want {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CheckID != out[j].CheckID {
			return out[i].CheckID < out[j].CheckID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// severityRank orders the attention list. Unknown severities rank lowest
// rather than panicking: a severity this build does not recognise is still a
// finding, and dropping it would be the worst possible response.
func severityRank(s finding.Severity) int {
	switch s {
	case finding.Critical:
		return 5
	case finding.High:
		return 4
	case finding.Medium:
		return 3
	case finding.Low:
		return 2
	case finding.Info:
		return 1
	default:
		return 0
	}
}

func sortBySeverityThenID(in []finding.Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		ri, rj := severityRank(in[i].Severity), severityRank(in[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if in[i].CheckID != in[j].CheckID {
			return in[i].CheckID < in[j].CheckID
		}
		return in[i].Subject < in[j].Subject
	})
}

// ---------------------------------------------------------------------------
// collector failures
// ---------------------------------------------------------------------------

// factErrors reports what the scanner could not observe, as distinct from what
// it observed and disliked. The two are different problems with different
// remedies, and merging them into one list is how "we could not read
// /etc/shadow" ends up looking like a passing host.
func (p *printer) factErrors(errs []fact.Error) {
	if len(errs) == 0 {
		return
	}
	p.section(fmt.Sprintf("Collection gaps (%d)", len(errs)))
	p.blank()
	p.line(p.paint(ansiDim, "  Facts the scan could not gather. Every check that needed one of these"))
	p.line(p.paint(ansiDim, "  is UNKNOWN above, and coverage is reduced accordingly."))
	p.blank()

	sorted := append([]fact.Error(nil), errs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Fact != sorted[j].Fact {
			return sorted[i].Fact < sorted[j].Fact
		}
		return sorted[i].Path < sorted[j].Path
	})

	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	for _, e := range sorted {
		if p.err != nil {
			return
		}
		where := cell(e.Path)
		if where == "" {
			where = "—"
		}
		// The message is the final cell, so colouring it cannot disturb any
		// column to its left.
		_, p.err = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
			cell(string(e.Fact)), cell(string(e.Kind)), where,
			p.paint(ansiYellow, cell(e.Msg)))
	}
	if p.err == nil {
		p.err = tw.Flush()
	}
}

// ---------------------------------------------------------------------------
// summary
// ---------------------------------------------------------------------------

// summaryLabel and summaryCount are the two column widths of the footer.
//
// The footer is built by hand rather than with tabwriter, because its result
// column is the mixed-colour case: PASS is green, FAIL is red, SKIPPED is dim.
// Uniform colouring is what makes a tabwriter column safe, and this column is
// not uniform.
const (
	summaryLabel = 15
	summaryCount = 5
)

func (p *printer) summary(in Input) {
	c := in.Score.Counts()
	p.section("Scan summary")
	p.blank()

	row := func(colour, label string, n int, note string) {
		line := "  " + p.paint(colour, pad(label, summaryLabel)) + padLeft(strconv.Itoa(n), summaryCount)
		if note != "" {
			line += "   " + p.paint(ansiDim, note)
		}
		p.line(line)
	}

	row(ansiGreen, "PASS", c.Pass, "")
	row(ansiRed, "FAIL", c.Fail, "")
	row(ansiYellow, "UNKNOWN", c.Unknown, unknownNote(c.Unknown))
	row(ansiDim, "NOT_APPLICABLE", c.NotApplicable, "")
	row(ansiDim, "SKIPPED", c.Skipped, suppressedNote(in.Findings))

	p.blank()
	p.line("  " + pad("evaluated", summaryLabel) + padLeft(strconv.Itoa(c.Total), summaryCount) +
		p.paint(ansiDim, "   checks in catalog "+strconv.Itoa(in.Score.CatalogVersion())))
	p.line("  " + pad("posture", summaryLabel) + p.postureLine(in.Score))

	if in.Degraded {
		p.blank()
		for _, l := range wrap("This scan completed degraded: a collector could not gather a fact it was asked for, so part of this host was never examined. The verdicts above are about what could be seen.", detailWidth) {
			p.line("  " + p.paint(ansiYellow, l))
		}
	}
	p.blank()
}

// suppressedNote says how much of the SKIPPED count is accepted risk rather
// than a check the profile never ran. Without it the two are one number, and a
// team that suppressed twenty findings reads the same as a team that filtered
// twenty out.
func suppressedNote(in []finding.Finding) string {
	n := 0
	for _, f := range in {
		if f.Suppression != nil {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("← %d accepted risk(s); see above", n)
}

func unknownNote(n int) string {
	if n == 0 {
		return ""
	}
	return "← not passes; the scan could not tell"
}

// postureLine renders posture and coverage together, or explains why there is
// no number.
//
// **Posture is never printed without coverage**, which is the same invariant
// the JSON renderer enforces and for the same reason: a posture with no scale
// beside it is a number that flatters an unexamined host. Here it is enforced
// by there being exactly one function that can print the word "posture", and
// by every branch of it either printing both or printing neither.
func (p *printer) postureLine(sc score.Score) string {
	posture, hasPosture := sc.Posture()
	coverage, hasCoverage := sc.Coverage()

	if !hasPosture || !hasCoverage {
		return p.paint(ansiDim, "undefined — nothing that carries weight was evaluated, which is not the same as zero")
	}

	colour := ansiGreen
	switch {
	case posture < 60:
		colour = ansiRed
	case posture < 85:
		colour = ansiYellow
	}

	// **Coverage caps the colour posture is allowed to wear.** A posture of
	// 86 over 17% coverage is arithmetically correct and, painted green, is a
	// lie an operator will act on: it is not a host that is mostly fine, it is
	// a host that was mostly not examined. Low coverage therefore takes green
	// off the table no matter how well the handful of evaluated checks did.
	coverageColour := ansiDim
	switch {
	case coverage < 50:
		coverageColour = ansiRed
		colour = ansiRed
	case coverage < 90:
		coverageColour = ansiYellow
		if colour == ansiGreen {
			colour = ansiYellow
		}
	}

	return p.paint(colour, padLeft(fmt.Sprintf("%.1f", posture), summaryCount)) +
		"   " + p.paint(coverageColour, fmt.Sprintf("coverage %.1f%%", coverage)) +
		p.paint(ansiDim, " of applicable checks")
}

// ---------------------------------------------------------------------------
// width, padding and wrapping
// ---------------------------------------------------------------------------

const (
	// detailWidth is the wrap column for free prose that starts at the left
	// margin — the degraded-scan note in the summary.
	//
	// fieldWidth is the wrap column for a labelled value inside an entry, and
	// it is what is left of the grid once the indent, the dash, the label and
	// the colon have been spent: reportWidth - (6 + 2 + fieldLabel + 2).
	//
	// Both are fixed rather than read from the terminal, for the reason stated
	// on reportWidth: a report has to be byte-identical across two runs of an
	// unchanged host, and a width that depends on how wide somebody's window
	// happened to be is not.
	detailWidth = 76
	fieldWidth  = reportWidth - (6 + 2 + fieldLabel + 2)
)

// truncate shortens s to w visible columns, marking the cut with an ellipsis.
//
// This is used on titles and on nothing else. A title is prose written for
// this report and losing its tail costs a few words of context; a check ID, a
// path or an evidence excerpt is a value an operator copies, and one silently
// shortened to make a column line up is worse than a ragged column. The
// ellipsis is one column wide, so the result is exactly w.
func truncate(s string, w int) string {
	if w <= 0 || visibleWidth(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	out, n := make([]rune, 0, w), 0
	for _, r := range s {
		if n == w-1 {
			break
		}
		out = append(out, r)
		n++
	}
	return string(out) + "…"
}

// visibleWidth counts the runes a terminal will actually draw, skipping SGR
// escape sequences. It is what lets pad align a coloured column, which
// text/tabwriter cannot do.
func visibleWidth(s string) int {
	n, inEscape := 0, false
	for _, r := range s {
		switch {
		case inEscape:
			// An SGR sequence ends at its final byte, which is a letter.
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			n++
		}
	}
	return n
}

// pad right-pads s to w visible columns. A string already at or over the width
// is returned untouched: truncating a check ID to make a column line up would
// corrupt the one field a suppression file matches on.
func pad(s string, w int) string {
	if n := visibleWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// padLeft left-pads s to w visible columns, which is how a column of counts is
// made to line up on its units digit.
func padLeft(s string, w int) string {
	if n := visibleWidth(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// cell prepares untrusted text for a table.
//
// Escape sequences and control characters are already neutralised upstream —
// sanitisation happens once, at the boundary where untrusted text becomes part
// of a finding (THREAT-MODEL.md T-03), not per renderer. Text is called again
// here as a belt-and-braces measure for any string that reached an Input
// without going through finding.NewEvidence, because this is the renderer that
// writes to a terminal and the cost of being wrong is the operator's session.
//
// The tab is the part sanitisation deliberately keeps, and it is the one
// character that breaks a tabwriter column, so it is turned into a space here
// rather than upstream — a tab in a config file is meaningful and must survive
// into the bundle; a tab in a table cell is a misaligned row.
func cell(s string) string {
	return strings.ReplaceAll(sanitize.Text(s), "\t", " ")
}

// wrap breaks prose at width, on spaces, without hyphenating. It returns at
// least one line for non-empty input so a caller never has to special-case it.
//
// A word longer than the width — a 200-character path in a detail sentence —
// is emitted on its own line rather than broken. Breaking it would produce a
// path an operator cannot copy, which defeats the point of printing it.
func wrap(s string, width int) []string {
	s = cell(s)
	if strings.TrimSpace(s) == "" {
		return nil
	}

	var out []string
	for _, paragraph := range strings.Split(s, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			continue
		}
		cur := words[0]
		for _, w := range words[1:] {
			if visibleWidth(cur)+1+visibleWidth(w) > width {
				out = append(out, cur)
				cur = w
				continue
			}
			cur += " " + w
		}
		out = append(out, cur)
	}
	return out
}

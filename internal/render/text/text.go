// Package text renders findings for a person reading a terminal.
//
// It is the default output and it is not the API. `findings/v1` is the API
// (ADR-0007); this package is free to change layout in a patch release, and
// nothing may parse it. Anything that needs to be read by a program asks for
// `--format json`, which is why the two renderers are separate packages over
// the same model rather than one renderer with a mode flag.
//
// Three properties are load-bearing, and each exists because the obvious
// implementation gets it wrong.
//
// **UNKNOWN is never quiet.** A tool that lists failures and buries what it
// could not determine is reporting a cleaner host than it actually saw. Every
// UNKNOWN gets the same full block a FAIL gets, the summary states the count on
// its own line, and coverage is printed beside posture every single time —
// because 100 over two checks out of two hundred is not a clean host, it is an
// unexamined one.
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
	p.resultsByModule(in.Findings)
	p.attention(in.Findings)
	p.factErrors(in.FactErrors)
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

const rule = "───────────────────────────────────────────────────────────────────────────"

func (p *printer) section(title string) {
	p.blank()
	p.line(p.paint(ansiBold, title))
	p.line(p.paint(ansiDim, rule))
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

// resultWidth is the width the result column pads to: the widest result word
// actually present, not the widest that exists.
//
// NOT_APPLICABLE is fourteen characters and most hosts never produce one, so
// padding to it unconditionally would put ten spaces after every PASS on every
// report for the sake of a state that is not there. Measuring the input keeps
// the common report tight and is still perfectly deterministic — the width is
// a function of the findings, so two reports of an unchanged host remain
// byte-identical.
func resultWidth(in []finding.Finding) int {
	w := 0
	for _, f := range in {
		if n := len(f.Result); n > w {
			w = n
		}
	}
	return w
}

// idWidth is the same measurement for the check-ID column.
func idWidth(in []finding.Finding) int {
	w := 0
	for _, f := range in {
		if n := len(f.CheckID); n > w {
			w = n
		}
	}
	return w
}

func (p *printer) resultsByModule(findings []finding.Finding) {
	if len(findings) == 0 {
		return
	}
	p.section("CHECKS BY MODULE")

	// Both widths are measured across the whole report rather than per module,
	// so the columns line up from the first module to the last. A table that
	// re-aligns itself every few lines is harder to scan than a slightly wider
	// one.
	rw, iw := resultWidth(findings), idWidth(findings)

	for _, m := range modulesOf(findings) {
		in := m.findings
		p.blank()
		p.printf("  %s  %s\n",
			p.paint(ansiBold, m.name),
			p.paint(ansiDim, p.moduleTally(in)))

		for _, f := range in {
			p.printf("    %s  %s  %s\n",
				p.paint(resultColor(f.Result), pad(string(f.Result), rw)),
				pad(f.CheckID, iw),
				cell(f.Title))
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

// attention prints the full block for every FAIL and every UNKNOWN.
//
// UNKNOWN is here, at the same weight as FAIL, and that placement is the whole
// argument of this project rendered as layout. A check that could not tell is
// not a check that passed, and a report that lists failures loudly while
// mentioning unknowns in a footnote is describing a cleaner host than the one
// it examined.
func (p *printer) attention(findings []finding.Finding) {
	fails := withResult(findings, finding.Fail)
	unknowns := withResult(findings, finding.Unknown)
	if len(fails) == 0 && len(unknowns) == 0 {
		return
	}

	if len(fails) > 0 {
		p.section(fmt.Sprintf("FAILING — %d", len(fails)))
		sortBySeverityThenID(fails)
		for _, f := range fails {
			p.block(f)
		}
	}

	if len(unknowns) > 0 {
		p.section(fmt.Sprintf("COULD NOT DETERMINE — %d", len(unknowns)))
		p.blank()
		p.line(p.paint(ansiDim, "  These are not passes. Each one is a question this scan could not answer,"))
		p.line(p.paint(ansiDim, "  with the reason it could not. Treat them as findings until they are resolved."))
		for _, f := range unknowns {
			p.block(f)
		}
	}
}

// block is one finding in full: what it is, what was observed, what that was
// derived from, and what to do about it.
func (p *printer) block(f finding.Finding) {
	p.blank()

	label := p.paint(resultColor(f.Result), string(f.Result))
	head := fmt.Sprintf("  %s  %s  %s", label, p.paint(ansiBold, f.CheckID), cell(f.Title))
	p.line(head)

	// The severity line carries the base severity too when the two differ, so
	// a context adjustment is never invisible.
	meta := []string{p.severityLabel(f)}
	if f.UnknownReason != "" {
		meta = append(meta, "reason "+p.paint(ansiYellow, string(f.UnknownReason)))
	}
	subject := cell(f.Subject)
	// A short subject rides along on the metadata line; a long one — a check
	// reporting on nine paths at once — gets its own wrapped lines rather than
	// running off the right edge of the terminal.
	if subject != "" && visibleWidth(subject) <= shortSubject {
		meta = append(meta, "subject "+subject)
		subject = ""
	}
	p.line("      " + strings.Join(meta, p.paint(ansiDim, "  ·  ")))
	if subject != "" {
		for _, l := range wrap("subject  "+subject, detailWidth) {
			p.line("      " + p.paint(ansiDim, l))
		}
	}

	for _, l := range wrap(f.Detail, detailWidth) {
		p.line("      " + l)
	}

	if len(f.Evidence) > 0 {
		p.blank()
		p.line("      " + p.paint(ansiDim, "evidence"))
		for _, e := range f.Evidence[:min(len(f.Evidence), maxEvidence)] {
			p.evidence(e)
		}
		if extra := len(f.Evidence) - maxEvidence; extra > 0 {
			p.line("        " + p.paint(ansiDim,
				fmt.Sprintf("… and %d more; --format json carries all of it", extra)))
		}
	}

	if f.Remediation != nil {
		p.remediation(*f.Remediation)
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

// shortSubject is how much subject fits on the metadata line before it earns
// lines of its own.
const shortSubject = 56

func (p *printer) evidence(e finding.Evidence) {
	where := cell(e.Source)
	if where == "" {
		where = "(no source)"
	}
	if e.Line > 0 {
		where += fmt.Sprintf(":%d", e.Line)
	}
	p.line("        " + p.paint(ansiDim, where))
	for _, l := range wrap(e.Excerpt, evidenceWidth) {
		p.line("          " + l)
	}
}

func (p *printer) remediation(r finding.Remediation) {
	p.blank()
	head := "      " + p.paint(ansiDim, "remediation")
	if r.Effort != "" {
		head += p.paint(ansiDim, fmt.Sprintf("  ·  effort %s", r.Effort))
	}
	p.line(head)
	for _, l := range wrap(r.Summary, detailWidth) {
		p.line("        " + l)
	}
	if r.Caution != "" {
		for _, l := range wrap("CAUTION: "+r.Caution, detailWidth) {
			p.line("        " + p.paint(ansiYellow, l))
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
	p.section(fmt.Sprintf("COLLECTION GAPS — %d", len(errs)))
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
	p.section("SUMMARY")
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
	row(ansiDim, "SKIPPED", c.Skipped, "")

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
	// detailWidth and evidenceWidth are the wrap columns for prose. They are
	// fixed rather than read from the terminal: a report has to be
	// byte-identical across two runs of an unchanged host, and a width that
	// depends on how wide somebody's window happened to be is not.
	detailWidth   = 92
	evidenceWidth = 88
)

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

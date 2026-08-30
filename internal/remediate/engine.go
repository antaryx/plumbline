// Package remediate turns findings into the work that would fix them.
//
// **It proposes and it does not act, and that is settled rather than pending.**
// Nothing in this package touches the host: it reads findings, produces a Plan
// describing what would be changed, and renders that plan as a shell script a
// person can read before anything happens. plumbline is a script generator and
// will not grow an apply path — a scanner that rewrites configuration as root,
// on a machine the operator cannot see, will eventually lock somebody out of
// production (PROJECT-BRIEF.md §1.3).
//
// An earlier revision of this file carried an Action.Argv alongside the text,
// on the argument that a later phase would execute it through internal/system.
// There is no later phase, so the field was a promise this project has
// disclaimed, and it is gone. The quoting it justified is not: every command
// built from parts still goes through command(), which quotes each argument
// rather than pasting a path into a string.
//
// Three rules shape what is here.
//
// **Only a check that failed is remediated.** Not UNKNOWN: a check that could
// not be evaluated has established nothing about the host, and "fixing" a
// parameter the scan could not read is writing configuration on the strength of
// a guess. Not NOT_APPLICABLE, which has nothing to fix. And never a suppressed
// finding — an operator who formally accepted a risk has said what they want to
// happen, and an engine that silently undid that would make the suppression
// file a lie. See Generate.
//
// **A fix is written per check, not per pattern.** There is no generic "set the
// sysctl the remediation text mentions" path, because the remediation text is
// prose meant for a person and parsing it would make the catalog's wording
// load-bearing in a way nobody reviewing a summary sentence would expect.
//
// **What is generated has to survive being run twice.** A host is scanned and
// remediated repeatedly, and a fix that appended a line each time would grow
// /etc/sysctl.d until something else broke. Idempotency is a property of the
// generated work, tested as one: see Merge.
package remediate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/finding"
)

// DefaultDropIn is the file plumbline writes persistent sysctl settings to.
//
// **One file, owned by this tool, and last in the drop-in order.** 99- puts it
// after every distribution and administrator file in /etc/sysctl.d, so what
// plumbline sets is what the host boots with; naming it plumbline says who
// wrote it, so an operator reading an unfamiliar machine knows what to blame
// and what to delete. Editing a file this tool does not own — /etc/sysctl.conf,
// or a distribution's 10-*.conf — would put plumbline's changes where an
// upgrade or a configuration-management run will silently revert or conflict
// with them.
const DefaultDropIn = "/etc/sysctl.d/99-plumbline-hardening.conf"

// DefaultUnitDir is where systemd drop-ins are written.
//
// **/etc, never /usr.** /usr/lib/systemd/system belongs to the package manager,
// and a directive written there is reverted by the next upgrade of the package
// — silently, and at a moment nobody is watching. /etc/systemd/system/<unit>.d/
// is what `systemctl edit` itself creates, survives upgrades, and is undone by
// deleting one file, which matters more than usual for a sandboxing directive
// that may have to be removed at three in the morning.
const DefaultUnitDir = "/etc/systemd/system"

// Options are the knobs a plan is built with.
type Options struct {
	// DropIn is the sysctl configuration file persistent settings are written
	// to. Empty means DefaultDropIn.
	//
	// It is a field rather than a constant so that a test can point a plan at a
	// temporary file and *run* the script it generates — which is the only way
	// to assert that the shell is idempotent rather than that it looks it.
	DropIn string

	// UnitDir is where systemd drop-ins are written. Empty means
	// DefaultUnitDir. A field for the same reason DropIn is one.
	UnitDir string
}

func (o Options) unitDir() string {
	if o.UnitDir == "" {
		return DefaultUnitDir
	}
	return o.UnitDir
}

func (o Options) dropIn() string {
	if o.DropIn == "" {
		return DefaultDropIn
	}
	return o.DropIn
}

// Action is one check's remediation: what would be run, and what would be
// written.
type Action struct {
	// CheckID is the finding this fixes.
	CheckID string
	// Title is the check's title, so the script says what it is doing in the
	// words the report used.
	Title string
	// Notes are comment lines written above the commands.
	//
	// **They are where a fix admits what it does not cover.** A finding's
	// evidence is capped, so a script built from it can be a partial list of a
	// larger problem — and a partial list that does not say so reads as a
	// complete one. See pathsFrom.
	Notes []string
	// Commands are the shell commands, in order.
	Commands []string
	// SysctlPairs are the parameters this action persists to the drop-in file,
	// keyed by dotted sysctl name.
	//
	// They are held apart from Commands because writing them is not one
	// command: the script's helper reads the file, decides between replacing a
	// line and appending one, and writes it back. See Merge, which is the same
	// rule in Go and the authority the helper is checked against.
	SysctlPairs map[string]string
}

// Fix knows how to remediate one check.
//
// It is an interface rather than a function so that the kinds of remediation
// that are coming — a systemd drop-in, a file mode, a package — can each carry
// their own state and their own rendering without the registry growing a switch
// on what sort of thing it is holding.
type Fix interface {
	// CheckID is the check this fixes. It is what the registry is keyed on.
	CheckID() string
	// Build produces the action for one finding. ok is false when this fix
	// declines the finding — the value is already what it should be, or the
	// finding does not carry what the fix needs.
	Build(f finding.Finding, opts Options) (Action, bool)
}

// registry is every fix this build knows, keyed by check ID.
//
// Populated by each fix file's init rather than listed here, so that adding a
// remediation is one new file and touching this one is not part of it — the
// same shape the catalog uses for checks.
var registry = map[string]Fix{}

func register(f Fix) {
	if _, dup := registry[f.CheckID()]; dup {
		// A duplicate is a build-time mistake and there is no sensible
		// recovery: two fixes for one check would race to write the same key.
		panic("remediate: two fixes registered for " + f.CheckID())
	}
	registry[f.CheckID()] = f
}

// Fixable reports whether this build has a fix for a check.
func Fixable(checkID string) bool {
	_, ok := registry[checkID]
	return ok
}

// Plan is what a scan proposes to change.
type Plan struct {
	// Actions are the remediations, ordered by check ID so that two runs over
	// an unchanged host produce the same script and a diff of the two is empty.
	Actions []Action
	// UnitDir is where the plan would write systemd drop-ins.
	UnitDir string
	// Unfixable are the failing findings no fix in this build covers. They are
	// carried rather than dropped: a plan that silently listed four of
	// thirty-six failures would read as "this is all that is wrong".
	Unfixable []finding.Finding
	// DropIn is the file the plan would write to.
	DropIn string
}

// Empty reports whether there is nothing to propose.
func (p Plan) Empty() bool { return len(p.Actions) == 0 }

// Pairs is every sysctl setting the plan would persist, merged across its
// actions and sorted.
func (p Plan) Pairs() map[string]string {
	out := map[string]string{}
	for _, a := range p.Actions {
		for k, v := range a.SysctlPairs {
			out[k] = v
		}
	}
	return out
}

// Generate compiles the actions for a slice of findings.
//
// **The filter is the safety property, so it is stated positively and in one
// place.** A finding is remediated only when it FAILED — the result the report
// prints as `[ WARNING ]` — and only when it was not suppressed. Everything
// else is left alone:
//
//   - UNKNOWN establishes nothing about the host. Writing a parameter because a
//     check could not read it is acting on a guess, and the guess is being made
//     as root.
//   - NOT_APPLICABLE has nothing to fix; the subject is not on this host.
//   - SKIPPED was deliberately not run.
//   - A suppressed finding is one an operator formally accepted. Undoing that
//     silently would make the suppression file a record of nothing.
func Generate(findings []finding.Finding, opts Options) Plan {
	p := Plan{DropIn: opts.dropIn(), UnitDir: opts.unitDir()}

	for _, f := range findings {
		if f.Result != finding.Fail || f.Suppression != nil {
			continue
		}
		fix, known := registry[f.CheckID]
		if !known {
			p.Unfixable = append(p.Unfixable, f)
			continue
		}
		action, ok := fix.Build(f, opts)
		if !ok {
			p.Unfixable = append(p.Unfixable, f)
			continue
		}
		p.Actions = append(p.Actions, action)
	}

	sort.Slice(p.Actions, func(i, j int) bool { return p.Actions[i].CheckID < p.Actions[j].CheckID })
	sort.Slice(p.Unfixable, func(i, j int) bool { return p.Unfixable[i].CheckID < p.Unfixable[j].CheckID })
	return p
}

// command appends one command, built from its parts and quoted.
//
// **Every command assembled from host data goes through here.** A path from a
// finding is a string this process read off the machine being audited, and a
// script that pasted one into a command line unquoted would be a shell
// injection with a root prompt at the end of it — from a file name, which is
// the one thing on a Linux host that can contain almost anything.
func command(a *Action, argv ...string) {
	out := make([]string, len(argv))
	for i, s := range argv {
		out[i] = shellQuote(s)
	}
	a.Commands = append(a.Commands, strings.Join(out, " "))
}

// literal appends a line of shell as written. It is for the fixed scaffolding a
// fix needs around its commands — a helper call, a comment — and never for
// anything carrying a value read off the host.
func literal(a *Action, line string) {
	a.Commands = append(a.Commands, line)
}

// note appends a comment line above an action's commands.
func note(a *Action, text string) {
	a.Notes = append(a.Notes, text)
}

// shellQuote wraps a word in single quotes unless it is plainly safe without
// them. The safe set is deliberately narrow: anything outside it is quoted, so
// a word that needs quoting can never be missed by a set that was not extended.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./=:,+@", r):
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Script renders a plan as a shell script an operator can read and run.
//
// **It is the proposal, not the mechanism.** A later phase will apply a plan
// through internal/system — argv for the commands, and Merge in Go for the
// drop-in — so nothing here is on the path plumbline itself takes. What this is
// for is the review step: an operator has to be able to see exactly what would
// change before agreeing to it, and a shell script is the form every one of
// them can already read and can run by hand on a host plumbline is not
// installed on.
//
// The script is idempotent, which the helper it defines is the whole reason
// for. See sysctlSetFunc.
func Script(p Plan) string {
	// The body is rendered first so the preamble can carry only the helpers it
	// turns out to need. A script that defined a JSON merge for a host with no
	// Docker on it would be three-quarters scaffolding an operator has to read
	// past to find the two lines that matter.
	var body strings.Builder
	for _, a := range p.Actions {
		body.WriteString("\n# " + a.CheckID + " — " + a.Title + "\n")
		for _, n := range a.Notes {
			body.WriteString("#   " + n + "\n")
		}
		for _, c := range a.Commands {
			body.WriteString(c + "\n")
		}
		for _, k := range sortedKeys(a.SysctlPairs) {
			body.WriteString(fmt.Sprintf("plumbline_sysctl_set %s %s \"$DROPIN\"\n",
				shellQuote(k), shellQuote(a.SysctlPairs[k])))
		}
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Proposed by plumbline. Nothing here has been run.\n")
	b.WriteString("#\n")
	b.WriteString("# Review it, then run it as root. It is safe to run twice: every step\n")
	b.WriteString("# either leaves a value that is already correct alone or replaces it\n")
	b.WriteString("# in place, and every file it edits is backed up once before the first\n")
	b.WriteString("# change.\n")
	b.WriteString("set -eu\n")

	if len(p.Pairs()) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("DROPIN=%s\n", shellQuote(p.DropIn)))
	}
	if strings.Contains(body.String(), "plumbline_dropin") {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("UNITDIR=%s\n", shellQuote(p.UnitDir)))
	}
	for _, h := range helpersFor(body.String()) {
		b.WriteString(h)
	}

	b.WriteString(body.String())

	if len(p.Pairs()) > 0 {
		b.WriteString("\n# Re-apply every configuration file, so the running kernel and the\n")
		b.WriteString("# files agree even where a value was already written but never loaded.\n")
		b.WriteString("sysctl --system\n")
	}

	return b.String()
}

// helper is one shell function the generated script may need, and the call that
// says it is needed.
type helper struct {
	call string
	body string
}

// helpers are declared in dependency order: plumbline_json_set calls
// plumbline_backup, so a script that needs the first needs the second even
// where nothing calls it directly.
var helpers = []helper{
	{call: "plumbline_backup", body: backupFunc},
	{call: "plumbline_sysctl_set", body: sysctlSetFunc},
	{call: "plumbline_json_set", body: jsonSetFunc},
	{call: "plumbline_dropin", body: dropInFunc},
}

// helpersFor returns the helper definitions a rendered body actually uses.
//
// Matching on the call rather than on which fixes are in the plan keeps this
// from becoming a second registry that has to be updated whenever a fix starts
// using a helper it did not before — the kind of list that is wrong for one
// release and nobody notices, because the symptom is a script that fails on the
// operator's host with "command not found".
func helpersFor(body string) []string {
	// plumbline_json_set's own body calls plumbline_backup, so scan the
	// definitions too and let the dependency pull its prerequisite in.
	want := map[string]bool{}
	scan := body
	for changed := true; changed; {
		changed = false
		for _, h := range helpers {
			if want[h.call] || !strings.Contains(scan, h.call) {
				continue
			}
			want[h.call] = true
			scan += h.body
			changed = true
		}
	}

	var out []string
	for _, h := range helpers {
		if want[h.call] {
			out = append(out, h.body)
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

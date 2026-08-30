package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/profile"
	"github.com/antaryx/plumbline/internal/remediate"
	renderjson "github.com/antaryx/plumbline/internal/render/json"
	rendersarif "github.com/antaryx/plumbline/internal/render/sarif"
	rendertext "github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
	"github.com/antaryx/plumbline/internal/suppress"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/version"
)

// gates are the flags that turn findings into an exit code.
type gates struct {
	failOn           string
	threshold        float64
	thresholdSet     bool
	minCoverage      float64
	minCoverageSet   bool
	strictPrivileges bool

	// failOnCritical and failOnHigh are count gates: fail the run when this
	// many findings of that severity are present.
	//
	// **They are counts where --fail-on is a floor, and the difference is what
	// makes them worth having.** `--fail-on high` fails a build on the first
	// HIGH, which is the right gate for a host that is supposed to be clean and
	// the wrong one for a fleet being brought up to standard — there, every
	// build fails from the first day and the signal is gone by the second week.
	// A count lets a pipeline hold a line it can actually meet and tighten it,
	// which is how a gate survives contact with a backlog.
	//
	// Zero is disabled rather than "fail on any", because a count gate that
	// fired at zero findings would fail every run including the clean ones.
	failOnCritical int
	failOnHigh     int
}

func (gt *gates) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&gt.failOn, "fail-on", "none", "exit 2 if any FAIL at or above this severity")
	f.Float64Var(&gt.threshold, "threshold", 0, "exit 3 if posture is below this")
	f.Float64Var(&gt.minCoverage, "min-coverage", 0, "exit 4 if coverage is below this")
	f.BoolVar(&gt.strictPrivileges, "strict-privileges", false, "exit 10 if the run lacked privileges a collector needed")
	f.IntVar(&gt.failOnCritical, "fail-on-critical", 0, "exit 2 if this many CRITICAL findings or more are present; 0 disables")
	f.IntVar(&gt.failOnHigh, "fail-on-high", 0, "exit 2 if this many HIGH findings or more are present; 0 disables")
}

// bind records which numeric gates the operator actually set, because 0 is a
// meaningful value for both and must not be confused with "unset".
func (gt *gates) bind(cmd *cobra.Command) {
	gt.thresholdSet = cmd.Flags().Changed("threshold")
	gt.minCoverageSet = cmd.Flags().Changed("min-coverage")
}

func newEvalCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	var (
		out outputFlags
		gt  gates
		sf  suppressFlags
		pf  profileFlags
	)

	cmd := &cobra.Command{
		Use:   "eval BUNDLE",
		Short: "Evaluate a bundle into findings",
		Long: `Evaluation is unprivileged and offline. It takes no --root: the bundle
already holds everything that was observed, which is what lets a bundle
collected on a production host be analysed somewhere safer.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gt.bind(cmd)
			failOn, err := parseFailOn(gt.failOn)
			if err != nil {
				return err
			}
			format, err := out.resolveFormat(cmd)
			if err != nil {
				return err
			}

			sup, err := sf.load()
			if err != nil {
				return err
			}
			prof, err := pf.load()
			if err != nil {
				return err
			}

			b, err := readBundle(args[0])
			if err != nil {
				// A bundle that will not open, or whose integrity fails, is an
				// internal error rather than a finding: nothing can be said
				// about the host from a file we cannot trust.
				return exitError{code: ExitInternal, message: err.Error()}
			}

			// nil presenter: eval has no collection phase to narrate and is
			// the offline, re-evaluate-an-archive path. Streaming it would put
			// a hundred lines of progress in front of a report that was
			// already instant.
			// nil presenter, and the report always written: eval has no
			// collection phase to narrate and nothing has shown the operator
			// anything yet, so withholding the document would leave the
			// command with no output at all.
			// No --fix: eval reads a bundle, and a bundle can be a month old
			// and from another host. Proposing changes to *this* machine from
			// it would be proposing them for the wrong one.
			// pace 0: eval has no --pace flag, because it has no stream to
			// pace. Pacing its report from a constant would be a delay with no
			// off switch, on the one command whose whole point is to
			// re-evaluate an archive as fast as it can be read.
			return renderAndGate(b, failOn, gt, format, out, sup, prof, nil, true, fixOptions{}, 0, stdout, stderr)
		},
	}

	out.register(cmd)
	gt.register(cmd)
	sf.register(cmd)
	pf.register(cmd)
	return cmd
}

// renderAndGate evaluates a bundle's facts, renders the document, and resolves
// the exit code. It is shared by eval and scan so that the two cannot drift.
//
// Rendering is chosen here rather than inside each command for the same
// reason: a report and its exit code are one answer, and a second call site
// would be a second place for the two to disagree.
// fixOptions is what --fix and --write-script asked for.
type fixOptions struct {
	// enabled is --fix: print the proposed script.
	enabled bool
	// path is --write-script: also write it there. Empty means print only.
	path string
}

func renderAndGate(b bundle.Bundle, failOn int, gt gates, format string, out outputFlags, sup *suppress.Set, prof *profile.Profile, live *rendertext.Stream, detail bool, fix fixOptions, pace time.Duration, stdout, stderr io.Writer) error {
	// The presenter is handed to the catalog rather than to the renderer,
	// because what it shows is evaluation happening — one line as each check
	// reaches a verdict — and by the time there is a slice to render, there is
	// nothing left to watch. A nil presenter is the plain evaluation.
	findings := evaluateWith(b.Facts, live)

	// The profile scopes before suppression does. Both sit between evaluation
	// and scoring, and the order matters: a check outside the baseline was
	// never asked, so there is nothing there to accept. Suppressing first would
	// let a rule fire against a finding the profile had already removed, and
	// report an accepted risk on a question nobody put.
	findings = applyProfile(prof, findings)

	// Suppression sits exactly here: after every check has reached its own
	// verdict, and before anything is scored, rendered or gated on. That
	// ordering is what keeps check purity intact — no check can see a
	// suppression, so no check's logic can depend on one — while still making
	// the accepted risk invisible to --fail-on and to posture, which is the
	// point of accepting it.
	//
	// Expiry is measured against the scan's start time rather than the wall
	// clock, so re-evaluating an archived bundle gives the same answer forever.
	// See suppress.Apply.
	applied := sup.Apply(findings, b.Manifest.Scan.Started)
	findings = applied.Findings

	// The suppression notes go to the same stderr the stream is being drawn on,
	// and the stream is now several rows behind the evaluation that produced
	// them. Await puts the rows on the screen first, so the notes appear below
	// the checks they are about rather than somewhere in the middle of them.
	live.Await()
	reportSuppressions(stderr, applied)

	sc := score.Compute(findings, version.Catalog())
	factErrors := b.Facts.Errors()

	// The stream closes before the report opens. Both may be pointed at the
	// same terminal — stderr and stdout usually are — and a tally that landed
	// in the middle of the report's header would be the one thing this layout
	// cannot survive.
	live.Close(sc)

	// The gate runs whether or not a document was written. An exit code is not
	// a rendering choice: `plumbline scan --fail-on high` has to mean the same
	// thing on a terminal that withheld the report as in a pipe that did not,
	// or the flag is worthless in the only place it is used.
	// The writer is opened once for both the report and the proposed
	// remediation, because --fix has to work in standard mode where there is no
	// report at all — and opening the --output file twice would truncate the
	// first write with the second. Hoisting it is safe: reportDestination
	// already returns true whenever --output is set, so the case this widens is
	// the one where writeTo hands back stdout and a close that does nothing.
	w, closeOut, err := writeTo(out.output, stdout)
	if err != nil {
		return exitError{code: ExitInternal, message: err.Error()}
	}

	// **The width is measured on the destination, and that is the whole of the
	// separation between the two layouts.** The warnings section follows the
	// terminal so a wide window is not wrapped at 78; a file or a pipe keeps the
	// fixed grid so a nightly diff of an unchanged host is still empty. No flag
	// decides which — the same ioctl that answers for a terminal fails for a
	// file, so a redirect cannot accidentally pick up the operator's window size
	// and `plumbline scan > report.txt` produces the same bytes from any
	// terminal it is run in.
	//
	// It is also the terminal test the report's pacing turns on, which is why it
	// is measured here rather than inside the branch below: --fix prints its
	// block in standard mode, where no report is rendered at all, and the
	// proposed script has to be paced on the same evidence the report is.
	columns, _ := system.TerminalWidth(w)

	var renderErr error
	if detail {
		switch format {
		case FormatJSON:
			renderErr = renderJSON(w, b, sc, findings, factErrors, prof.Name())
		case FormatSARIF:
			renderErr = renderSARIF(w, b, sc, findings, len(factErrors) > 0, prof.Name())
		default:
			// The scan phase is dropped only when the stream drew it on the
			// same terminal this report is going to. A redirect or --output
			// gets the whole document even though a stream also ran.
			narrated := live != nil && out.output == "" && system.IsTerminal(w)

			renderErr = renderTerminal(w, b, sc, findings, factErrors,
				useColor(w, out.noColor, out.output != ""), prof.Name(), narrated, columns, pace)
		}
	}

	// After the report, so an operator reads what is wrong before reading what
	// would be done about it — and to the same destination, because a --output
	// run has already said where its output goes.
	if renderErr == nil && fix.enabled {
		renderErr = renderFixPlan(w, findings, useColor(w, out.noColor, out.output != ""), fix.path, columns, pace, stderr)
	}

	if cerr := closeOut(); renderErr == nil {
		renderErr = cerr
	}
	if renderErr != nil {
		return exitError{code: ExitInternal, message: renderErr.Error()}
	}

	return gateOn(sc, findings, factErrors, failOn, gt)
}

func renderJSON(w io.Writer, b bundle.Bundle, sc score.Score, findings []finding.Finding, factErrors []fact.Error, activeProfile string) error {
	return renderjson.Render(w, renderjson.Input{
		Tool: renderjson.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
		Scan: renderjson.Scan{
			Started:  b.Manifest.Scan.Started,
			Finished: b.Manifest.Scan.Finished,
			Root:     b.Manifest.Scan.Root,
			EUID:     b.Manifest.Scan.EUID,
			Profile:  activeProfile,
			Host:     hostFor(b),
		},
		Score:      sc,
		Findings:   findings,
		FactErrors: factErrors,
		Degraded:   len(factErrors) > 0,
	})
}

// renderSARIF emits SARIF 2.1.0. The mapping lives in ADR-0018; this function
// is only the wiring, and deliberately takes the same arguments as the other
// two renderers so that a third output can never see a different finding set
// from the first two.
func renderSARIF(w io.Writer, b bundle.Bundle, sc score.Score, findings []finding.Finding, degraded bool, activeProfile string) error {
	return rendersarif.Render(w, rendersarif.Input{
		Fixes: generatedFixes(findings),
		Tool:  rendersarif.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
		Scan: rendersarif.Scan{
			Started:  b.Manifest.Scan.Started,
			Finished: b.Manifest.Scan.Finished,
			Root:     b.Manifest.Scan.Root,
			EUID:     b.Manifest.Scan.EUID,
			Profile:  activeProfile,
			Hostname: b.Meta.Hostname,
		},
		Score:    sc,
		Findings: findings,
		Degraded: degraded,
	})
}

func renderTerminal(w io.Writer, b bundle.Bundle, sc score.Score, findings []finding.Finding, factErrors []fact.Error, color bool, activeProfile string, narrated bool, columns int, pace time.Duration) error {
	return rendertext.Render(w, rendertext.Input{
		Tool: rendertext.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
		Scan: rendertext.Scan{
			Started:  b.Manifest.Scan.Started,
			Finished: b.Manifest.Scan.Finished,
			Root:     b.Manifest.Scan.Root,
			EUID:     b.Manifest.Scan.EUID,
			Profile:  activeProfile,
			Host:     textHostFor(b),
		},
		Score:        sc,
		Findings:     findings,
		FactErrors:   factErrors,
		Degraded:     len(factErrors) > 0,
		Color:        color,
		ScanNarrated: narrated,
		Width:        columns,
		Pace:         pace,
	})
}

// textHostFor is hostFor for the terminal renderer. The two host types are
// separate because the two renderers are separate packages over one model, and
// making the text report import the JSON document's types would tie a layout
// this project is free to change in a patch release to the schema it is not.
func textHostFor(b bundle.Bundle) *rendertext.Host {
	if b.Meta.Hostname == "" && b.Meta.OSRelease == "" && b.Meta.Kernel == "" && b.Meta.Arch == "" {
		return nil
	}
	return &rendertext.Host{
		Hostname:  b.Meta.Hostname,
		OSVersion: b.Meta.OSRelease,
		Kernel:    b.Meta.Kernel,
		Arch:      b.Meta.Arch,
	}
}

// hostFor maps a bundle's host descriptors into the document. A redacted
// bundle has nothing to map, and the document says nothing rather than saying
// an empty name.
func hostFor(b bundle.Bundle) *renderjson.Host {
	if b.Meta.Hostname == "" && b.Meta.OSRelease == "" && b.Meta.Kernel == "" && b.Meta.Arch == "" {
		return nil
	}
	return &renderjson.Host{
		Hostname:  b.Meta.Hostname,
		OSVersion: b.Meta.OSRelease,
		Kernel:    b.Meta.Kernel,
		Arch:      b.Meta.Arch,
	}
}

// gateOn resolves the outcome. Every gate is evaluated and the ladder decides,
// rather than the first gate that trips winning by accident.
func gateOn(sc score.Score, findings []finding.Finding, factErrors []fact.Error, failOn int, gt gates) error {
	o := Outcome{
		Degraded: len(factErrors) > 0,
		Failing:  anyFailureAtOrAbove(findings, failOn),
	}

	// The count gates share exit 2 with --fail-on, deliberately: to a pipeline
	// they are the same event — "the findings are unacceptable" — and a second
	// code would make every CI configuration that checks for 2 wrong on the day
	// somebody adds one of these flags. Which gate fired is in the message.
	if n := gt.failOnCritical; n > 0 && countSeverity(findings, finding.Critical) >= n {
		o.Failing = true
		o.CountGate = fmt.Sprintf("--fail-on-critical %d (%d present)", n, countSeverity(findings, finding.Critical))
	}
	if n := gt.failOnHigh; n > 0 && countSeverity(findings, finding.High) >= n {
		o.Failing = true
		if o.CountGate != "" {
			o.CountGate += " and "
		}
		o.CountGate += fmt.Sprintf("--fail-on-high %d (%d present)", n, countSeverity(findings, finding.High))
	}

	if gt.strictPrivileges && lacksPrivilege(factErrors) {
		o.Privileges = true
	}
	if coverage, ok := sc.Coverage(); gt.minCoverageSet && (!ok || coverage < gt.minCoverage) {
		o.Degraded = true
	}
	if posture, ok := sc.Posture(); gt.thresholdSet && ok && posture < gt.threshold {
		o.BelowThreshold = true
	}

	if code := ExitCode(o); code != ExitOK {
		return exitError{code: code, message: explain(o)}
	}
	return nil
}

func explain(o Outcome) string {
	switch {
	case o.Privileges:
		return "insufficient privileges for one or more collectors, and --strict-privileges was set"
	case o.Degraded:
		return "completed degraded: a collector failed, or coverage is below --min-coverage"
	case o.Failing && o.CountGate != "":
		return "findings at or above " + o.CountGate
	case o.Failing:
		return "findings at or above --fail-on"
	case o.BelowThreshold:
		return "posture is below --threshold"
	}
	return ""
}

// lacksPrivilege reports whether any gap was a privilege gap. --strict-privileges
// turns that into exit 10 so a pipeline can insist on a scan that was actually
// allowed to look, rather than accepting a clean report from a blind run.
func lacksPrivilege(errs []fact.Error) bool {
	for _, e := range errs {
		if e.Kind == fact.ErrPermission {
			return true
		}
	}
	return false
}

// renderFixPlan writes the proposed-remediation block.
//
// **It is the joint between the renderer and the engine**, which is why it is
// here: internal/render may not import internal/remediate — a renderer that
// knew how a fix was built is one that would eventually build one — and
// internal/remediate must not know how a report is laid out. The CLI is the
// composition root and is already allowed to know about both.
//
// Nothing is executed. This phase proposes; applying a plan is a later one, and
// will go through internal/system with an argv rather than through the shell
// this prints.
func renderFixPlan(w io.Writer, findings []finding.Finding, color bool, scriptPath string, columns int, pace time.Duration, stderr io.Writer) error {
	plan := remediate.Generate(findings, remediate.Options{})
	script := remediate.Script(plan)

	if err := rendertext.RenderRemediation(w, rendertext.RemediationInput{
		Color:     color,
		Covered:   len(plan.Actions),
		Uncovered: len(plan.Unfixable),
		Script:    script,
		SavedTo:   scriptPath,
		Width:     columns,
		Pace:      pace,
	}); err != nil {
		return err
	}
	if scriptPath == "" {
		return nil
	}

	// **Written after the block is printed, so a failure to write cannot cost
	// the operator the script.** The proposal is already on their screen by the
	// time this runs; if the path is wrong or the disk is full they can still
	// read, copy and act on what the scan produced.
	if err := writeScriptTo(scriptPath, script); err != nil {
		return err
	}

	// stderr, and after everything the stream drew, for the reason `bundle
	// saved to` goes there: it is a note about this run rather than part of the
	// document, and a `--format terminal` report redirected to a file should
	// not end with a line about where a different file went.
	fmt.Fprintf(stderr, "[+] Remediation script saved to %s\n", scriptPath)
	return nil
}

// writeScriptTo writes the generated script, owner-only and executable.
//
// The mode is the seam's (system.ScriptMode, 0700) rather than a number
// repeated here: a script that says exactly how to change this host's security
// posture is not a file to leave group-writable on a shared machine, where it
// could be edited in the window between the review and the run.
func writeScriptTo(path, script string) error {
	f, err := system.CreateScript(path)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, script); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// countSeverity counts the findings that actually failed at a severity.
//
// **Only a FAIL counts, and a suppressed one does not.** A check's severity is
// what it *would* be worth if it failed, so counting every finding at that
// severity would count the passes too and fail a clean host on its first run.
// And an accepted risk has been decided: a gate that counted it would make the
// suppression file unable to do the one thing it exists for.
func countSeverity(findings []finding.Finding, want finding.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Result == finding.Fail && f.Suppression == nil && f.Severity == want {
			n++
		}
	}
	return n
}

// generatedFixes is the exact shell plumbline would propose, per check.
//
// **It is built here rather than in the renderer**, for the reason
// renderFixPlan is here: internal/render may not import internal/remediate, and
// the CLI is the composition root that is allowed to know about both.
//
// It runs on every `--format sarif` render rather than only under --fix. A
// SARIF document is written for a machine to ingest, and a pipeline that wanted
// the proposed commands would otherwise have to run the scan twice — once for
// the document and once for the script — over a host that may have changed in
// between. The cost is a plan built from findings already in memory: no
// collection, no host access, no shell.
func generatedFixes(findings []finding.Finding) map[string][]string {
	plan := remediate.Generate(findings, remediate.Options{})
	if len(plan.Actions) == 0 {
		return nil
	}
	out := make(map[string][]string, len(plan.Actions))
	for _, a := range plan.Actions {
		out[a.CheckID] = a.Commands
	}
	return out
}

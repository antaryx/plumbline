package cli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/profile"
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
}

func (gt *gates) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&gt.failOn, "fail-on", "none", "exit 2 if any FAIL at or above this severity")
	f.Float64Var(&gt.threshold, "threshold", 0, "exit 3 if posture is below this")
	f.Float64Var(&gt.minCoverage, "min-coverage", 0, "exit 4 if coverage is below this")
	f.BoolVar(&gt.strictPrivileges, "strict-privileges", false, "exit 10 if the run lacked privileges a collector needed")
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
			return renderAndGate(b, failOn, gt, format, out, sup, prof, nil, true, stdout, stderr)
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
func renderAndGate(b bundle.Bundle, failOn int, gt gates, format string, out outputFlags, sup *suppress.Set, prof *profile.Profile, live *rendertext.Stream, detail bool, stdout, stderr io.Writer) error {
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
	if detail {
		w, closeOut, err := writeTo(out.output, stdout)
		if err != nil {
			return exitError{code: ExitInternal, message: err.Error()}
		}

		var renderErr error
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
				useColor(w, out.noColor, out.output != ""), prof.Name(), narrated)
		}

		if cerr := closeOut(); renderErr == nil {
			renderErr = cerr
		}
		if renderErr != nil {
			return exitError{code: ExitInternal, message: renderErr.Error()}
		}
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
		Tool: rendersarif.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
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

func renderTerminal(w io.Writer, b bundle.Bundle, sc score.Score, findings []finding.Finding, factErrors []fact.Error, color bool, activeProfile string, narrated bool) error {
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

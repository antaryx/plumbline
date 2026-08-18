package cli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	renderjson "github.com/antaryx/plumbline/internal/render/json"
	"github.com/antaryx/plumbline/internal/score"
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
		format string
		output string
		gt     gates
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
			if format != "json" {
				return usageErrorf("--format %q is not implemented yet; only json exists in v0.1", format)
			}

			b, err := readBundle(args[0])
			if err != nil {
				// A bundle that will not open, or whose integrity fails, is an
				// internal error rather than a finding: nothing can be said
				// about the host from a file we cannot trust.
				return exitError{code: ExitInternal, message: err.Error()}
			}

			return renderAndGate(b, failOn, gt, format, output, stdout, stderr)
		},
	}

	f := cmd.Flags()
	f.StringVar(&format, "format", "json", "output format")
	f.StringVarP(&output, "output", "o", "", "write the document here instead of stdout")
	gt.register(cmd)
	return cmd
}

// renderAndGate evaluates a bundle's facts, renders the document, and resolves
// the exit code. It is shared by eval and scan so that the two cannot drift.
func renderAndGate(b bundle.Bundle, failOn int, gt gates, format, output string, stdout, stderr io.Writer) error {
	findings := evaluate(b.Facts)
	sc := score.Compute(findings, version.Catalog())
	factErrors := b.Facts.Errors()

	w, closeOut, err := writeTo(output, stdout)
	if err != nil {
		return exitError{code: ExitInternal, message: err.Error()}
	}
	renderErr := renderjson.Render(w, renderjson.Input{
		Tool: renderjson.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
		Scan: renderjson.Scan{
			Started:  b.Manifest.Scan.Started,
			Finished: b.Manifest.Scan.Finished,
			Root:     b.Manifest.Scan.Root,
			EUID:     b.Manifest.Scan.EUID,
			Profile:  b.Manifest.Scan.Profile,
			Host:     hostFor(b),
		},
		Score:      sc,
		Findings:   findings,
		FactErrors: factErrors,
		Degraded:   len(factErrors) > 0,
	})
	if cerr := closeOut(); renderErr == nil {
		renderErr = cerr
	}
	if renderErr != nil {
		return exitError{code: ExitInternal, message: renderErr.Error()}
	}

	return gateOn(sc, findings, factErrors, failOn, gt)
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

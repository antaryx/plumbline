package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/diff"
	"github.com/antaryx/plumbline/internal/finding"
	rendertext "github.com/antaryx/plumbline/internal/render/text"
	"github.com/antaryx/plumbline/internal/score"
	"github.com/antaryx/plumbline/internal/suppress"
	"github.com/antaryx/plumbline/internal/version"
)

func newDiffCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	var (
		out outputFlags
		sf  suppressFlags
	)

	cmd := &cobra.Command{
		Use:   "diff OLD NEW",
		Short: "Compare two bundles and report what changed",
		Long: `diff re-evaluates two bundles with today's catalog and reports only what
moved. Unchanged findings are not printed.

Both sides are judged by the same code, which is what makes the comparison
mean something: a check whose logic was corrected between the two collections
cannot appear as the host having changed. There is consequently no
catalog-drift flag — a bundle stores facts, not verdicts, so there is no drift
to allow.

Findings are matched by fingerprint, which is stable across verdict changes by
design. A suppressed finding is compared by the verdict it actually reached, so
accepting a risk diffs as an acceptance rather than as a fix.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := out.resolveFormat(cmd)
			if err != nil {
				return err
			}
			if format == FormatJSON {
				// Rendering the comparison as a document would be a second
				// public API, and findings/v1 does not describe one. Refusing
				// is better than emitting a shape nothing has agreed to and
				// that a pipeline would then depend on.
				return exitError{code: ExitUsage, message: "diff has no --json output yet; findings/v1 does not describe a comparison document"}
			}
			sup, err := sf.load()
			if err != nil {
				return err
			}

			oldB, err := readBundleFor("OLD", args[0])
			if err != nil {
				return err
			}
			newB, err := readBundleFor("NEW", args[1])
			if err != nil {
				return err
			}

			oldF, oldScore := evaluateForDiff(oldB, sup, stderr, "OLD")
			newF, newScore := evaluateForDiff(newB, sup, stderr, "NEW")

			w, closeOut, err := writeTo(out.output, stdout)
			if err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
			}
			renderErr := rendertext.RenderDiff(w, rendertext.DiffInput{
				Tool:     rendertext.Tool{Name: "plumbline", Version: version.Version, Commit: version.Commit},
				Old:      diffSideFor(args[0], oldB),
				New:      diffSideFor(args[1], newB),
				Result:   diff.Compare(oldF, newF),
				OldScore: oldScore,
				NewScore: newScore,
				Color:    useColor(w, out.noColor, out.output != ""),
			})
			if cerr := closeOut(); renderErr == nil {
				renderErr = cerr
			}
			if renderErr != nil {
				return exitError{code: ExitInternal, message: renderErr.Error()}
			}
			return nil
		},
	}

	out.register(cmd)
	sf.register(cmd)
	return cmd
}

// readBundleFor names which of the two arguments failed. "no such file" is not
// a useful message when the command took two paths.
func readBundleFor(which, path string) (bundle.Bundle, error) {
	b, err := readBundle(path)
	if err != nil {
		return bundle.Bundle{}, exitError{code: ExitInternal,
			message: fmt.Sprintf("%s bundle %s: %v", which, path, err)}
	}
	return b, nil
}

// evaluateForDiff runs the catalog over one side and applies suppressions to
// it, in the same order renderAndGate does — checks first, then acceptance,
// then scoring — so a diff and a scan of the same bundle agree about what a
// finding is.
//
// Expiry is measured against each bundle's own scan time, which is what makes
// "the acceptance lapsed between these two runs" a thing this command can see:
// one suppression file, two moments, two answers.
func evaluateForDiff(b bundle.Bundle, sup *suppress.Set, stderr io.Writer, which string) ([]finding.Finding, score.Score) {
	findings := evaluate(b.Facts)
	applied := sup.Apply(findings, b.Manifest.Scan.Started)
	for _, r := range applied.Expired {
		fmt.Fprintf(stderr, "plumbline: %s: suppression %s expired %s; the finding is reported\n",
			which, r.Fingerprint, r.ExpiresAt)
	}
	return applied.Findings, score.Compute(applied.Findings, version.Catalog())
}

func diffSideFor(path string, b bundle.Bundle) rendertext.DiffSide {
	return rendertext.DiffSide{
		Path: path,
		Scan: rendertext.Scan{
			Started:  b.Manifest.Scan.Started,
			Finished: b.Manifest.Scan.Finished,
			Root:     b.Manifest.Scan.Root,
			EUID:     b.Manifest.Scan.EUID,
			Profile:  b.Manifest.Scan.Profile,
			Host:     textHostFor(b),
		},
	}
}

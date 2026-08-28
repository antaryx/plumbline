package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/system/live"
)

func newScanCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	var (
		root         string
		saveBundle   string
		redact       bool
		timeout      time.Duration
		perCollector time.Duration
		out          outputFlags
		gt           gates
		sf           suppressFlags
		pf           profileFlags
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Collect, evaluate and render in one pass",
		Long: `scan is collect and eval fused, with the bundle held in memory. It is a
convenience over a pipeline, never a different code path: the same collectors
produce the same facts and the same catalog evaluates them, so a scan and a
collect-then-eval of one host give identical findings. A test asserts that.

Use --save-bundle to keep the evidence a scan was derived from:

    plumbline scan --save-bundle host.plb

That file is an evidence bundle — the facts observed, not the verdicts drawn
from them — and it is what 'plumbline eval' and 'plumbline diff' take. A
findings document written with '--json > out.json' holds verdicts and cannot be
re-evaluated or diffed; the two are not interchangeable.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gt.bind(cmd)
			failOn, err := parseFailOn(gt.failOn)
			if err != nil {
				return err
			}
			format, err := out.resolveFormat(cmd)
			if err != nil {
				return err
			}
			// Loaded before a single file of the host is touched. A
			// suppression file with a typo in it is a thirty-millisecond
			// failure here and a thirty-minute one after the collection.
			sup, err := sf.load()
			if err != nil {
				return err
			}
			prof, err := pf.load()
			if err != nil {
				return err
			}

			// Before anything is collected, and therefore before the
			// progress indicator claims the line (VERSIONING §2.4). A
			// scoring change has to be stated before the score it moved is
			// reported, not after it — an operator reading a number they
			// cannot explain has already started investigating the host.
			//
			// stderr, so a --format json run still hands stdout a document
			// and nothing else.
			reportScoringNotices(stderr, useColor(stderr, out.noColor, false))

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			sys := live.New(root)
			got, err := collectFacts(ctx, sys, collectOptions{
				redact: redact, profile: pf.name, perCollector: perCollector,
				progress: stderr,
			})
			if err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
			}

			// Before --save-bundle and before rendering, because both would
			// otherwise produce an artifact that looks like a finished answer.
			//
			// A findings document from a half-finished collection is the worst
			// output this tool can emit: every check whose facts never arrived
			// resolves to UNKNOWN or NOT_APPLICABLE, the posture score is
			// computed over whatever did, and nothing on the page says that a
			// human stopped it. ExitCode's ladder already puts 130 above
			// everything, so returning here cannot contradict it.
			if got.interrupted {
				return exitError{code: ExitInterrupted, message: "interrupted; no report was produced"}
			}

			if saveBundle != "" {
				if err := writeBundle(saveBundle, got.bundle); err != nil {
					return exitError{code: ExitInternal, message: err.Error()}
				}
				fmt.Fprintf(stderr, "bundle saved to %s\n", saveBundle)
			}

			// A run that ran out of time is reported as such whatever the
			// findings say: an incomplete scan's verdicts are not a verdict on
			// the host.
			if got.timedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return exitError{code: ExitTimeout, message: "scan exceeded --timeout"}
			}

			return renderAndGate(got.bundle, failOn, gt, format, out, sup, prof, stdout, stderr)
		},
	}

	f := cmd.Flags()
	f.StringVar(&root, "root", "", "scan root; paths are interpreted beneath it")
	f.StringVar(&saveBundle, "save-bundle", "", "write the evidence bundle this scan used to PATH (e.g. host.plb); required for later eval/diff")
	f.BoolVar(&redact, "redact", false, "omit hostname and non-loopback addresses at collection time")
	f.DurationVar(&timeout, "timeout", 30*time.Minute, "whole-scan budget")
	f.DurationVar(&perCollector, "collector-timeout", 2*time.Minute, "budget for one collector that declares none")
	out.register(cmd)
	gt.register(cmd)
	sf.register(cmd)
	pf.register(cmd)
	return cmd
}

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
		profile      string
		timeout      time.Duration
		perCollector time.Duration
		out          outputFlags
		gt           gates
		sf           suppressFlags
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Collect, evaluate and render in one pass",
		Long: `scan is collect and eval fused, with the bundle held in memory. It is a
convenience over a pipeline, never a different code path: the same collectors
produce the same facts and the same catalog evaluates them, so a scan and a
collect-then-eval of one host give identical findings. A test asserts that.

Use --save-bundle to keep the evidence a scan was derived from.`,
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

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			sys := live.New(root)
			got, err := collectFacts(ctx, sys, collectOptions{
				redact: redact, profile: profile, perCollector: perCollector,
			})
			if err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
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

			return renderAndGate(got.bundle, failOn, gt, format, out, sup, stdout, stderr)
		},
	}

	f := cmd.Flags()
	f.StringVar(&root, "root", "", "scan root; paths are interpreted beneath it")
	f.StringVar(&saveBundle, "save-bundle", "", "keep the bundle this scan produced")
	f.BoolVar(&redact, "redact", false, "omit hostname and non-loopback addresses at collection time")
	f.StringVar(&profile, "profile", "default", "collection profile")
	f.DurationVar(&timeout, "timeout", 30*time.Minute, "whole-scan budget")
	f.DurationVar(&perCollector, "collector-timeout", 2*time.Minute, "budget for one collector that declares none")
	out.register(cmd)
	gt.register(cmd)
	sf.register(cmd)
	return cmd
}

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

func newCollectCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	var (
		root         string
		output       string
		redact       bool
		profile      string
		timeout      time.Duration
		perCollector time.Duration
	)

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect facts into a bundle and stop",
		Long: `Collection is the privileged step. It reads the host and writes a bundle;
it evaluates nothing, so the analysis can happen later, elsewhere, or against a
catalog that does not exist yet.

collect takes no selection flags beyond --profile. A bundle collected with
today's checks in mind cannot answer tomorrow's question.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				return usageErrorf("collect needs -o BUNDLE; collecting facts and discarding them is not a scan")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			sys := live.New(root)
			got, err := collectFacts(ctx, sys, collectOptions{
				redact: redact, profile: profile, perCollector: perCollector,
				progress: stderr,
			})
			if err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
			}

			// Checked before the bundle is written, and it is the whole point
			// of checking here rather than at the bottom with the other exits.
			//
			// A bundle assembled from a collection that stopped half way is a
			// file with no mark on it saying so: the manifest lists the facts
			// that made it and says nothing about the ones that did not, and
			// six months later it re-evaluates to a posture score drawn from
			// half a host. An operator who pressed Ctrl-C did not ask for a
			// file, and the safest artifact is the one that was never written.
			//
			// This is deliberately stricter than the --timeout path below,
			// which does keep its bundle. A budget is a decision to accept
			// whatever fits inside it; an interrupt is a decision to stop.
			if got.interrupted {
				return exitError{
					code:    ExitInterrupted,
					message: fmt.Sprintf("interrupted; %s was not written", output),
				}
			}

			if err := writeBundle(output, got.bundle); err != nil {
				return exitError{code: ExitInternal, message: err.Error()}
			}

			errs := got.bundle.Facts.Errors()
			fmt.Fprintf(stderr, "collected %d fact(s), %d error(s) -> %s\n",
				len(got.bundle.Facts.IDs()), len(errs), output)
			if redact {
				fmt.Fprintln(stderr, "bundle is redacted: hostname omitted at collection time")
			}

			// A timeout outranks a degraded result: the run did not finish, so
			// what it did collect is not a complete answer either way.
			switch {
			case got.timedOut || errors.Is(ctx.Err(), context.DeadlineExceeded):
				return exitError{code: ExitTimeout, message: "collection exceeded --timeout"}
			case len(errs) > 0:
				return exitError{code: ExitDegraded, message: fmt.Sprintf("%d collector(s) reported an error", len(errs))}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&root, "root", "", "scan root; paths are interpreted beneath it")
	f.StringVarP(&output, "output", "o", "", "evidence bundle to write, e.g. host.plb (required)")
	f.BoolVar(&redact, "redact", false, "omit hostname and non-loopback addresses at collection time")
	f.StringVar(&profile, "profile", "default", "collection profile")
	f.DurationVar(&timeout, "timeout", 30*time.Minute, "whole-scan budget")
	f.DurationVar(&perCollector, "collector-timeout", 2*time.Minute, "budget for one collector that declares none")
	return cmd
}

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/sanitize"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/version"
)

// collected is the result of one collection pass: everything that goes into a
// bundle, plus the timing a report needs to explain itself.
type collected struct {
	bundle   bundle.Bundle
	timedOut bool
}

// collectFacts runs every registered collector against s and assembles a
// bundle. It is shared by `collect` and `scan`, which is what makes the two
// genuinely equivalent rather than merely similar.
func collectFacts(ctx context.Context, s system.System, opts collectOptions) (collected, error) {
	id, err := bundleID()
	if err != nil {
		return collected{}, err
	}

	facts := fact.NewSet()
	evidence := bundle.NewEvidenceStore()
	started := time.Now().UTC()

	runner := collect.Runner{
		Registry: collect.Default(),
		Timeout:  opts.perCollector,
		Evidence: evidence,
	}
	if err := runner.Run(ctx, s, facts); err != nil {
		return collected{}, err
	}
	finished := time.Now().UTC()

	out := collected{
		timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
		bundle: bundle.Bundle{
			Manifest: bundle.Manifest{
				BundleID:       id,
				Tool:           bundle.Tool{Version: version.Version},
				CatalogVersion: version.Catalog(),
				Created:        finished,
				Redacted:       opts.redact,
				Scan: bundle.Scan{
					Root:     s.Root(),
					EUID:     s.Euid(),
					Started:  started,
					Finished: finished,
					Profile:  opts.profile,
				},
			},
			Meta:     hostMeta(s, opts.redact),
			Facts:    facts,
			Evidence: evidence,
		},
	}
	return out, nil
}

// collectOptions are the collection-time choices. Filtering is deliberately
// absent: `collect` takes no selection flags, because a bundle collected with
// today's checks in mind cannot answer tomorrow's question (CLI-SPEC.md §3).
type collectOptions struct {
	redact       bool
	profile      string
	perCollector time.Duration
}

// hostMeta describes the host being scanned, read through the seam so that
// --root reports the mounted image's identity rather than the machine doing
// the scanning.
//
// Everything here is optional and everything is best-effort: a host that will
// not tell us its name is not a failed scan. What matters is that a value we
// could not read is absent rather than invented.
func hostMeta(s system.System, redact bool) bundle.Meta {
	var m bundle.Meta

	// --redact drops the identifying fields at collection time, so a redacted
	// bundle is safe to attach to a bug report without a second pass over it
	// (docs/DATA-MODEL.md §6.1). Redacting at render time would leave the
	// identity on disk, which is where it matters.
	if !redact {
		if res, err := s.ReadFile("/etc/hostname", 4096); err == nil {
			m.Hostname = sanitize.Text(strings.TrimSpace(string(res.Data)))
		}
	}

	if res, err := s.ReadFile("/etc/os-release", 64<<10); err == nil {
		m.OSRelease = sanitize.Text(osRelease(string(res.Data)))
	}
	return m
}

// osRelease extracts a human identifier from /etc/os-release. PRETTY_NAME is
// the one field every distribution sets and the one an operator recognises.
func osRelease(data string) string {
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "PRETTY_NAME" {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

// bundleID is a random 128-bit identifier. It is not derived from host
// identity, so it leaks nothing under --redact.
func bundleID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating bundle id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// writeBundle serialises b to path, owner-only.
func writeBundle(path string, b bundle.Bundle) error {
	f, err := system.CreateBundle(path)
	if err != nil {
		return err
	}
	if err := bundle.Write(f, b); err != nil {
		f.Close()
		return fmt.Errorf("writing bundle: %w", err)
	}
	return f.Close()
}

// readBundle parses a bundle from disk. A bundle that will not open is an
// internal-error exit, not a findings exit: nothing can be said about the host
// from a file we cannot read.
func readBundle(path string) (bundle.Bundle, error) {
	f, err := system.OpenLocal(path)
	if err != nil {
		return bundle.Bundle{}, err
	}
	defer f.Close()
	return bundle.Read(f)
}

// evaluate runs the catalog over collected facts.
func evaluate(facts *fact.Set) []finding.Finding {
	return buildCatalog().Evaluate(facts)
}

// severityRank orders severities for --fail-on. rank 0 is "none", which never
// gates.
var severityRank = map[string]int{
	"none":     0,
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

func rankOf(sev finding.Severity) int { return severityRank[strings.ToLower(string(sev))] }

// parseFailOn validates a --fail-on level. An unknown value is an error, never
// a default: silently ignoring `--fail-on hgih` is how a gate stops gating
// while continuing to report success (CLI-SPEC.md §5).
func parseFailOn(level string) (int, error) {
	r, ok := severityRank[strings.ToLower(strings.TrimSpace(level))]
	if !ok {
		return 0, usageErrorf("unknown --fail-on level %q; want one of none, info, low, medium, high, critical", level)
	}
	return r, nil
}

// anyFailureAtOrAbove reports whether a FAIL finding meets the gate.
func anyFailureAtOrAbove(findings []finding.Finding, threshold int) bool {
	if threshold == 0 {
		return false
	}
	for _, f := range findings {
		if f.Result == finding.Fail && rankOf(f.Severity) >= threshold {
			return true
		}
	}
	return false
}

// writeTo returns the stream a document is written to: a file when --output was
// given, otherwise stdout.
func writeTo(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return stdout, func() error { return nil }, nil
	}
	f, err := system.CreateLocal(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

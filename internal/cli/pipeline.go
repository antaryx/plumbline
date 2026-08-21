package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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

	// interrupted: the operator stopped the run with a signal. It is separate
	// from timedOut because the two arrive identically — a cancelled context —
	// and mean opposite things to whoever reads the exit code. 11 says raise
	// the budget; 130 says you already know why.
	interrupted bool
}

// collectFacts runs every registered collector against s and assembles a
// bundle. It is shared by `collect` and `scan`, which is what makes the two
// genuinely equivalent rather than merely similar.
func collectFacts(ctx context.Context, s system.System, opts collectOptions) (collected, error) {
	id, err := bundleID()
	if err != nil {
		return collected{}, err
	}

	// The progress indicator is started here rather than at the two call
	// sites for the same reason renderAndGate is one function: this is the
	// collection phase, both commands have one, and a gate applied at every
	// call site is a gate somebody eventually forgets at a third.
	//
	// Deferred rather than stopped after Run, so that a panic escaping a
	// collector cannot leave a half-drawn line on the operator's terminal.
	// What follows Run is assembling a struct, which costs nothing worth
	// stopping the indicator early for.
	defer startProgress(opts.progress, "Collecting host evidence").Stop()

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
		// Asked of the context rather than of a flag this function sets,
		// because the cancellation may have been noticed several layers down —
		// a collector waiting on the expensive slot, a walk part-way through a
		// directory — and context.Cause walks up to the one that carries the
		// reason.
		interrupted: system.Interrupted(ctx),
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

	// progress is the stream a transient indicator is drawn on while the
	// collectors run, or nil for no indicator. It is always stderr in
	// practice; whether anything is actually drawn on it is progress.go's
	// decision, not the caller's.
	progress io.Writer
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
	if err := rejectFindingsDocument(f, path); err != nil {
		return bundle.Bundle{}, err
	}
	return bundle.Read(f)
}

// sniffLen is how much of a file is examined to tell a JSON document from a
// bundle. A findings document opens with `{` and names its schema within the
// first hundred bytes; a bundle opens with a zstd frame magic.
const sniffLen = 512

// rejectFindingsDocument catches the commonest mistake anyone makes with this
// tool and answers it in the terms the operator was thinking in.
//
// `plumbline scan --json > out.json` produces a *findings document*: verdicts,
// already evaluated. `eval` and `diff` want a *bundle*: the facts those
// verdicts were derived from, which is what lets them re-evaluate with today's
// catalog. The two are both "the output of a scan" from the outside, and
// handing the wrong one over used to produce
// `malformed bundle: reading tar: invalid input: magic number mismatch` —
// an accurate description of the sixth thing that went wrong and no help at all
// with the first.
//
// **The test is the file's first bytes, not its extension.** A bundle an
// operator chose to name `.json` is still a bundle, and refusing to read it
// because of its name would replace one wrong answer with another. Every
// findings document this tool has ever written begins with `{`, so the content
// answers the question the name only guesses at.
func rejectFindingsDocument(f *os.File, path string) error {
	prefix := make([]byte, sniffLen)
	n, err := f.Read(prefix)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// Whatever happens next, the reader has to start from the beginning: this
	// function is a look, not a consumption.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	prefix = prefix[:n]

	if !bytes.HasPrefix(bytes.TrimLeft(prefix, " \t\r\n"), []byte("{")) {
		return nil
	}

	what := "a JSON document"
	if bytes.Contains(prefix, []byte(`"findings/v1"`)) {
		what = "a findings/v1 document — the rendered verdicts of a scan"
	}
	return fmt.Errorf("%s is %s, not an evidence bundle.\n"+
		"  A bundle holds the facts a scan observed, which is what lets them be re-evaluated;\n"+
		"  a findings document holds verdicts that have already been drawn from those facts.\n"+
		"  Write one with:  plumbline scan --save-bundle host.plb   (keeps the evidence a scan used)\n"+
		"               or:  plumbline collect -o host.plb          (collects evidence and evaluates nothing)",
		path, what)
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

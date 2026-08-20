package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/suppress"
	"github.com/antaryx/plumbline/internal/system"
)

// suppressFlags carries --suppress. It is a struct rather than a bare string
// for the reason outputFlags and gates are: eval and scan register the same
// value, and one shared type is what stops the two commands drifting.
type suppressFlags struct {
	path string
}

func (sf *suppressFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sf.path, "suppress", "",
		"apply accepted-risk suppressions from a suppressions/v1 file")
}

// load reads and parses the file, or returns nil when the flag was not given.
//
// The file is opened through system.OpenLocal, not through the audit seam, and
// that is the whole reason this function is in internal/cli rather than in
// internal/suppress. A suppression file is a path the *operator* named — it
// lives in their working directory or their repository, alongside the bundle
// they asked for — so --root must never be prefixed onto it (ADR-0011).
// Reading it through the rooted seam would mean `--root /mnt/image
// --suppress ./accepted.json` silently looked for the operator's file inside
// the filesystem under audit, found nothing, and scanned with no suppressions
// at all.
//
// A file that will not open or will not parse is a hard error, never a
// warning. Continuing without it would produce a report full of failures the
// operator has already accepted, which they would reasonably read as the
// suppressions having been applied and nothing having been accepted.
func (sf *suppressFlags) load() (*suppress.Set, error) {
	if sf.path == "" {
		return nil, nil
	}
	f, err := system.OpenLocal(sf.path)
	if err != nil {
		return nil, exitError{code: ExitInternal,
			message: fmt.Sprintf("--suppress %s: %v", sf.path, err)}
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSuppressBytes))
	if err != nil {
		return nil, exitError{code: ExitInternal,
			message: fmt.Sprintf("--suppress %s: %v", sf.path, err)}
	}
	if len(data) == int(maxSuppressBytes) {
		return nil, exitError{code: ExitInternal,
			message: fmt.Sprintf("--suppress %s: file exceeds %d bytes", sf.path, maxSuppressBytes)}
	}

	set, err := suppress.Parse(data)
	if err != nil {
		return nil, exitError{code: ExitInternal,
			message: fmt.Sprintf("--suppress %s: %v", sf.path, err)}
	}
	return set, nil
}

// maxSuppressBytes bounds the read. Every other file this tool opens is
// bounded and this one is no different: it is parsed by a process that
// frequently runs as root, and "the operator named it" is not a reason to read
// an unbounded amount of it. A megabyte is some thirty thousand rules.
const maxSuppressBytes int64 = 1 << 20

// reportSuppressions writes the lines about rules that did *not* fire.
//
// These go to stderr rather than into the findings document, because they are
// facts about the operator's suppression file rather than about the host. A
// lapsed or stale rule is not a property of the machine being audited.
func reportSuppressions(stderr io.Writer, out suppress.Outcome) {
	for _, r := range out.Expired {
		fmt.Fprintf(stderr, "plumbline: suppression %s expired %s; the finding is reported\n",
			r.Fingerprint, r.ExpiresAt)
	}
	for _, r := range out.Unmatched {
		fmt.Fprintf(stderr, "plumbline: suppression %s matched no failing finding; "+
			"it may already be fixed, or the subject may have changed\n", r.Fingerprint)
	}
}

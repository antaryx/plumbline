package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/profile"
	"github.com/antaryx/plumbline/internal/system"
)

// profileFlags carries --profile, which names either a built-in baseline or a
// file.
//
// **This is the same --profile that scan has always taken**, not a second flag
// wearing the same name. It was recorded in the bundle manifest and displayed
// in the header and did nothing else; it now scopes the evaluation, and the
// manifest field it already wrote becomes the record of what that scope was.
// Adding a second profile-ish flag beside it would have left an operator
// guessing which one they meant.
type profileFlags struct {
	name string
}

func (pf *profileFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&pf.name, "profile", profile.DefaultID,
		"evaluation baseline: a built-in name (see `plumbline profiles`) or a path to a profile/v1 file")
}

// maxProfileBytes bounds the read of an operator-named file, for the reason
// every other read in this tool is bounded.
const maxProfileBytes int64 = 1 << 20

// load resolves the flag to a profile.
//
// A name that is neither a built-in nor an existing file is a hard error that
// lists the built-ins. Falling back to the whole catalog would silently score a
// host against a baseline nobody asked for, and the operator would read the
// number as though their profile had applied.
func (pf *profileFlags) load() (*profile.Profile, error) {
	name := strings.TrimSpace(pf.name)
	if name == "" || name == profile.DefaultID {
		p, _ := profile.Builtin(profile.DefaultID)
		return p, nil
	}
	if p, ok := profile.Builtin(name); ok {
		return p, nil
	}

	// Only a path can be meant now. A built-in name never contains a
	// separator, so an operator who typed one wanted a file.
	if !looksLikePath(name) {
		return nil, exitError{code: ExitUsage, message: fmt.Sprintf(
			"unknown profile %q\n  built-in profiles: %s\n  or pass a path to a profile/v1 file",
			name, strings.Join(profile.BuiltinIDs(), ", "))}
	}

	// Opened through the operator-named-file seam, never the audit seam, so
	// --root can never be prefixed onto it (ADR-0011).
	f, err := system.OpenLocal(name)
	if err != nil {
		return nil, exitError{code: ExitUsage, message: fmt.Sprintf("--profile %s: %v", name, err)}
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxProfileBytes))
	if err != nil {
		return nil, exitError{code: ExitUsage, message: fmt.Sprintf("--profile %s: %v", name, err)}
	}
	p, err := profile.Parse(data)
	if err != nil {
		return nil, exitError{code: ExitUsage, message: fmt.Sprintf("--profile %s: %v", name, err)}
	}
	return p, nil
}

func looksLikePath(s string) bool {
	return strings.ContainsAny(s, "/\\.") || strings.HasPrefix(s, "~")
}

// applyProfile scopes an evaluated finding set to a baseline.
//
// It runs after every check has reached its own verdict and before anything is
// scored — the same seam suppression uses, and for the same reason: no check
// can observe a profile, so check purity is untouched. A profile is a statement
// about which questions to count, not an input to answering one.
//
// **An excluded check is rewritten, never dropped.** A report that silently
// omitted the checks a narrow profile left out would describe a cleaner host
// than the one examined, which is the failure this project refuses everywhere.
func applyProfile(p *profile.Profile, in []finding.Finding) []finding.Finding {
	if p == nil {
		return in
	}
	out := make([]finding.Finding, len(in))
	copy(out, in)

	for i := range out {
		f := &out[i]
		if !p.Includes(f.CheckID) {
			f.Result = finding.Skipped
			f.SkippedBy = p.ID
			f.Detail = fmt.Sprintf("Not in profile %q (%s). The check was not evaluated, "+
				"and it is outside the posture denominator rather than counted against this host.",
				p.ID, p.Title)
			// Evidence and remediation describe a verdict that was never
			// reached. Keeping them would invite a reader to act on a finding
			// this scan did not make.
			f.Evidence = nil
			f.Remediation = nil
			f.UnknownReason = ""
			continue
		}
		// A severity override moves the effective severity and never the base,
		// exactly as a context adjustment does, so a renderer can always show
		// that a number was moved and from what.
		if sev, ok := p.SeverityFor(f.CheckID); ok {
			f.Severity = sev
		}
	}
	return out
}

// newProfilesCmd builds `plumbline profiles`.
func newProfilesCmd(g *globals, stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List the baselines built into this binary",
		Long: `profiles lists the evaluation baselines embedded in this build, with how
many of the catalog's checks each one selects.

A profile scopes what is evaluated and what the posture score is measured
against. Checks outside it are reported as SKIPPED — never omitted — and leave
the posture denominator, because the profile declares what applies.

--profile also accepts a path to a profile/v1 file, which is not listed here
because this binary does not know what is on your disk.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids := buildCatalog().IDs()
			for _, p := range profile.Builtins() {
				fmt.Fprintf(stdout, "%-12s %3d/%d checks   %s\n",
					p.ID, p.Count(ids), len(ids), p.Title)
			}
			return nil
		},
	}
}

// Package sshd holds the SSHD module's checks.
//
// SSHD-0002 is the project's reference check. Anything unclear about how to
// write a check is answered here first and in docs/CHECK-AUTHORING.md second.
// Note what it does not do: no file reads, no exec, no clock, no network. It
// receives facts and returns an Outcome. That is the whole contract.
package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// openSSHDefaultPermitRootLogin is what sshd uses when the keyword is absent.
// It has been prohibit-password since OpenSSH 7.0 (2015). Encoding the real
// default matters: reporting "not configured" as though it meant "root login
// allowed" would be a false FAIL, and treating absence as PASS would be a
// false assurance.
const openSSHDefaultPermitRootLogin = "prohibit-password"

// Check0002 tests whether direct root login over SSH is disabled.
var Check0002 = catalog.Check{
	ID:     "SSHD-0002",
	Module: "SSHD",
	Title:  "Root login over SSH is disabled",
	Description: `Direct root login over SSH removes the accountability that
sudo provides — every action is attributed to "root" rather than to a person —
and it presents remote attackers with a username that is guaranteed to exist on
every system, which makes credential attacks meaningfully cheaper.

PermitRootLogin no requires an administrator to authenticate as themselves and
then escalate, which leaves an audit trail. The OpenSSH default when the
keyword is absent is prohibit-password: key-based root login remains possible.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "remote-access", "accountability"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 1,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed, so
		// this read cannot fail in a way the check must handle.
		cfg, _, _ := fact.Get[fact.SSHDConfig](fs, fact.SSHDConfigID)

		if !cfg.Installed {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "No sshd configuration found; the SSH server is not configured on this host.",
			}
		}

		d, ok := cfg.Effective("PermitRootLogin")

		if !ok {
			// The keyword is absent from everything we could read. If an
			// Include failed to resolve, the value may exist in a file we
			// never saw, and asserting the default would be a guess.
			if len(cfg.UnresolvedIncludes) > 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Detail: fmt.Sprintf(
						"PermitRootLogin is not set in any readable file, but %d Include directive(s) could not be resolved (%s); the effective value cannot be determined.",
						len(cfg.UnresolvedIncludes),
						strings.Join(cfg.UnresolvedIncludes, ", ")),
					Evidence: []finding.Evidence{finding.NewEvidence(
						cfg.Files[0], 0,
						"unresolved Include: "+strings.Join(cfg.UnresolvedIncludes, ", "),
						cfg.Digests[cfg.Files[0]])},
				}
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Severity: finding.Medium, // key-only root login, not password
				Detail: fmt.Sprintf(
					"PermitRootLogin is not configured; sshd applies its built-in default of %q, which permits root login with a key.",
					openSSHDefaultPermitRootLogin),
				Evidence: []finding.Evidence{finding.NewEvidence(
					cfg.Files[0], 0,
					"PermitRootLogin not present in any parsed file",
					cfg.Digests[cfg.Files[0]])},
			}
		}

		// NewEvidence is the constructor THREAT-MODEL.md T-03 names: it
		// neutralises the untrusted strings a directive carries, and it
		// attaches the digest of the file the line came from so an auditor can
		// re-read the source in the bundle rather than trusting this excerpt.
		ev := []finding.Evidence{finding.NewEvidence(
			d.File, d.Line,
			fmt.Sprintf("%s %s", d.Keyword, d.Value),
			cfg.Digests[d.File])}

		// If the operator has a Match-scoped override, name it. Otherwise the
		// report contradicts what they can plainly see in the file, and they
		// stop trusting the tool.
		if scoped := matchScopedEvidence(cfg, "PermitRootLogin"); len(scoped) > 0 {
			ev = append(ev, scoped...)
		}

		switch strings.ToLower(d.Value) {
		case "no":
			// A Match block can re-enable root login for a subset of
			// connections, and reporting PASS while that is true would be
			// exactly the false assurance this module exists to avoid. The
			// severity steps down one class because the exposure is
			// conditional rather than global — see conditionalFail.
			if loosened := loosenedInMatch(cfg, "PermitRootLogin", permitsRootLogin); len(loosened) > 0 {
				return conditionalFail(cfg, "PermitRootLogin",
					fmt.Sprintf("set to %q globally at %s:%d", d.Value, d.File, d.Line),
					ev[0], loosened, finding.High,
					"Root may log in directly on connections matching those blocks, so administrator actions from them are not individually attributable.")
			}
			return catalog.Outcome{
				Result:   finding.Pass,
				Detail:   "PermitRootLogin is set to no; direct root login over SSH is refused.",
				Evidence: ev,
			}

		case "yes":
			return catalog.Outcome{
				Result:   finding.Fail,
				Severity: finding.High,
				Detail: fmt.Sprintf(
					"PermitRootLogin is set to %q at %s:%d; root may log in directly, including with a password.",
					d.Value, d.File, d.Line),
				Evidence: ev,
			}

		case "prohibit-password", "without-password", "forced-commands-only":
			return catalog.Outcome{
				Result:   finding.Fail,
				Severity: finding.Medium,
				Detail: fmt.Sprintf(
					"PermitRootLogin is set to %q at %s:%d; password login is refused but root may still authenticate directly with a key, so administrator actions are not individually attributable.",
					d.Value, d.File, d.Line),
				Evidence: ev,
			}

		default:
			// sshd would refuse to start on an unrecognised value, so the
			// running configuration is not what this file says. Say so rather
			// than guessing in either direction.
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Detail: fmt.Sprintf(
					"PermitRootLogin has unrecognised value %q at %s:%d; sshd would reject this configuration, so the running server may be using a different file.",
					d.Value, d.File, d.Line),
				Evidence: ev,
			}
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set PermitRootLogin to no and reload sshd.",
		Effort:  "LOW",
		Steps: []string{
			"Confirm you have a non-root account that can log in over SSH and escalate with sudo.",
			"Verify that account works in a second, separate session before continuing.",
			"Set 'PermitRootLogin no' in /etc/ssh/sshd_config, or in a file under /etc/ssh/sshd_config.d/ if the distribution uses Include.",
			"Check the configuration parses: sshd -t",
			"Reload sshd; keep the existing session open until a new one is verified.",
		},
		Commands: []string{
			"sshd -t",
			"systemctl reload sshd",
		},
		Caution: "Applying this while your only access is a root SSH session will lock you out. Verify a non-root path in a separate session first, and never reload sshd from the session you would lose.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6(2)"},
		{Framework: "nist-800-53-r5", Control: "AC-6(5)"},
		{Framework: "nist-800-53-r5", Control: "IA-2(1)"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — PermitRootLogin", URL: "https://man.openbsd.org/sshd_config#PermitRootLogin"},
	},
}

// permitsRootLogin reports whether a PermitRootLogin value admits root at all.
//
// An unrecognised value is not "permits": sshd would refuse to start on it, so
// it is a parse problem rather than a permissive setting, and treating the two
// alike would report a typo inside a Match block as a deliberate weakening.
func permitsRootLogin(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "prohibit-password", "without-password", "forced-commands-only":
		return true
	}
	return false
}

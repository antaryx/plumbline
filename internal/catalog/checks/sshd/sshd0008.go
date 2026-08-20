package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0008 tests whether the server will tunnel arbitrary TCP connections.
var Check0008 = catalog.Check{
	ID:     "SSHD-0008",
	Module: "SSHD",
	Title:  "TCP forwarding is restricted",
	Description: `TCP forwarding turns an SSH session into a general-purpose
network tunnel. With it unrestricted, any user who can log in can reach any
address this host can reach ('ssh -L'), and can expose any port of this host's
network to their own client ('ssh -R'). Neither requires a shell: an account
with /usr/sbin/nologin still forwards.

That matters because network segmentation is usually the control that survives
when everything else has failed. A database in a private subnet, a management
interface on a separate VLAN, an internal API with no authentication because it
is "not reachable" — all of them are reachable from a workstation the moment one
account on a host in that subnet can forward. Egress filtering fails the same
way in reverse.

sshd accepts five values. 'yes' and 'all' permit everything. 'local' permits
only -L, 'remote' only -R, and 'no' neither. The OpenSSH default is 'yes'.

This check fails only the unrestricted values. 'local' and 'remote' each close
one direction and are reported as a pass with the remaining direction named,
because which one a host needs is a question about its role that no scanner can
answer. Note also that this is not a boundary against a determined user with
shell access — anyone who can execute code can run their own tunnel — so it is
a control over the default and the accidental, not over the adversary who
already has a shell.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "network", "lateral-movement"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: func(fs *fact.Set) catalog.Outcome {
		unrestricted := func(v string) bool {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "yes", "all":
				return true
			}
			return false
		}

		return evaluate(fs, "AllowTcpForwarding",
			func(cfg fact.SSHDConfig) catalog.Outcome {
				return catalog.Outcome{
					Result:  finding.Fail,
					Subject: "AllowTcpForwarding",
					Detail: fmt.Sprintf(
						"AllowTcpForwarding is not configured, so sshd applies its built-in default of %q: any account that can authenticate — including one with a nologin shell — can tunnel arbitrary TCP in both directions through this host, reaching anything this host can reach and exposing this host's network to their client.",
						defaultAllowTcpForwarding),
					Evidence: []finding.Evidence{primaryEvidence(cfg,
						fmt.Sprintf("AllowTcpForwarding not present in any parsed file; built-in default %q applies",
							defaultAllowTcpForwarding))},
				}
			},

			func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
				ev := append([]finding.Evidence{directiveEvidence(cfg, d)},
					matchScopedEvidence(cfg, "AllowTcpForwarding")...)

				pass := func(detail string) catalog.Outcome {
					if loosened := loosenedInMatch(cfg, "AllowTcpForwarding", unrestricted); len(loosened) > 0 {
						return conditionalFail(cfg, "AllowTcpForwarding",
							fmt.Sprintf("set to %q globally at %s:%d", d.Value, d.File, d.Line),
							ev[0], loosened, finding.Medium,
							"Connections matching those blocks can tunnel arbitrary TCP through this host in both directions.")
					}
					return catalog.Outcome{Result: finding.Pass, Detail: detail, Evidence: ev}
				}

				switch strings.ToLower(strings.TrimSpace(d.Value)) {
				case "no":
					return pass(fmt.Sprintf(
						"AllowTcpForwarding is set to %q at %s:%d; no session can tunnel TCP in either direction, so an account on this host cannot be used to reach past the network boundary it sits behind.",
						d.Value, d.File, d.Line))

				case "local":
					return pass(fmt.Sprintf(
						"AllowTcpForwarding is set to %q at %s:%d; remote forwarding (-R) is refused, so this host's network cannot be exposed to a client. Local forwarding (-L) remains available, which still lets an authenticated user reach anything this host can reach — set 'no' if that is not intended.",
						d.Value, d.File, d.Line))

				case "remote":
					return pass(fmt.Sprintf(
						"AllowTcpForwarding is set to %q at %s:%d; local forwarding (-L) is refused, so a user cannot reach past this host into its network. Remote forwarding (-R) remains available, which still lets a user expose a listener on this host — set 'no' if that is not intended.",
						d.Value, d.File, d.Line))

				case "yes", "all":
					return catalog.Outcome{
						Result:  finding.Fail,
						Subject: "AllowTcpForwarding",
						Detail: fmt.Sprintf(
							"AllowTcpForwarding is set to %q at %s:%d, so any account that can authenticate can tunnel arbitrary TCP in both directions: reaching anything this host can reach, and exposing this host's network to their own client. Network segmentation around this host does not constrain an authenticated SSH user.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}

				default:
					return catalog.Outcome{
						Result:        finding.Unknown,
						UnknownReason: finding.ReasonParse,
						Subject:       "AllowTcpForwarding",
						Detail: fmt.Sprintf(
							"AllowTcpForwarding has unrecognised value %q at %s:%d; sshd accepts only yes, all, no, local or remote and would reject this configuration, so the running server may be using a different file.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}
				}
			})
	},

	Remediation: &finding.Remediation{
		Summary: "Set AllowTcpForwarding no, or restrict it to the direction the host's role requires.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Establish what uses it first. Forwarding is invisible in most monitoring; 'ss -tnp' on the host during normal operation shows the loopback listeners that -R creates, and client-side ~/.ssh/config files often document -L usage.",
			"For a host with no tunnelling role, set 'AllowTcpForwarding no' in /etc/ssh/sshd_config.",
			"For a bastion, forwarding is the point — scope it instead. A 'Match Group jumpusers' block with 'AllowTcpForwarding yes' inside an otherwise-'no' configuration confines it to the accounts that need it. Plumbline reports that as a conditional finding rather than a clean pass, which is the accurate reading: the capability exists, for a named set of users.",
			"Where an account only needs sftp, combine 'ForceCommand internal-sftp' with 'AllowTcpForwarding no' — the shell restriction alone does not stop forwarding.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i allowtcpforwarding",
		},
		Caution: "Database clients, CI runners and remote IDE sessions frequently tunnel through a host without anyone recording that they do. Turning this off produces connection failures in tooling far from the host you changed, and the error surfaces on the client, not here.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "AC-4"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — AllowTcpForwarding", URL: "https://man.openbsd.org/sshd_config#AllowTcpForwarding"},
	},
}

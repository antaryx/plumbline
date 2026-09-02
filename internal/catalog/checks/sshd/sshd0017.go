package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0017 tests whether a pre-authentication banner is presented.
//
// This is the one check in the module whose purpose is legal rather than
// technical, and it is written to say so. A banner stops no attacker. What it
// does is establish that access was not authorised by default, which is what
// several jurisdictions require before unauthorised access can be prosecuted
// and what most computer-use policies rely on.
var Check0017 = catalog.Check{
	ID:     "SSHD-0017",
	Module: "SSHD",
	Title:  "A pre-authentication warning banner is presented",
	Description: `Banner names a file whose contents sshd sends to the client
before authentication. It has no effect on what anyone can do.

Its purpose is evidentiary. Several legal regimes, and most organisational
computer-use policies, distinguish between a system that announced its access
conditions and one that did not, and the announcement has to precede
authentication to be relied on. Where an organisation intends to be able to act
on unauthorised access, this is the mechanism that records the intent.

Two practical notes. The banner must not describe the host: version numbers,
hostnames, roles and contact details in a pre-authentication banner are
reconnaissance handed to anyone who connects, and the file is world-readable to
the internet by construction. And Banner is not the same as MOTD, which is
displayed after authentication and therefore says nothing to anyone who failed
to authenticate.

The OpenSSH default is 'none', no banner.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"ssh", "compliance", "policy"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: func(fs *fact.Set) catalog.Outcome {
		disabled := func(v string) bool {
			return strings.EqualFold(strings.TrimSpace(v), "none")
		}

		return evaluate(fs, "Banner",
			func(cfg fact.SSHDConfig) catalog.Outcome {
				return catalog.Outcome{
					Result:  finding.Fail,
					Subject: "Banner",
					Detail:  "Banner is not configured, so sshd applies its built-in default of \"none\" and presents nothing before authentication. Access conditions are therefore not announced to anyone connecting, which is the condition several legal regimes and most computer-use policies require before unauthorised access can be acted on.",
					Evidence: []finding.Evidence{primaryEvidence(cfg,
						"Banner not present in any parsed file; built-in default \"none\" applies")},
				}
			},

			func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
				ev := append([]finding.Evidence{directiveEvidence(cfg, d)},
					matchScopedEvidence(cfg, "Banner")...)

				if disabled(d.Value) {
					return catalog.Outcome{
						Result:  finding.Fail,
						Subject: "Banner",
						Detail: fmt.Sprintf(
							"Banner is set to %q at %s:%d, which explicitly disables the pre-authentication banner. Nothing is presented before authentication, so access conditions are not announced.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}
				}

				if loosened := loosenedInMatch(cfg, "Banner", disabled); len(loosened) > 0 {
					return conditionalFail(cfg, "Banner",
						fmt.Sprintf("set to %q globally at %s:%d", d.Value, d.File, d.Line),
						ev[0], loosened, finding.Low,
						"Connections matching those blocks are presented with no banner at all.")
				}

				// The file's existence and contents are deliberately not
				// asserted. Plumbline does not read arbitrary operator-named
				// paths from a directive (ADR-0011), and a banner that names a
				// missing file fails open — sshd logs and continues — so the
				// check reports what the configuration says and tells the
				// reader what it did not verify.
				return catalog.Outcome{
					Result: finding.Pass,
					Detail: fmt.Sprintf(
						"Banner is set to %q at %s:%d, so access conditions are presented before authentication. This check does not read that file: whether it exists, and whether its contents leak host details that should not be shown before authentication, are not verified here.",
						d.Value, d.File, d.Line),
					Evidence: ev,
				}
			})
	},

	Remediation: &finding.Remediation{
		Summary: "Write a banner file containing your organisation's access notice and point Banner at it.",
		Effort:  "LOW",
		Steps: []string{
			"Get the wording from whoever owns it, legal or security, not the person editing sshd_config. The text is the entire value of this control and a generic one may not carry the effect intended.",
			"Write it to /etc/issue.net and set 'Banner /etc/issue.net' in /etc/ssh/sshd_config.",
			"Check what the file does not say: no hostname, no operating system version, no role, no contact details. Everything in it is shown to anyone who connects, before they authenticate.",
			"Confirm the file is world-readable and not a symlink into anything unexpected: 'ls -lL /etc/issue.net'.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'. Verify with 'ssh -o PreferredAuthentications=none <host>' from elsewhere.",
		},
		Commands: []string{
			"sshd -T | grep -i banner",
			"ssh -o PreferredAuthentications=none <host>",
		},
		Caution: "Automated clients that parse SSH output, older scripted transfers and some monitoring probes, can be confused by unexpected banner text. Test against the automation that talks to this host, not only from an interactive terminal.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-8"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). Banner", URL: "https://man.openbsd.org/sshd_config#Banner"},
	},
}

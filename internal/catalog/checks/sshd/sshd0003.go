package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests whether password authentication is accepted over SSH.
var Check0003 = catalog.Check{
	ID:     "SSHD-0003",
	Module: "SSHD",
	Title:  "Password authentication over SSH is disabled",
	Description: `A password is a secret a person can be persuaded to type. Over
SSH it is also a secret an attacker can attempt from anywhere on the internet,
at whatever rate the server will tolerate, against a username list that is
largely guessable. Every large-scale SSH compromise of the last two decades has
run through this door: credential stuffing from other breaches, spraying a
common password across many accounts, or simply exhausting a weak one.

Public-key authentication removes the class entirely. The private key never
leaves the client, there is nothing to guess, and a stolen credential is a file
an attacker must first obtain rather than a string they can derive.

The OpenSSH default is yes, so a host that has never been configured accepts
passwords. Debian, Ubuntu and RHEL all ship it explicitly as yes as well, which
means this finding appears on a stock installation of every mainstream
distribution, correctly.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "remote-access", "authentication", "credentials"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "PasswordAuthentication",
		Secure:  "no",
		Default: defaultPasswordAuthentication,
		Base:    finding.High,
		Consequence: "any account with a usable password can be attacked remotely by " +
			"guessing it, at whatever rate this server tolerates",
		Assurance: "authentication requires a key, so there is no secret an attacker can guess remotely",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Deploy keys for every account that needs SSH access, then set PasswordAuthentication no.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Establish key access first: 'ssh-copy-id <user>@<host>' for every account that logs in, and confirm each one works in a separate session.",
			"Check who would be locked out: 'awk -F: '\\''$2 !~ /^[!*]/ && $2 != \"\" {print $1}'\\'' /etc/shadow' lists accounts that currently rely on a password.",
			"Set 'PasswordAuthentication no' in /etc/ssh/sshd_config, or in a drop-in under /etc/ssh/sshd_config.d/ if the distribution uses Include.",
			"Set 'KbdInteractiveAuthentication no' as well. On a host with UsePAM yes, leaving it at its default can let PAM accept a password through a different code path, which is the most common reason this change appears not to take effect.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd', keeping the current session open until a new one is verified.",
		},
		Commands: []string{
			"sshd -t",
			"sshd -T | grep -Ei 'passwordauthentication|kbdinteractive'",
		},
		Caution: "This is the change most likely to lock you out of a remote host. Verify key authentication works in a second, independent session before reloading, and never reload from the session you would lose. If the host has no out-of-band console, arrange one first.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-2(1)"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). PasswordAuthentication", URL: "https://man.openbsd.org/sshd_config#PasswordAuthentication"},
	},
}

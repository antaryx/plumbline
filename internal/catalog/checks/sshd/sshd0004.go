package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests whether accounts with an empty password may log in over SSH.
var Check0004 = catalog.Check{
	ID:     "SSHD-0004",
	Module: "SSHD",
	Title:  "Accounts with empty passwords cannot log in over SSH",
	Description: `PermitEmptyPasswords yes allows an account whose password
field in /etc/shadow is empty to authenticate over SSH by pressing return. No
guessing, no credential, no rate limit that matters.

The OpenSSH default is no, so this can only be reached deliberately, usually by
a hardening script that inverted a value, an appliance image built for
convenience, or a container base image where a password was never set and the
setting was relaxed to make the account usable.

This is the SSH-facing half of USERS-0003. That check reports which accounts
have an empty password field; this one reports whether the SSH server will
accept it. Either alone is survivable. Both together is remote unauthenticated
access, which is why this check is CRITICAL rather than HIGH: no other single
sshd_config value produces that outcome by itself.`,

	BaseSeverity: finding.Critical,
	Tags:         []string{"ssh", "remote-access", "authentication", "credentials"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "PermitEmptyPasswords",
		Secure:  "no",
		Default: defaultPermitEmptyPasswords,
		Base:    finding.Critical,
		Consequence: "any account whose password field is empty can log in remotely by pressing return, " +
			"with no credential to steal and nothing to guess",
		Assurance: "an account with an empty password field is refused rather than admitted",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set PermitEmptyPasswords no, and fix the accounts that made it reachable.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config. This is the OpenSSH default, so the line can also simply be removed.",
			"Find the accounts this was protecting or exposing: 'awk -F: '\\''$2 == \"\" {print $1}'\\'' /etc/shadow'. USERS-0003 reports the same set.",
			"For each, decide whether it needs a password ('passwd <name>') or should not authenticate at all ('passwd -l <name>').",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
			"Check whether the door was used while it was open: 'last', 'lastlog', and the authentication log for accepted logins by those accounts.",
		},
		Commands: []string{
			"sshd -T | grep -i permitemptypasswords",
			"awk -F: '$2 == \"\" {print $1}' /etc/shadow",
		},
		Caution: "If a service or automation authenticates as an account with an empty password, this change stops it. That is the correct outcome, but find out what breaks before you are told by an outage, and treat any account that was reachable this way as potentially compromised rather than merely misconfigured.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). PermitEmptyPasswords", URL: "https://man.openbsd.org/sshd_config#PermitEmptyPasswords"},
	},
}

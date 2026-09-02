package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0015 tests whether users may set environment variables at login.
var Check0015 = catalog.Check{
	ID:     "SSHD-0015",
	Module: "SSHD",
	Title:  "Users cannot set arbitrary environment variables at login",
	Description: `PermitUserEnvironment yes makes sshd read ~/.ssh/environment
and the environment= options in ~/.ssh/authorized_keys, and apply what it finds
to the session before any shell starts.

That turns a file the user can write into the environment of a process the
system starts on their behalf. LD_PRELOAD is the direct route: a user who can
set it loads a library of their choosing into every program run from that
session, including anything the session later escalates to. PATH, LD_LIBRARY_PATH
and BASH_ENV are variations on the same theme.

Where this matters most is exactly where the user was supposed to be
constrained, a forced-command key, a restricted shell, an sftp-only account.
Each of those confines what the user may run, and none of them confines what
the user may load into it.

The OpenSSH default is no, and the manual page recommends leaving it there.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "privilege"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "PermitUserEnvironment",
		Secure:  "no",
		Default: defaultPermitUserEnvironment,
		Base:    finding.Medium,
		Consequence: "a user can set LD_PRELOAD and PATH for their own session from a file they " +
			"control, which subverts forced commands, restricted shells and any other constraint " +
			"that limits what they may run rather than what they may load",
		Assurance: "the session environment comes from the system rather than from files the user can write",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set PermitUserEnvironment no and use AcceptEnv or SetEnv for variables that genuinely need to pass through.",
		Effort:  "LOW",
		Steps: []string{
			"Find out what is relying on it: 'ls /home/*/.ssh/environment' and 'grep -l environment= /home/*/.ssh/authorized_keys'.",
			"Set 'PermitUserEnvironment no' in /etc/ssh/sshd_config, the OpenSSH default, so the line may be removed.",
			"Where a variable genuinely must reach the session, name it explicitly: 'AcceptEnv' allows a listed variable from the client, and 'SetEnv' sets one from the server. Both are administrator-controlled, which is the difference that matters.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i permituserenvironment",
			"ls /home/*/.ssh/environment 2>/dev/null",
		},
		Caution: "Automation that sets variables through authorized_keys, build agents and deployment keys most often, will lose them silently: the session starts normally and the variable is simply absent. Check for the files before reloading rather than after the first failed job.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SI-3"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). PermitUserEnvironment", URL: "https://man.openbsd.org/sshd_config#PermitUserEnvironment"},
	},
}

package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0014 tests whether host-based authentication is enabled.
var Check0014 = catalog.Check{
	ID:     "SSHD-0014",
	Module: "SSHD",
	Title:  "Host-based authentication is disabled",
	Description: `Host-based authentication admits a user because of the machine
they are connecting from, not because of anything they know or hold. The client
host proves its identity with its own host key, and from that point sshd accepts
whichever local username the client asserts.

The consequence is that the trusted host's security boundary becomes this host's
security boundary. Anyone with root on the trusted machine, or anyone who can
read its host key, which lives on disk and is often included in backups and
machine images, can authenticate here as any user the trust covers. A single
compromised workstation becomes access to every host that trusted it, with no
credential to steal and nothing in this host's logs that distinguishes it from
a legitimate login.

The OpenSSH default is no. This is the modern descendant of rhosts trust
(SSHD-0013), and the two are usually enabled together.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "remote-access", "authentication", "lateral-movement"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "HostbasedAuthentication",
		Secure:  "no",
		Default: defaultHostbasedAuthentication,
		Base:    finding.High,
		Consequence: "a user is admitted on the strength of the machine they came from, so root on any " +
			"trusted host — or anyone holding a copy of its host key — can authenticate here as any " +
			"user that trust covers",
		Assurance: "authentication requires a credential this user holds rather than a machine they came from",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set HostbasedAuthentication no and remove the trust configuration behind it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Establish what currently depends on it before changing anything: 'cat /etc/ssh/shosts.equiv /etc/hosts.equiv' and the per-user ~/.shosts files list the trusted hosts.",
			"Replace the trust with keys for whatever automation relied on it. A per-account key with a forced command is both narrower and auditable.",
			"Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config, the OpenSSH default, so the line may simply be removed.",
			"Remove /etc/shosts.equiv, /etc/hosts.equiv and any ~/.shosts files, after recording their contents for the incident trail.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i hostbasedauthentication",
			"cat /etc/ssh/shosts.equiv /etc/hosts.equiv 2>/dev/null",
		},
		Caution: "Cluster tooling from the HPC and older Unix worlds, parallel shells, batch schedulers, some backup agents, depends on this. Each of those is currently authenticating with no per-user credential; migrate them to keys rather than leaving the trust in place, and expect the migration to take longer than the config change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "IA-3"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). HostbasedAuthentication", URL: "https://man.openbsd.org/sshd_config#HostbasedAuthentication"},
	},
}

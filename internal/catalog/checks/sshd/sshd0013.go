package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0013 tests whether the legacy rhosts trust files are honoured.
var Check0013 = catalog.Check{
	ID:     "SSHD-0013",
	Module: "SSHD",
	Title:  "Per-user .rhosts and .shosts files are ignored",
	Description: `~/.rhosts and ~/.shosts are the BSD r-command trust files: a
line naming a host and a user in one of them says "let that user in from that
host without a credential". The trust is asserted by the client's hostname,
which is exactly the thing an attacker on the network controls.

IgnoreRhosts yes tells sshd not to consult them. The keyword only has an effect
where host-based authentication is actually enabled (SSHD-0014), so on most
hosts this is defence in depth rather than an active exposure, but the two
settings are frequently changed together by the same legacy migration, and a
host that has turned one on has usually turned the other on too.

The OpenSSH default is yes. A host reporting a failure here has been configured
to honour these files deliberately, which is worth knowing on its own.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "authentication", "legacy"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "IgnoreRhosts",
		Secure:  "yes",
		Default: defaultIgnoreRhosts,
		Base:    finding.Medium,
		Consequence: "sshd consults ~/.rhosts and ~/.shosts, so a user who can write their own home " +
			"directory can grant access to any account on any host they can impersonate on the network",
		Assurance: "the legacy rhosts trust files are not consulted, so a writable home directory cannot grant remote access",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set IgnoreRhosts yes and remove the trust files that are already on disk.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config. This is the OpenSSH default, so the line can also be removed.",
			"Find the files that exist regardless: 'find /home /root -maxdepth 2 -name .rhosts -o -name .shosts'.",
			"Read each one before deleting it, its contents record who was trusted, which is worth keeping for the incident record if the host has been exposed.",
			"Confirm host-based authentication is also off (SSHD-0014), since that is what gives these files their effect.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i ignorerhosts",
			"find /home /root -maxdepth 2 \\( -name .rhosts -o -name .shosts \\)",
		},
		Caution: "A legacy application that still relies on r-command trust will stop authenticating. Those are rare in 2026 and each one is a standing unauthenticated-access path, so find out what breaks rather than leaving the setting in place.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). IgnoreRhosts", URL: "https://man.openbsd.org/sshd_config#IgnoreRhosts"},
	},
}

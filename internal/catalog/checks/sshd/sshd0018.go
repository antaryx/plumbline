package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0018 tests whether SSH agent forwarding is offered.
var Check0018 = catalog.Check{
	ID:     "SSHD-0018",
	Module: "SSHD",
	Title:  "SSH agent forwarding is disabled",
	Description: `Agent forwarding places a socket on the server that anyone
with root there, or the user's own uid, can use to sign authentication
requests with the keys held in the user's local agent. The keys themselves do
not move, which is what the feature is usually defended with, but the ability to
authenticate with them does, for as long as the session is open. A compromised
jump host can use a forwarded agent to log into every other host that user's key
opens, and the resulting logins are indistinguishable from the real ones.

ProxyJump ('ssh -J') achieves what agent forwarding is normally used for without
this property: the connection to the final host is negotiated from the client,
the intermediate host sees only encrypted traffic, and no socket is exposed on
it. It has been available since OpenSSH 7.3 (2016) and is the answer in almost
every case where agent forwarding is still configured.

The OpenSSH default is yes. This ships at LOW because the exposure requires the
server to be compromised first, and because the setting is only reachable when
a user chooses to forward, but on a bastion, which is precisely where agent
forwarding is most used, that first condition is the whole threat model.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"ssh", "remote-access", "lateral-movement", "credentials"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "AllowAgentForwarding",
		Secure:  "no",
		Default: defaultAllowAgentForwarding,
		Base:    finding.Low,
		Consequence: "a user who forwards their agent exposes a socket on this host that root here can " +
			"use to authenticate as them to every other host their keys open, for as long as the " +
			"session lasts",
		Assurance: "no forwarded agent socket is created, so a compromise of this host cannot borrow a user's keys",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set AllowAgentForwarding no and move users to ProxyJump.",
		Effort:  "LOW",
		Steps: []string{
			"Establish the replacement first: 'ssh -J bastion.example.net target.example.net', or a 'ProxyJump' line in the users' ~/.ssh/config. This is what agent forwarding is usually being used for.",
			"Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config.",
			"Note that this is not a security boundary against a determined user, anyone who can run a shell here can forward a connection themselves. It removes the default and the accident, not the capability.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i allowagentforwarding",
		},
		Caution: "Deployment tooling that hops through this host to reach a git remote or a downstream server will stop authenticating. ProxyJump or a deploy key scoped to the specific repository are the replacements; arrange one before the change rather than after the pipeline fails.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-17"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). AllowAgentForwarding", URL: "https://man.openbsd.org/sshd_config#AllowAgentForwarding"},
		{Title: "ssh_config(5). ProxyJump", URL: "https://man.openbsd.org/ssh_config#ProxyJump"},
	},
}

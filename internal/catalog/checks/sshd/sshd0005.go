package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests whether the server offers X11 forwarding.
var Check0005 = catalog.Check{
	ID:     "SSHD-0005",
	Module: "SSHD",
	Title:  "X11 forwarding is disabled",
	Description: `X11 has no meaningful isolation between clients. A program
connected to an X display can read every keystroke sent to any other window on
that display, take screenshots of it, and inject synthetic input into it. That
is not a defect; it is the protocol working as designed for a 1984 model of a
trusted local network.

X11 forwarding extends that display across an SSH connection. When a user with
forwarding enabled logs into a server, a process on the server can reach back
through the tunnel to their workstation's display — so a compromise of the
server becomes a keylogger on the administrator's desktop. 'ForwardX11Trusted'
makes this explicit; without it the X11 SECURITY extension restricts some
operations, but it is widely regarded as insufficient and OpenSSH's own manual
warns against relying on it.

The upstream OpenSSH default is no. **Debian and Ubuntu ship X11Forwarding yes
in their packaged sshd_config**, so this check reports a finding on a stock
installation of either — which is correct, and is the most common reason it
appears.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "attack-surface", "lateral-movement"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "X11Forwarding",
		Secure:  "no",
		Default: defaultX11Forwarding,
		Base:    finding.Medium,
		Consequence: "a process on this server can reach back through a user's session to their " +
			"workstation display, where X11's absence of client isolation lets it log keystrokes " +
			"and inject input into every other window",
		Assurance: "no session can reach a client's X display through this server",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set X11Forwarding no; use a browser or a purpose-built remote desktop where a GUI is genuinely needed.",
		Effort:  "LOW",
		Steps: []string{
			"Find out whether anything uses it before disabling it: 'grep -i x11 /var/log/auth.log' or 'journalctl -u sshd | grep -i x11' shows forwarding requests.",
			"Set 'X11Forwarding no' in /etc/ssh/sshd_config. On Debian and Ubuntu the packaged file sets it to yes explicitly, so the line must be changed rather than removed.",
			"Where a small number of users genuinely need it, scope it rather than enabling it globally: a 'Match User' block confines the exposure to named accounts — Plumbline reports that as a conditional finding rather than a clean pass, which is the honest reading.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i x11forwarding",
		},
		Caution: "Administrators who run graphical tools over SSH — installers, database consoles, some vendor appliances — will find them stop working with no error more helpful than 'cannot open display'. Establish the replacement path before making the change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — X11Forwarding", URL: "https://man.openbsd.org/sshd_config#X11Forwarding"},
		{Title: "ssh(1) — X11 forwarding warning", URL: "https://man.openbsd.org/ssh#X"},
	},
}

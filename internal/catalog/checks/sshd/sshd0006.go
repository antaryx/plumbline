package sshd

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// maxAuthTriesLimit is the highest MaxAuthTries this check accepts.
//
// 4 is the CIS figure. The number matters less than the shape: sshd logs a
// failure once a connection passes half of MaxAuthTries, so a limit of 6 means
// the first three attempts of every connection are silent. A limit of 4 makes
// the third attempt visible, and a client with several keys loaded still gets
// enough attempts to offer them before being disconnected.
const maxAuthTriesLimit = 4

// Check0006 tests how many authentication attempts one connection may make.
var Check0006 = catalog.Check{
	ID:     "SSHD-0006",
	Module: "SSHD",
	Title:  "Authentication attempts per connection are limited",
	Description: `MaxAuthTries bounds the number of authentication attempts sshd
will accept on a single TCP connection before dropping it. It does not limit how
many connections an attacker may open, so it is not by itself a defence against
password guessing, pam_faillock and a rate limit at the network layer are what
do that.

What it does control is the cost per connection and, less obviously, what gets
logged. sshd writes a failure to the authentication log once a connection has
used more than **half** of MaxAuthTries. With the default of 6 the first three
attempts of every connection produce no log line at all, which is a meaningful
blind spot for anything watching that log for brute-force patterns. Lowering the
limit to 4 makes the third attempt visible.

The upstream default is 6. This check accepts 4 or fewer, and treats 0 as a
misconfiguration rather than maximum strictness: sshd refuses every
authentication at 0, which is a denial of service rather than a hardening.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "authentication", "logging"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: intSpec{
		Keyword:    "MaxAuthTries",
		Default:    defaultMaxAuthTries,
		Acceptable: func(n int) bool { return n >= 1 && n <= maxAuthTriesLimit },
		Render:     func(n int) string { return fmt.Sprintf("%d attempt(s) per connection", n) },
		Base:       finding.Medium,
		Syntax:     "a positive whole number",
		Consequence: fmt.Sprintf(
			"each connection may make more than %d attempts, and because sshd only logs a failure "+
				"once a connection has used more than half its allowance, the earlier attempts leave "+
				"no record for anything watching the authentication log", maxAuthTriesLimit),
		Assurance: "a connection is dropped after a small number of attempts, and a failure is logged " +
			"early enough for log-based detection to see it",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set MaxAuthTries to 4 or fewer, and add a real lockout mechanism alongside it.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.",
			"Do not treat this as brute-force protection on its own. It bounds attempts per connection, not per attacker; configure pam_faillock (or the distribution equivalent) for account lockout, and rate-limit port 22 at the firewall.",
			"If users authenticate with several keys, check that the limit still fits: each key the client offers consumes one attempt, so a user with five keys loaded can exhaust a limit of 4 before reaching the right one. 'IdentitiesOnly yes' in their client configuration is the fix on that side.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i maxauthtries",
		},
		Caution: "Users with many keys in their agent can be disconnected before the correct key is offered, which presents as an intermittent 'Too many authentication failures' that is easy to misattribute to the server. Warn users to set IdentitiesOnly, or raise the limit slightly rather than leaving it at the default.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-7"},
		{Framework: "nist-800-53-r5", Control: "AU-2"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). MaxAuthTries", URL: "https://man.openbsd.org/sshd_config#MaxAuthTries"},
	},
}

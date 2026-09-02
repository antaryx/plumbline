package sshd

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// loginGraceLimit is the longest LoginGraceTime this check accepts, in seconds.
const loginGraceLimit = 60

// Check0016 tests how long an unauthenticated connection may stay open.
var Check0016 = catalog.Check{
	ID:     "SSHD-0016",
	Module: "SSHD",
	Title:  "Unauthenticated connections are closed promptly",
	Description: `LoginGraceTime is how long sshd will hold a connection open
before the client has authenticated. Every such connection occupies one of the
slots MaxStartups allows, and each one runs a pre-authentication process.

The default is 120 seconds, which means an attacker can hold the listener's
unauthenticated capacity with a trickle of connections that never complete,
the classic slow-loris shape applied to SSH. Reducing it to 60 seconds or less
halves the cost of holding a slot without inconveniencing anyone: an interactive
login that takes more than a minute to authenticate has a different problem.

The wider reason to care is that pre-authentication code is the most exposed
code in the daemon. It is what CVE-2024-6387 ("regreSSHion") reached, and that
vulnerability was triggered specifically by letting the grace timer expire, on
a host running the vulnerable version, a shorter grace time raised the cost of
the attack because each attempt had to be repeated more often. Shortening the
window does not fix such bugs, but it reduces how long an unauthenticated peer
gets to work with the code that contains them.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"ssh", "remote-access", "availability", "attack-surface"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: intSpec{
		Keyword: "LoginGraceTime",
		Default: defaultLoginGraceTime,
		Parse:   parseTimeSeconds,
		// 0 disables the timeout entirely: the connection is held until the
		// client goes away. That is the worst value, not the strictest, and a
		// bare "n <= 60" would have reported it as a PASS.
		Acceptable: func(n int) bool { return n > 0 && n <= loginGraceLimit },
		Render:     func(n int) string { return fmt.Sprintf("%d second(s)", n) },
		Base:       finding.Low,
		Syntax:     "a number of seconds, or a time format such as '1m'",
		Consequence: fmt.Sprintf(
			"an unauthenticated connection may occupy a listener slot for longer than %d seconds, "+
				"so a small number of connections that never authenticate can exhaust the "+
				"unauthenticated capacity, and each one holds open the most exposed code in the daemon",
			loginGraceLimit),
		Assurance: "an unauthenticated connection is closed promptly, so the pre-authentication " +
			"capacity of the listener cannot be held open cheaply",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set LoginGraceTime to 60 seconds or less.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'LoginGraceTime 60' in /etc/ssh/sshd_config. Never set it to 0, that disables the timeout rather than tightening it.",
			"Review MaxStartups at the same time; the grace time and the connection limit together decide how cheaply the listener can be saturated.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -Ei 'logingracetime|maxstartups'",
		},
		Caution: "Interactive authentication that involves a hardware token, a push notification or a slow directory lookup can legitimately take longer than a user expects. Sixty seconds is comfortable for all three; going much below that will start rejecting real logins during a directory outage.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-5"},
		{Framework: "nist-800-53-r5", Control: "AC-17"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5). LoginGraceTime", URL: "https://man.openbsd.org/sshd_config#LoginGraceTime"},
		{Title: "CVE-2024-6387 (regreSSHion)", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
	},
}

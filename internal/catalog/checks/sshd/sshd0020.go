package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0020 tests whether sshd runs the PAM stack.
//
// This is the check that ties the SSHD module to the USERS module. Everything
// USERS-0009 and USERS-0010 assert about password aging is enforced by
// pam_unix's account phase; with UsePAM no, sshd never runs it, and the policy
// those checks report is simply not applied to SSH logins.
var Check0020 = catalog.Check{
	ID:     "SSHD-0020",
	Module: "SSHD",
	Title:  "sshd runs the PAM account and session stack",
	Description: `With UsePAM no, sshd authenticates against /etc/shadow itself
and starts the session directly. Nothing in the PAM stack runs, and everything
that lives there stops applying to SSH logins specifically:

- **Account expiry and password aging.** The shadow fields USERS-0009 and
  USERS-0010 report are enforced by pam_unix's account phase. Without it, an
  expired password and an expired account both still log in.
- **Lockout after repeated failures.** pam_faillock and pam_tally2 never see the
  attempt, so an account can be attacked indefinitely regardless of how the
  lockout policy is written.
- **Access restrictions.** pam_access, pam_time and pam_nologin are all bypassed,
  including the /etc/nologin file an administrator writes during maintenance.
- **Session accounting.** pam_limits, pam_loginuid and the session records other
  tools read are never established, which degrades both resource control and the
  audit trail.

The upstream OpenSSH default is **no**. Every mainstream distribution ships
'UsePAM yes' in its packaged sshd_config, so a host reporting a failure here has
either had the line removed or is running a configuration built from scratch —
and in either case a policy the operator believes is in force is not.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "remote-access", "authentication", "policy-enforcement"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "UsePAM",
		Secure:  "yes",
		Default: defaultUsePAM,
		Base:    finding.High,
		Consequence: "sshd never runs the PAM account and session stack, so password aging, account " +
			"expiry, failed-login lockout, pam_access restrictions and /etc/nologin are all bypassed " +
			"for SSH logins — the policy is configured and simply not applied",
		Assurance: "the PAM account and session stack runs, so account expiry, lockout and access " +
			"policy apply to SSH logins as configured",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set UsePAM yes and confirm the PAM stack for sshd is present.",
		Effort:  "LOW",
		Steps: []string{
			"Confirm the PAM service file exists before enabling it: '/etc/pam.d/sshd'. Enabling UsePAM without it will refuse every login.",
			"Set 'UsePAM yes' in /etc/ssh/sshd_config.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd', keeping the current session open until a new login is verified.",
			"Check that the policy is now actually in force: an account with an expired password should be prompted to change it at login rather than being let in.",
			"Note the interaction with SSHD-0003: with UsePAM yes, 'PasswordAuthentication no' alone does not close password login, because PAM can still accept one through keyboard-interactive. 'KbdInteractiveAuthentication no' is the other half.",
		},
		Commands: []string{
			"sshd -T | grep -i usepam",
			"ls -l /etc/pam.d/sshd",
		},
		Caution: "If /etc/pam.d/sshd is missing or broken, turning UsePAM on refuses every SSH login immediately. Verify the file exists, reload from a session you are not depending on, and keep a console or second session open.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-7"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — UsePAM", URL: "https://man.openbsd.org/sshd_config#UsePAM"},
	},
}

package auth

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// LockoutModules are the failed-attempt counters, under every name.
//
// pam_faillock is current. pam_tally2 is deprecated and removed in recent
// releases but is still what a long-lived host has, and pam_tally is older
// still. A check that looked only for the current one would report "no lockout
// is configured" on a host that has one.
var LockoutModules = []string{"pam_faillock.so", "pam_tally2.so", "pam_tally.so"}

// Check0003 tests that repeated authentication failures lock the account.
var Check0003 = catalog.Check{
	ID:     "AUTH-0003",
	Module: "AUTH",
	Title:  "Repeated authentication failures lock the account",
	Description: `Without a lockout module, a password is only as strong as the
rate at which it can be guessed, and locally, or through a service that does
not rate-limit for itself, that rate is bounded by the hardware rather than by
policy. Password quality and lockout are two halves of one control: quality
sets the size of the search space, lockout sets how much of it an attacker may
search. Neither is sufficient alone, and the second is the cheaper of the two
to add, because it costs users nothing until they mistype.

It matters most where nobody is watching. sshd counts its own failures per
connection and gives up, which makes remote brute force expensive but not
impossible. su, sudo, login on a console, and any service authenticating
through PAM without its own limiter have no such counter of their own. A
lockout module is the only thing between a stolen shell and an unlimited number
of guesses at the next account.

The module has to be in the **auth** stack to count failures, and normally also
in **account** to refuse an already-locked user. This check reports whether a
counter is configured; the thresholds are reported in the detail where they can
be read, from either the module arguments or /etc/security/faillock.conf.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"auth", "pam", "brute-force", "lockout"},
	Requires:     []fact.ID{fact.PAMID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := pamFact(fs)
		if !p.Installed {
			return notInstalled()
		}

		stacks := p.Primary(fact.PAMAuth)
		if len(stacks) == 0 {
			return noStack(p, fact.PAMAuth)
		}

		lines := fact.Find(stacks, fact.PAMAuth, LockoutModules...)

		// Positive: the rule is written. No include we failed to follow can
		// unmake one we read.
		if len(lines) > 0 {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  lines[0].Module,
				Detail:   fmt.Sprintf("%s is in the auth stack, so repeated failures are counted and the account is locked.%s", modules(lines), thresholds(p, lines)),
				Evidence: linesEvidence(p, lines),
			}
		}

		return unknownIfIncomplete(stacks, catalog.Outcome{
			Result:  finding.Fail,
			Subject: "pam_faillock.so",
			Detail: fmt.Sprintf(
				"No failed-attempt counter is in the auth stack (%s), so an account may be guessed at without limit. sshd counts failures per connection and gives up, which makes remote brute force expensive; su, sudo and console login have no counter of their own, so an attacker who already has a shell may guess at the next account as fast as the hardware allows.",
				stackNames(stacks)),
			Evidence: stackEvidence(stacks),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Add pam_faillock.so to the auth and account stacks and set the threshold in /etc/security/faillock.conf.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Use the distribution's mechanism rather than editing the shared stack by hand. Red Hat: 'authselect enable-feature with-faillock'. Debian and Ubuntu: 'pam-auth-update' offers it, and the change survives a package update.",
			"Where you edit directly, faillock needs three rules and the order is the whole of it: 'auth required pam_faillock.so preauth' before pam_unix.so, 'auth [default=die] pam_faillock.so authfail' immediately after it, and 'account required pam_faillock.so' in the account stack. Only the preauth line is not enough, nothing then records the failure.",
			"Set the thresholds in /etc/security/faillock.conf, not as module arguments: 'deny = 5', 'unlock_time = 900', 'fail_interval = 900'. The file is read by every faillock rule and survives a stack regeneration.",
			"Decide deliberately whether root is included. 'even_deny_root' locks root out too, which is correct on a host with console access and a way to boot single-user, and is a self-inflicted outage on a cloud instance with neither.",
			"Prefer a finite unlock_time to a permanent lock. A permanent lock converts a guessing attempt into a denial of service: anyone who knows a username can lock it out on purpose, repeatedly, and the recovery needs an administrator every time.",
			"Test from a second session with a throwaway account: fail the threshold, confirm the lock, then 'faillock --user testuser --reset'.",
		},
		Commands: []string{
			"grep -E 'pam_faillock|pam_tally' /etc/pam.d/*",
			"grep -Ev '^\\s*(#|$)' /etc/security/faillock.conf",
			"faillock --user someuser",
		},
		Caution: "A lockout policy with no unlock_time turns a brute-force attempt into a denial of service that anybody can trigger against any account whose name they know. Setting even_deny_root on a host with no console and no single-user boot can lock you out permanently. Keep a root session open, test with a throwaway account, and know how you would reach the machine if the test went wrong.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-7"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
	},

	References: []finding.Reference{
		{Title: "pam_faillock(8)", URL: "https://man7.org/linux/man-pages/man8/pam_faillock.8.html"},
		{Title: "faillock.conf(5)", URL: "https://man7.org/linux/man-pages/man5/faillock.conf.5.html"},
	},
}

// thresholds reports the lockout parameters where they can be read, from
// either the module arguments or /etc/security/faillock.conf.
//
// They are reported rather than judged. Whether five failures or ten is right
// depends on who uses the host and how they reach it, and a verdict on the
// number would fire on defensible configurations far more often than on
// dangerous ones.
func thresholds(p fact.PAM, lines []fact.PAMLine) string {
	deny, denyFrom, haveDeny := effectiveInt(lines, p.Faillock, "deny")
	unlock, unlockFrom, haveUnlock := effectiveInt(lines, p.Faillock, "unlock_time")

	switch {
	case haveDeny && haveUnlock && unlock == 0:
		return fmt.Sprintf(" The account locks after %d failures (%s) and stays locked until an administrator resets it (unlock_time = 0, %s) — which means anyone who knows a username can lock it out on purpose.",
			deny, denyFrom, unlockFrom)
	case haveDeny && haveUnlock:
		return fmt.Sprintf(" The account locks after %d failures (%s) for %d seconds (%s).", deny, denyFrom, unlock, unlockFrom)
	case haveDeny:
		return fmt.Sprintf(" The account locks after %d failures (%s); no unlock_time was found, so how long it stays locked comes from the module's own default.", deny, denyFrom)
	default:
		return " The threshold is set neither on the PAM line nor in /etc/security/faillock.conf, so how many failures it takes comes from the module's own default rather than from anything written on this host."
	}
}

package auth

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// MinRemembered is the number of previous passwords that must be refused.
//
// Five is CIS's and DISA's number. See the check's description for why this is
// LOW severity despite being a hardening-benchmark requirement: NIST SP 800-63B
// argues against the control that makes it necessary.
const MinRemembered = 5

// HistoryModules are the modules that keep previous password hashes.
//
// pam_pwhistory is the dedicated one. pam_unix takes the same 'remember'
// argument and keeps the history itself, which is what Red Hat's stack has
// historically used, so a check looking only for pam_pwhistory would report no
// history on a host that has one.
var HistoryModules = []string{"pam_pwhistory.so", "pam_unix.so"}

// Check0006 tests that a password cannot be immediately reused.
var Check0006 = catalog.Check{
	ID:     "AUTH-0006",
	Module: "AUTH",
	Title:  "Recent passwords cannot be reused",
	Description: `Password history exists to make expiry mean something. Where a
host requires a change every ninety days and remembers nothing, the ordinary
response is to change the password to the same one — or to cycle two — and the
expiry policy becomes a recurring inconvenience that produces no security at
all. Worse, it produces the predictable variants an attacker's rule engine
generates first: the same word with an incrementing digit is the single most
common pattern in every leaked corpus.

It matters most after a compromise. When a credential is known to have leaked
and every affected account is forced to change, history is what stops the
change being a no-op. Without it, the account most likely to be reset to its
previous password is exactly the one whose previous password an attacker
already has.

**This check is LOW severity on purpose, and the reason is a genuine
disagreement rather than a hedge.** CIS and DISA require remembering at least
five. NIST SP 800-63B recommends against routine expiry altogether — arguing
that forced rotation drives users toward predictable transformations and that
passwords should be changed on evidence of compromise rather than on a
calendar — and history is a control that mainly exists to prop up rotation. On
a host that does not expire passwords, history is close to redundant. The
finding is reported so the decision is visible, at a severity that says it is
not the thing to fix first.

USERS-0009 reports whether passwords expire at all, and carries the other half
of the same disagreement.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"auth", "pam", "password", "history"},
	Requires:     []fact.ID{fact.PAMID},
	SinceCatalog: 10,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := pamFact(fs)
		if !p.Installed {
			return notInstalled()
		}

		stacks := p.Primary(fact.PAMPassword)
		if len(stacks) == 0 {
			return noStack(p, fact.PAMPassword)
		}

		lines := fact.Find(stacks, fact.PAMPassword, HistoryModules...)

		best, from, found := 0, "", false
		for _, l := range lines {
			n, ok := l.IntArg("remember")
			if !ok {
				continue
			}
			if !found || n > best {
				best, from, found = n, fmt.Sprintf("%s:%d", l.File, l.Line), true
			}
		}

		switch {
		case found && best >= MinRemembered:
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  "pam_pwhistory.so",
				Detail:   fmt.Sprintf("The last %d passwords are remembered and refused (remember=%d at %s), so a forced change cannot be satisfied by reusing the password that was being replaced.", best, best, from),
				Evidence: linesEvidence(p, lines),
			}

		// Positive: we read the value and it is too small.
		case found:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "pam_pwhistory.so",
				Detail: fmt.Sprintf(
					"Only the last %d password%s remembered (remember=%d at %s); CIS and DISA ask for at least %d. A short history is satisfied by cycling a small set of passwords, which is what it is meant to prevent. NIST SP 800-63B would not require this control at all, arguing that routine expiry — which history exists to support — pushes users toward predictable variants; the finding is LOW for that reason.",
					best, plural(best, " is", "s are"), best, from, MinRemembered),
				Evidence: linesEvidence(p, lines),
			}

		default:
			return unknownIfIncomplete(stacks, catalog.Outcome{
				Result:  finding.Fail,
				Subject: "pam_pwhistory.so",
				Detail: fmt.Sprintf(
					"No password history is kept: neither pam_pwhistory.so nor pam_unix.so carries a 'remember' argument in the password stack (%s). A user required to change their password may set it to the one they are replacing, which makes an expiry policy a recurring inconvenience that produces no security, and makes a post-compromise forced reset a no-op for exactly the account whose old password is already known. NIST SP 800-63B would not require this control; CIS and DISA do, and the finding is LOW because of that disagreement.",
					stackNames(stacks)),
				Evidence: stackEvidence(stacks),
			})
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Add pam_pwhistory.so with remember=5 to the password stack, above pam_unix.so.",
		Effort:  "LOW",
		Steps: []string{
			"Decide whether you want this control at all before adding it. It exists to support routine password expiry; if this host does not expire passwords — which is what NIST SP 800-63B recommends — then history adds little, and suppressing the finding with that reasoning recorded is a legitimate answer.",
			"Where you do want it, add it through the distribution's mechanism: 'authselect' on Red Hat, 'pam-auth-update' on Debian, so the change survives a stack regeneration.",
			"Editing directly, the rule goes *above* pam_unix.so in the password stack: 'password required pam_pwhistory.so remember=5 use_authtok'. Below pam_unix.so it never runs, because the password has already been set.",
			"Alternatively add 'remember=5' to the existing pam_unix.so password rule, which keeps the history itself. Do one or the other rather than both — two modules keeping overlapping history is confusing to reason about and gains nothing.",
			"Know where the history lives: /etc/security/opasswd. It holds previous password *hashes* and needs the same protection as /etc/shadow — mode 0600, owned by root. A world-readable opasswd hands an attacker every password the user has ever had, which is a larger prize than the current one.",
			"Test with a throwaway account: change its password, then try to change it back. The second attempt must be refused.",
		},
		Commands: []string{
			"grep -E 'pam_pwhistory|remember=' /etc/pam.d/*",
			"ls -l /etc/security/opasswd",
			"authselect current",
		},
		Caution: "/etc/security/opasswd holds previous password hashes and is created by the module the first time a password changes. If it ends up world-readable, this control has handed an attacker every password each user has had rather than only the current one — check its mode after enabling it, not before.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
	},

	References: []finding.Reference{
		{Title: "pam_pwhistory(8)", URL: "https://man7.org/linux/man-pages/man8/pam_pwhistory.8.html"},
		{Title: "NIST SP 800-63B §5.1.1.2 — against routine expiry", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"},
	},
}

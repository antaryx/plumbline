package users

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0010 tests the fourth field of /etc/shadow: how soon after changing a
// password it may be changed again.
//
// It reports two distinct conditions. A minimum of zero makes password history
// bypassable; a minimum greater than the maximum makes the account
// unrecoverable without administrator intervention, which is an availability
// failure rather than a policy one and is reported at a higher severity.
var Check0010 = catalog.Check{
	ID:     "USERS-0010",
	Module: "USERS",
	Title:  "Passwords that can authenticate have a minimum age set",
	Description: `The fourth field of /etc/shadow is the number of days that
must pass before a password may be changed again. Its purpose is narrow and
frequently misunderstood: it is what makes password history mean anything. With
a minimum of zero, a user told to choose a new password can run 'passwd' as
many times as the history depth and arrive back at the password they started
with, in one sitting, without any policy having been violated. A minimum of one
day makes that cost a day per cycle, which is enough to make it pointless.

This matters only where password history is actually enforced — pam_pwhistory
or pam_unix's "remember" option. Where no history is configured there is
nothing to cycle through and the minimum protects nothing, which is why this
ships at LOW severity. Plumbline does not yet collect the PAM stack, so it
cannot tell which case this host is in; that fact belongs to the AUTH module.

A separate and more serious condition is a minimum greater than the maximum.
Such an account is locked out by construction: the password expires and demands
a change, and passwd refuses the change because the minimum has not elapsed.
The user cannot recover without an administrator, and nothing in the login
message explains why. That is reported at MEDIUM.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"users", "credentials", "password-policy"},
	Requires:     []fact.ID{fact.ShadowID, fact.PasswdID},
	SinceCatalog: 5,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := shadowFact(fs)
		p := passwdFact(fs)

		accounts := authenticating(s)
		if len(accounts) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No account in %s can authenticate with a password — every entry is locked, empty or without a stored hash — so there is no password change interval to govern.",
					s.Path),
			}
		}

		var (
			noMinimum []string
			lockedOut []string
			subjects  []string
			evidence  []finding.Evidence
		)
		for _, e := range accounts {
			// The lockout condition is strict inequality on purpose. With
			// min == max the change is permitted on exactly the day the
			// password expires, which is tight but works; only min > max
			// leaves a window in which the account must change its password
			// and cannot.
			if e.MinDays != nil && e.MaxDays != nil && *e.MinDays > *e.MaxDays {
				lockedOut = append(lockedOut, fmt.Sprintf(
					"%s (minimum %d days, maximum %d)", e.Name, *e.MinDays, *e.MaxDays))
				subjects = append(subjects, e.Name)
				evidence = append(evidence, shadowEntryEvidence(s, e, fmt.Sprintf(
					"minimum age %d exceeds maximum age %d (fields 4 and 5)", *e.MinDays, *e.MaxDays)))
				continue
			}
			if e.MinDays == nil || *e.MinDays < 1 {
				noMinimum = append(noMinimum, fmt.Sprintf("%s (%s)", e.Name, agingValue(e.MinDays)))
				subjects = append(subjects, e.Name)
				evidence = append(evidence, shadowEntryEvidence(s, e,
					fmt.Sprintf("minimum age %s (field 4)", agingValue(e.MinDays))))
			}
		}

		if len(lockedOut) > 0 || len(noMinimum) > 0 {
			var parts []string
			if len(lockedOut) > 0 {
				parts = append(parts, fmt.Sprintf(
					"%d account(s) have a minimum age greater than their maximum and are locked out by construction — the password expires and passwd refuses to change it: %s",
					len(lockedOut), joinNames(lockedOut)))
			}
			if len(noMinimum) > 0 {
				parts = append(parts, fmt.Sprintf(
					"%d account(s) have no minimum age, so a user required to change their password can cycle through the history and return to the original in a single sitting: %s",
					len(noMinimum), joinNames(noMinimum)))
			}

			severity := finding.Severity("")
			if len(lockedOut) > 0 {
				// An account that cannot change an expired password is an
				// availability failure, not a policy preference, and it is not
				// contingent on whether password history is configured.
				severity = finding.Medium
			}

			return catalog.Outcome{
				Result:   finding.Fail,
				Severity: severity,
				Subject:  joinNames(subjects),
				Detail: fmt.Sprintf(
					"Of the %d account(s) in %s that can authenticate: %s.",
					// The lockout clause comes first because it is the more
					// serious of the two; sorting would put it wherever its
					// first character fell.
					len(accounts), s.Path, strings.Join(parts, "; ")),
				Evidence: evidence,
			}
		}

		return unknownIfShadowIncomplete(p, s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d account(s) in %s that can authenticate have a minimum password age of at least one day, and none has a minimum greater than its maximum.",
				len(accounts), s.Path),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Set a minimum age of at least one day, and never above the maximum.",
		Effort:  "LOW",
		Steps: []string{
			"Inspect the account: 'chage -l <name>' reports both the minimum and the maximum together, which is the pair that matters.",
			"Set a minimum: 'chage -m 1 <name>'.",
			"Where the minimum exceeds the maximum, fix that first — the account cannot change its own password until you do. 'chage -m 1 -M 365 <name>' sets both in one command.",
			"To change the default for accounts created from now on, set PASS_MIN_DAYS in /etc/login.defs. Existing accounts are unaffected.",
			"The minimum only has an effect where password history is enforced. Confirm that pam_pwhistory or pam_unix's 'remember' option is configured, or the setting protects nothing.",
		},
		Commands: []string{
			"chage -l <name>",
			"awk -F: '$2 !~ /^[!*]/ && $2 != \"\" {print $1, $4, $5}' /etc/shadow",
		},
		Caution: "Do not set a minimum age on an account whose password may need to be rotated urgently — an incident response that has to change a credential twice in one day will be refused by passwd, and the account will have to be edited by an administrator instead.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
	},

	References: []finding.Reference{
		{Title: "chage(1)", URL: "https://man7.org/linux/man-pages/man1/chage.1.html"},
		{Title: "pam_pwhistory(8)", URL: "https://man7.org/linux/man-pages/man8/pam_pwhistory.8.html"},
	},
}

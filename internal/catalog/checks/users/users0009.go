package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0009 tests that every account that can authenticate has a bounded
// password lifetime.
//
// It ships at LOW severity on purpose. Current guidance does not agree that
// this control is desirable at all — NIST SP 800-63B tells verifiers not to
// impose periodic rotation, while CIS and the DISA STIGs require it — and a
// check whose premise is contested should not be shouting. The finding says
// what the file contains and names the disagreement, so a reader can decide
// which framework they are being measured against rather than inheriting this
// project's opinion by accident.
var Check0009 = catalog.Check{
	ID:     "USERS-0009",
	Module: "USERS",
	Title:  "Passwords that can authenticate have a bounded maximum age",
	Description: `The fifth field of /etc/shadow is the number of days a
password may be kept before the system requires a new one. shadow-utils writes
99999 into it by default, which is a little over 273 years and means the
password never expires; an empty field means the same thing more explicitly.

**The frameworks disagree about whether this control should exist.** NIST SP
800-63B §5.1.1.2 states that verifiers SHOULD NOT require periodic password
changes, on the evidence that forced rotation produces predictable
transformations of one password rather than genuinely new ones, and should
instead force a change only on evidence of compromise. CIS Benchmarks require a
maximum of 365 days, and the DISA STIGs require 60. All three positions are
current and none of them is a misreading of the others.

Plumbline reports the setting at LOW severity against the CIS threshold,
because that is the number most audits are run against, and states the conflict
in the finding rather than resolving it. An organisation following NIST's
position should suppress this check deliberately, which is a decision with a
record, rather than have the tool make it for them silently.

Only accounts that can actually authenticate are considered. A locked or
password-less account has no lifetime to bound, and the dozen such accounts
every distribution ships would otherwise dominate the result.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"users", "credentials", "password-policy"},
	Requires:     []fact.ID{fact.ShadowID, fact.PasswdID},
	SinceCatalog: 5,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := shadowFact(fs)
		p := passwdFact(fs)

		accounts := authenticating(s)
		if len(accounts) == 0 {
			// Genuinely not applicable rather than merely uninteresting: there
			// is no account on this host whose password could expire.
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No account in %s can authenticate with a password — every entry is locked, empty or without a stored hash — so there is no password lifetime to bound.",
					s.Path),
			}
		}

		var (
			unbounded []string
			subjects  []string
			evidence  []finding.Evidence
		)
		for _, e := range accounts {
			if e.MaxDays != nil && *e.MaxDays <= MaxPasswordAgeDays {
				continue
			}
			what := "the maximum age field is empty, so the password never expires"
			if e.MaxDays != nil {
				what = fmt.Sprintf("maximum age is %d days", *e.MaxDays)
				if *e.MaxDays >= 99999 {
					what += ", which is shadow-utils' default and means the password never expires"
				}
			}
			unbounded = append(unbounded, fmt.Sprintf("%s (%s)", e.Name, what))
			subjects = append(subjects, e.Name)
			evidence = append(evidence, shadowEntryEvidence(s, e,
				fmt.Sprintf("maximum age %s (field 5)", agingValue(e.MaxDays))))
		}

		if len(unbounded) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: joinNames(subjects),
				Detail: fmt.Sprintf(
					"%d of the %d account(s) in %s that can authenticate have no bounded password lifetime: %s. The threshold applied is %d days, which is the CIS Benchmark figure; NIST SP 800-63B takes the opposite position and advises against forced rotation entirely, so an organisation following NIST should suppress this check rather than treat the finding as a defect.",
					len(unbounded), len(accounts), s.Path, joinNames(unbounded), MaxPasswordAgeDays),
				Evidence: evidence,
			}
		}

		return unknownIfShadowIncomplete(p, s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d account(s) in %s that can authenticate have a maximum password age of %d days or fewer. Note that NIST SP 800-63B advises against forced rotation, so this PASS reflects the CIS position rather than a universally agreed control.",
				len(accounts), s.Path, MaxPasswordAgeDays),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Decide which framework applies, then set a maximum age or suppress this check deliberately.",
		Effort:  "LOW",
		Steps: []string{
			"Decide first whether you intend to enforce rotation at all. If the organisation follows NIST SP 800-63B, the correct action is to suppress USERS-0009 in the suppression file with a reason, not to change the setting.",
			"To see the current state of an account: 'chage -l <name>'.",
			"To set a maximum on one account: 'chage -M 365 <name>'.",
			"To change the default applied to accounts created from now on, set PASS_MAX_DAYS in /etc/login.defs. That does not alter existing accounts.",
			"Confirm the change: 'chage -l <name>' reports the new maximum and the resulting expiry date.",
		},
		Commands: []string{
			"chage -l <name>",
			"awk -F: '$2 !~ /^[!*]/ && $2 != \"\" {print $1, $5}' /etc/shadow",
		},
		Caution: "Setting a maximum age shorter than the time already elapsed since the password was last changed expires it immediately, and the account will be forced to change its password at its next login. On a service account that authenticates non-interactively, that means it stops working with no interactive prompt to reveal why.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
	},

	References: []finding.Reference{
		{Title: "chage(1)", URL: "https://man7.org/linux/man-pages/man1/chage.1.html"},
		{Title: "shadow(5)", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"},
		{Title: "NIST SP 800-63B, Authentication and Lifecycle Management", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"},
	},
}

package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/catalog/checks/logindefs"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// PassMinDaysKey is the login.defs directive that sets the default minimum age.
const PassMinDaysKey = "PASS_MIN_DAYS"

// Check0012 tests the shadow suite's default minimum password age.
//
// **It is the persistence half of USERS-0010, not a second opinion on it.**
// USERS-0010 reads /etc/shadow and reports what each existing account has;
// this reads /etc/login.defs and reports what the *next* account will get. A
// host where every current account has a minimum age of one and login.defs
// says zero passes USERS-0010 and creates its next user with no minimum at all
// — which is a real and common state, because the accounts were fixed by hand
// and the default never was.
//
// The catalog already draws this line elsewhere: KERNEL-0004 asks what the
// running kernel does and KERNEL-0019 asks what the files say. Same shape, same
// reason — a host that has done one and not the other should see one finding.
var Check0012 = catalog.Check{
	ID:     "USERS-0012",
	Module: "USERS",
	Title:  "The default minimum password age is at least one day",

	Description: `A minimum password age is the setting that makes a password
history mean anything.

Password history, "you may not reuse your last five passwords", is enforced
by pam_pwhistory or pam_unix's remember=. Without a minimum age it costs an
determined user about thirty seconds to defeat: change the password five times
in a row, then change it back to the one they started with. The history is
full, every rule was satisfied at every step, and the password is the one the
policy was trying to retire.

PASS_MIN_DAYS is what stops that. At 1 the same manoeuvre takes five days and
stops being something somebody does while their coffee is brewing.

**It is a default for accounts created from now on, not a policy over the ones
that exist.** useradd reads it when it makes an account; chage writes the value
into /etc/shadow's fifth field, which is what actually governs an existing
account and what USERS-0010 reads. Setting this fixes the next user and none of
the current ones.

**Zero is not "unset".** A host with no PASS_MIN_DAYS line and a host with
PASS_MIN_DAYS 0 behave identically, the shadow suite's own default is zero,
but they are different findings to an operator, because one is a decision and
the other is an omission. The check reports both and names which it saw.`,

	// Low. It is a real weakness and it is not one an attacker reaches for:
	// it needs an account whose password is already known to somebody who
	// wants to keep it. Rating it level with the checks about how a password
	// is hashed or whether an empty one is accepted would put a housekeeping
	// finding in the same list as an unauthenticated login.
	BaseSeverity: finding.Low,
	Tags:         []string{"users", "password-policy", "login.defs", "persistence"},
	Requires:     []fact.ID{fact.LoginDefsID},
	SinceCatalog: 34,

	Eval: func(fs *fact.Set) catalog.Outcome {
		l, _, _ := fact.Get[fact.LoginDefs](fs, fact.LoginDefsID)

		switch l.State {
		case fact.SourceAbsent:
			// Alpine's busybox shadow tools do not read login.defs, and a
			// minimal image frequently has no shadow suite at all. There is
			// no default to report on, and USERS-0010 still covers the
			// accounts that exist.
			return catalog.Outcome{
				Result:  finding.NotApplicable,
				Subject: l.Path,
				Detail: "This host has no /etc/login.defs, so the shadow suite has no configured default " +
					"minimum password age to report. USERS-0010 covers what the accounts that exist are set to.",
			}
		case fact.SourceDenied:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Subject:       l.Path,
				Detail:        "/etc/login.defs could not be read (" + l.Msg + "), so the default minimum password age is unknown.",
				Evidence:      []finding.Evidence{finding.NewEvidence(l.Path, 0, l.Msg, "")},
			}
		case fact.SourceError:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Subject:       l.Path,
				Detail:        "/etc/login.defs could not be interpreted: " + l.Msg,
				Evidence:      []finding.Evidence{finding.NewEvidence(l.Path, 0, l.Msg, "")},
			}
		}

		days, set, ok := l.Int(PassMinDaysKey)
		if !ok {
			if _, present := l.Effective(PassMinDaysKey); present {
				// Set to something that is not a number. shadow(3) would
				// reject it too, but what it falls back to is the library's
				// business and not observable from the file.
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonParse,
					Subject:       PassMinDaysKey,
					Detail: fmt.Sprintf(
						"%s is set to %q in /etc/login.defs (line %d), which is not a number of days. "+
							"What the shadow suite does with it is the library's business and is not readable "+
							"from this file, so the effective default could not be established.",
						PassMinDaysKey, set.Value, set.Line),
					Evidence: []finding.Evidence{logindefs.Evidence(l, set)},
				}
			}

			// Absent. Identical in behaviour to zero and different as a
			// finding: one is an omission, the other a decision.
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: PassMinDaysKey,
				Detail: fmt.Sprintf(
					"/etc/login.defs sets no %s, so the shadow suite's own default of 0 applies and every "+
						"account created from now on may have its password changed twice in the same second. "+
						"A password history is then defeated by cycling through it and back, which takes about "+
						"thirty seconds. This is the default for new accounts; USERS-0010 reports what the "+
						"accounts that already exist are set to.%s",
					PassMinDaysKey, minAgeCaveat),
				Evidence: []finding.Evidence{finding.NewEvidence(l.Path, 0, "no "+PassMinDaysKey+" line", l.Digest)},
			}
		}

		if days >= 1 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: PassMinDaysKey,
				Detail: fmt.Sprintf(
					"%s is %d in /etc/login.defs (line %d), so an account created from now on cannot have its "+
						"password changed again for %s. Cycling through a password history to arrive back at "+
						"the original takes that many days per step rather than seconds.%s%s",
					PassMinDaysKey, days, set.Line, dayCount(days),
					logindefs.ShadowedNote(l, PassMinDaysKey), minAgeCaveat),
				Evidence: []finding.Evidence{logindefs.Evidence(l, set)},
			}
		}

		// Positive: we read the value. Nothing unread can unmake it.
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: PassMinDaysKey,
			Detail: fmt.Sprintf(
				"%s is %d in /etc/login.defs (line %d), so an account created from now on may have its "+
					"password changed twice in the same second. A password history — pam_pwhistory, or "+
					"pam_unix's remember= — is then defeated by changing the password as many times as the "+
					"history is deep and then changing it back, which takes about thirty seconds. This is the "+
					"default for new accounts; USERS-0010 reports what the accounts that already exist are "+
					"set to.%s%s",
				PassMinDaysKey, days, set.Line,
				logindefs.ShadowedNote(l, PassMinDaysKey), minAgeCaveat),
			Evidence: []finding.Evidence{logindefs.Evidence(l, set)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set PASS_MIN_DAYS to 1 in /etc/login.defs, and apply it to the accounts that already exist.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'PASS_MIN_DAYS 1' in /etc/login.defs. Edit the first occurrence rather than appending: the shadow suite reads the first match and ignores every later one, so a line added at the end of a file that already sets the key has no effect at all.",
			"That is the default for accounts created afterwards. Existing accounts keep whatever is in /etc/shadow's fifth field: 'chage --mindays 1 <user>' sets one, and USERS-0010 is the check that reports them.",
			"A minimum age is only worth setting if a password history is enforced, otherwise it inconveniences users and stops nothing. Check for pam_pwhistory or remember= on the pam_unix.so password line.",
			"Consider who is affected. A minimum age applies to the user changing their own password, not to root using 'passwd <user>', so a helpdesk reset still works. A user who mistypes a new password into a system that accepted it, though, cannot change it again until the minimum has passed.",
		},
		Commands: []string{
			"grep -n PASS_MIN_DAYS /etc/login.defs",
			"chage --list <user>",
		},
		Caution: "A minimum password age stops a user changing their password again for that many days, including immediately after a change they regret, a mistyped passphrase they did not notice, or one they have already written down somewhere they should not have. Root can still reset it with 'passwd <user>', which is the escape hatch, and an operator setting this should know that is the only one.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
	},

	References: []finding.Reference{
		{Title: "login.defs(5)", URL: "https://man7.org/linux/man-pages/man5/login.defs.5.html"},
		{Title: "chage(1)", URL: "https://man7.org/linux/man-pages/man1/chage.1.html"},
	},
}

// minAgeCaveat is appended to every verdict this check draws.
const minAgeCaveat = " A minimum age is only worth having where a password history is enforced; without one it " +
	"delays a change and prevents nothing."

func dayCount(n int) string {
	if n == 1 {
		return "a day"
	}
	return fmt.Sprintf("%d days", n)
}

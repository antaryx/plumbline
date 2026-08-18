package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests that no account authenticates with an empty password.
//
// It requires users.shadow first and users.passwd second, and the order is
// deliberate: the runner's required-fact gate reports the first unavailable
// fact, and on an unprivileged scan the interesting answer is "shadow was
// unreadable", not "we could not proceed".
var Check0003 = catalog.Check{
	ID:     "USERS-0003",
	Module: "USERS",
	Title:  "No account has an empty password",
	Description: `An empty password field in /etc/shadow means the account
authenticates with no password at all. Wherever the PAM stack consults shadow —
console login, su, and any service configured to use it — pressing return is
sufficient.

This is not a theoretical state. It is produced by 'passwd -d', by automated
provisioning that intended to set a password later, and by restoring a partial
backup. It is distinct from a locked account: a lock token means no password
can ever match, which is safe, while an empty field means every password
matches, which is the opposite.`,

	BaseSeverity: finding.Critical,
	Tags:         []string{"users", "authentication", "credentials"},
	Requires:     []fact.ID{fact.ShadowID, fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := shadowFact(fs)
		p := passwdFact(fs)

		var (
			empty    []string
			evidence []finding.Evidence
		)
		for _, e := range s.Entries {
			if !e.Empty {
				continue
			}
			empty = append(empty, e.Name)
			evidence = append(evidence, shadowEntryEvidence(s, e,
				"password field is empty; authentication succeeds with no password"))
		}

		if len(empty) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: joinNames(empty),
				Detail: fmt.Sprintf(
					"%d account(s) have an empty password field in %s and authenticate with no password: %s. This is not the same as a locked account — a lock refuses every password, an empty field accepts every password.",
					len(empty), s.Path, joinNames(empty)),
				Evidence: evidence,
			}
		}

		if len(s.Entries) == 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"%s contains no entries. A host with local accounts has some, so either passwords are supplied by a directory service this check cannot see or the file is not what it appears to be.",
					s.Path),
				Evidence: []finding.Evidence{finding.NewEvidence(s.Path, 0, "no entries", "")},
			}
		}

		return unknownIfShadowIncomplete(p, s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"None of the %d account(s) in %s has an empty password field.",
				len(s.Entries), s.Path),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Set a password on the account, or lock it if it should not authenticate.",
		Effort:  "LOW",
		Steps: []string{
			"Decide which the account should be. An account that a person uses needs a password; an account that only owns files or runs a daemon needs a lock.",
			"To lock it so no password can ever match: 'passwd -l <name>'. This is the right answer for a service account.",
			"To set a password: 'passwd <name>'. Do not leave it until later — the state you are fixing is what 'later' looks like.",
			"Verify: 'passwd -S <name>' reports 'L' for locked, 'P' for a usable password, and 'NP' for no password.",
			"Check whether the account was used while it was open: 'lastlog -u <name>' and 'last <name>'.",
		},
		Commands: []string{
			"passwd -S <name>",
			"passwd -l <name>",
		},
		Caution: "Locking an account that a service authenticates as will stop that service. Confirm what uses the account first; locking root in particular can leave a host with no console recovery path.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
	},

	References: []finding.Reference{
		{Title: "shadow(5)", URL: "https://man7.org/linux/man-pages/man5/shadow.5.html"},
	},
}

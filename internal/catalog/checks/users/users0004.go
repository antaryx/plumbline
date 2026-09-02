package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests that stored password hashes use a modern algorithm.
var Check0004 = catalog.Check{
	ID:     "USERS-0004",
	Module: "USERS",
	Title:  "Password hashes use a modern algorithm",
	Description: `A password hash is only as good as the work it costs to test a
guess. The old schemes cost almost nothing on modern hardware: DES crypt
considers only the first eight characters of a password and falls to
exhaustive search in minutes, and MD5-crypt runs at billions of guesses per
second on a commodity GPU. A file full of those hashes is a list of passwords
with a short delay attached.

SHA-512 and yescrypt are the schemes current distributions ship. yescrypt is
memory-hard, which is what makes GPU and ASIC attacks expensive rather than
merely slower.

Changing the system's hashing scheme does not rewrite existing hashes. Each
account keeps whatever it was hashed with until its password is next changed,
so a host that switched years ago can still be carrying MD5 hashes for accounts
nobody has touched, which are exactly the accounts nobody is watching.`,

	BaseSeverity: finding.High,
	Tags:         []string{"users", "authentication", "credentials", "cryptography"},
	Requires:     []fact.ID{fact.ShadowID, fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := shadowFact(fs)
		p := passwdFact(fs)

		var (
			weak       []string
			unknownAlg []string
			evidence   []finding.Evidence
			hashed     int
		)
		for _, e := range s.Entries {
			switch {
			case e.Algorithm == fact.HashNone:
				// No hash at all: the account is locked, or has an empty
				// password. Neither is this check's question — USERS-0003
				// covers the empty case — and counting a locked account as a
				// weak hash would report a safe state as a failure.
				continue

			case e.Algorithm.Weak():
				hashed++
				weak = append(weak, fmt.Sprintf("%s (%s)", e.Name, e.Algorithm))
				evidence = append(evidence, shadowEntryEvidence(s, e,
					fmt.Sprintf("password hashed with %s", e.Algorithm)))

			case e.Algorithm.Strong():
				hashed++

			default:
				// Structured like a hash, scheme not recognised. This is
				// neither weak nor strong, and saying either would be an
				// invention: a newer scheme this build predates looks exactly
				// like a corrupted field.
				hashed++
				unknownAlg = append(unknownAlg, e.Name)
				evidence = append(evidence, shadowEntryEvidence(s, e,
					"password hash uses an unrecognised scheme"))
			}
		}

		// A weak hash we found is a weak hash, whatever else is unresolved.
		if len(weak) > 0 {
			detail := fmt.Sprintf(
				"%d account(s) have passwords hashed with an algorithm that no longer provides meaningful resistance to offline cracking: %s. Changing the system's hashing scheme does not rewrite an existing hash; each of these keeps its current scheme until that account's password is next changed.",
				len(weak), joinNames(weak))
			if len(unknownAlg) > 0 {
				detail += fmt.Sprintf(
					" A further %d account(s) use a scheme this build does not recognise: %s.",
					len(unknownAlg), joinNames(unknownAlg))
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  joinNames(weak),
				Detail:   detail,
				Evidence: evidence,
			}
		}

		if len(unknownAlg) > 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       joinNames(unknownAlg),
				Detail: fmt.Sprintf(
					"%d account(s) have a password hash whose scheme identifier this build does not recognise: %s. It may be a scheme newer than this release or a corrupted field; either way its strength cannot be judged.",
					len(unknownAlg), joinNames(unknownAlg)),
				Evidence: evidence,
			}
		}

		if hashed == 0 {
			// Every account is locked or has no password. There is no stored
			// hash whose algorithm could be judged.
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"No account in %s stores a password hash; every entry is locked or has no password, so there is no hashing algorithm in use to assess.",
					s.Path),
			}
		}

		return unknownIfShadowIncomplete(p, s, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d stored password hash(es) use a modern algorithm.", hashed),
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Change the affected passwords so they are re-hashed with the system's current scheme.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Confirm the system default is modern: ENCRYPT_METHOD in /etc/login.defs should be SHA512 or YESCRYPT, and the pam_unix line in the PAM stack should not override it.",
			"A hash is only rewritten when the password changes, so each affected account must set a new password: 'passwd <name>', or 'chage -d 0 <name>' to force the change at next login.",
			"For an account nobody logs into, the right answer is usually to lock it instead: 'passwd -l <name>'.",
			"Re-run the audit and confirm the scheme has changed.",
		},
		Commands: []string{
			"grep ENCRYPT_METHOD /etc/login.defs",
			"chage -d 0 <name>",
		},
		Caution: "'chage -d 0' forces a password change at the account's next login. Applied to a service account that logs in non-interactively, it will lock that service out silently at its next authentication.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-5(1)"},
		{Framework: "nist-800-53-r5", Control: "SC-13"},
	},

	References: []finding.Reference{
		{Title: "crypt(5), password hashing methods", URL: "https://man7.org/linux/man-pages/man5/crypt.5.html"},
	},
}

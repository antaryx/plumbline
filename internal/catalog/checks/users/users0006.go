package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0006 tests that the account database contains no legacy directory
// import entries.
var Check0006 = catalog.Check{
	ID:     "USERS-0006",
	Module: "USERS",
	Title:  "The account database contains no legacy NIS import entries",
	Description: `A line in /etc/passwd whose first field begins with "+" is NIS
compatibility syntax: it tells glibc to pull accounts from a directory service
and merge them into the local database. A bare "+::::::" imports every account
NIS offers, with whatever uid, shell and group the directory says — including,
if the directory is compromised or spoofed, uid 0.

NIS transmits its maps without authentication or encryption and its successor,
NIS+, was withdrawn. Where a host genuinely needs directory accounts, that is
what nsswitch.conf and SSSD are for; a "+" line is a mechanism from an era when
the network was assumed to be trustworthy.

The entry also changes what every other check in this module can conclude. Once
accounts arrive from somewhere this scan cannot read, "no account has uid 0"
becomes a statement about a list that is explicitly not the whole list — which
is why the other USERS checks resolve to UNKNOWN when one of these is present
rather than reporting a PASS they cannot support.`,

	BaseSeverity: finding.High,
	Tags:         []string{"users", "authentication", "legacy", "attack-surface"},
	Requires:     []fact.ID{fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := passwdFact(fs)

		if len(p.CompatEntries) == 0 {
			// Through the module's gate like every other PASS here. Without
			// it, a file that is not an account database at all — an HTML
			// error page written over /etc/passwd during a failed
			// configuration-management run is the way this happens — parses
			// into zero entries and zero compat lines, and this check reports
			// that every account is defined locally. It is true of the file
			// and false of the host.
			return unknownIfIncomplete(p, catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"%s contains no NIS compatibility entries; every account it defines is defined locally.",
					p.Path),
			})
		}

		var (
			specs    []string
			evidence []finding.Evidence
		)
		for _, c := range p.CompatEntries {
			specs = append(specs, fmt.Sprintf("%q (line %d)", c.Spec, c.Line))
			evidence = append(evidence, finding.NewEvidence(p.Path, c.Line,
				c.Spec+"  (NIS compatibility entry)", p.Digest))
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: p.Path,
			Detail: fmt.Sprintf(
				"%s contains %d NIS compatibility entr(ies): %s. These import accounts from a directory service over an unauthenticated protocol, so the uid, shell and group of the accounts they add are decided off this host — and every other check over this file is limited to the accounts defined locally.",
				p.Path, len(p.CompatEntries), joinNames(specs)),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Remove the compatibility entries and configure directory accounts through nsswitch.conf.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Determine whether the host actually uses NIS: 'ypwhich' reports the bound server, and 'grep compat /etc/nsswitch.conf' shows whether the compat backend is even active.",
			"If NIS is not in use, the entries are inert leftovers and can be removed from /etc/passwd and /etc/group.",
			"If directory accounts are genuinely needed, migrate to SSSD or LDAP through nsswitch.conf, which authenticates the directory and encrypts the transport.",
			"Remove the '+' lines only after the replacement resolves accounts correctly: 'getent passwd <a directory account>' must still return an entry.",
			"Re-run the audit; the other USERS checks will produce definite verdicts once the local file is the whole list.",
		},
		Commands: []string{
			"grep -n '^[+-]' /etc/passwd /etc/group",
			"getent passwd <name>",
		},
		Caution: "Removing the entries on a host that really is using NIS will make every directory account stop resolving, which locks out everyone who is not a local user. Verify the replacement resolves accounts before removing the old mechanism, and keep a local root session open.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
	},

	References: []finding.Reference{
		{Title: "nsswitch.conf(5)", URL: "https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html"},
	},
}

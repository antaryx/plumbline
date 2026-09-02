package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests that uid 0 belongs to root and to nothing else.
var Check0001 = catalog.Check{
	ID:     "USERS-0001",
	Module: "USERS",
	Title:  "Only the root account has uid 0",
	Description: `The kernel grants privilege by uid, not by name. An account
called "backup" with uid 0 is root, it can read every file, load kernel
modules and change any password, and nothing in the shell prompt, the process
list or the audit log distinguishes it from the real thing.

A second uid 0 account is one of the quietest persistence mechanisms available
to an attacker. It survives password changes to root, it is not listed by tools
that enumerate "the root account", and on a busy host nobody reads
/etc/passwd. It is also occasionally created deliberately, by an administrator
who wanted a personal root login and did not realise sudo already provided
one with an audit trail.`,

	BaseSeverity: finding.Critical,
	Tags:         []string{"users", "privilege-escalation", "persistence"},
	Requires:     []fact.ID{fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := passwdFact(fs)

		roots := p.ByUID(0)

		// A working Unix system has an account with uid 0. When none does,
		// either this file is not the whole account database or something is
		// badly wrong; reporting PASS would be reporting the absence of a
		// violation in a list that does not contain the account it is about.
		if len(roots) == 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"No account in %s holds uid 0. A working system has one, so either the account database is incomplete or accounts are supplied by a directory service this check cannot see.",
					p.Path),
				Evidence: []finding.Evidence{finding.NewEvidence(p.Path, 0, "no uid 0 entry", p.Digest)},
			}
		}

		var (
			impostors []string
			evidence  []finding.Evidence
		)
		for _, e := range roots {
			if e.Name != "root" {
				impostors = append(impostors, e.Name)
				evidence = append(evidence, passwdEvidence(p, e))
			}
		}

		// A positive result stands whatever else is incomplete: an account we
		// read with uid 0 has uid 0, whether or not other accounts are
		// imported from elsewhere.
		if len(impostors) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: joinNames(impostors),
				Detail: fmt.Sprintf(
					"%d account(s) other than root hold uid 0: %s. The kernel makes no distinction between them and root, so each has complete control of this host and each is a separate credential an attacker may target.",
					len(impostors), joinNames(impostors)),
				Evidence: evidence,
			}
		}

		// root itself must be the uid 0 account, not merely present.
		if len(roots) == 1 && roots[0].Name == "root" {
			return unknownIfIncomplete(p, catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"uid 0 is held by the root account and by no other account in %s.", p.Path),
				Evidence: []finding.Evidence{passwdEvidence(p, roots[0])},
			})
		}

		// More than one entry named root, all with uid 0: a duplicate line.
		// glibc resolves the first, so the others are unreachable but still
		// present, and USERS-0005 reports the duplication itself.
		for _, e := range roots {
			evidence = append(evidence, passwdEvidence(p, e))
		}
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: "root",
			Detail: fmt.Sprintf(
				"uid 0 appears on %d separate lines of %s, all named root. Name resolution returns the first, so the later entries are unreachable and whatever they were meant to configure — shell, home directory — is not in force.",
				len(roots), p.Path),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Give every account other than root a unique non-zero uid, or remove it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Identify what the account is for: 'grep -R <name> /etc/cron* /etc/sudoers.d /etc/systemd' and check for running processes with 'ps -u <name>'.",
			"If it exists to give a person root access, remove it and grant that person sudo instead, which produces an audit trail attributable to them.",
			"If it is a service account that was given uid 0 by mistake, allocate a free uid, change it with 'usermod -u <newuid> <name>', then fix ownership of its files: 'find / -xdev -uid 0 -user <name>' will not work once the uid has changed, so record the file list first.",
			"If it is unexplained, treat it as a compromise indicator: check its home directory, its authorized_keys, its shell history and the last-login record before removing it.",
		},
		Commands: []string{
			"awk -F: '$3 == 0 {print $1}' /etc/passwd",
			"lastlog -u <name>",
		},
		Caution: "Changing root's own uid, or removing the account that a running service authenticates as, will break the host. Confirm what depends on the account before altering it, and keep a root session open while you do.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
		{Framework: "nist-800-53-r5", Control: "IA-2"},
	},

	References: []finding.Reference{
		{Title: "passwd(5)", URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"},
	},
}

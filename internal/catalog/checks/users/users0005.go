package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests that no uid and no account name is used twice.
var Check0005 = catalog.Check{
	ID:     "USERS-0005",
	Module: "USERS",
	Title:  "No uid or account name is used by more than one entry",
	Description: `Two accounts sharing a uid are the same account as far as the
kernel is concerned. They can read each other's files, signal each other's
processes and inherit each other's group memberships, while appearing in every
listing as two separate identities — which destroys attribution: an audit log
recording a uid cannot say which of the two names was responsible.

Two entries sharing a name are worse in a different way. Name resolution
returns the first match, so the second entry is unreachable: its uid, its
shell, its home directory and its group are all silently ignored. An
administrator who edits the second copy makes no change at all and has no way
to tell.

Both states are usually accidental — a provisioning script that allocated a uid
already in use, or a file edited by two tools at once — and both are also a
tidy way to hide an account in plain sight.`,

	BaseSeverity: finding.High,
	Tags:         []string{"users", "accountability", "attribution"},
	Requires:     []fact.ID{fact.PasswdID},
	SinceCatalog: 4,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := passwdFact(fs)

		dupUIDs := p.DuplicateUIDs()
		dupNames := p.DuplicateNames()

		if len(dupUIDs) == 0 && len(dupNames) == 0 {
			return unknownIfIncomplete(p, catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"Every one of the %d account(s) in %s has a distinct uid and a distinct name.",
					len(p.Entries), p.Path),
			})
		}

		var (
			evidence []finding.Evidence
			parts    []string
			subjects []string
		)

		for _, uid := range dupUIDs {
			shared := p.ByUID(uid)
			names := make([]string, 0, len(shared))
			for _, e := range shared {
				names = append(names, e.Name)
				evidence = append(evidence, passwdEvidence(p, e))
			}
			parts = append(parts, fmt.Sprintf("uid %d is shared by %s", uid, joinNames(names)))
			subjects = append(subjects, names...)
		}

		for _, name := range dupNames {
			var lines []int
			for _, e := range p.Entries {
				if e.Name == name {
					lines = append(lines, e.Line)
					evidence = append(evidence, passwdEvidence(p, e))
				}
			}
			parts = append(parts, fmt.Sprintf(
				"the name %q appears on lines %s, and only the first is reachable",
				name, joinInts(lines)))
			subjects = append(subjects, name)
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: joinNames(subjects),
			Detail: fmt.Sprintf(
				"%s contains duplicate identities: %s. A shared uid makes two names one account and destroys attribution; a shared name makes the later entry unreachable, so anything configured there is silently not in force.",
				p.Path, joinNames(parts)),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Give every account a unique uid and a unique name.",
		Effort:  "MEDIUM",
		Steps: []string{
			"List the collisions: 'awk -F: '\\''{print $3}'\\'' /etc/passwd | sort | uniq -d' for uids, and the same on $1 for names.",
			"For a duplicated uid, decide which account should keep it and record which files the other owns before changing anything: 'find / -xdev -uid <uid> -print > /root/uid-<uid>.list'.",
			"Allocate a free uid and apply it: 'usermod -u <newuid> <name>', then re-own the recorded files with 'chown'.",
			"For a duplicated name, remove the unreachable entry — but first confirm it is genuinely redundant, because it may be the entry somebody believed was in effect.",
			"Verify with 'pwck', which reports both conditions.",
		},
		Commands: []string{
			"pwck -r",
			"awk -F: '{print $3}' /etc/passwd | sort | uniq -d",
		},
		Caution: "Changing a uid does not change the ownership of files already on disk; those files become owned by whatever account now holds the old uid. Record the file list before making the change — after it, the old uid no longer identifies them.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "IA-4"},
		{Framework: "nist-800-53-r5", Control: "AU-6"},
	},

	References: []finding.Reference{
		{Title: "pwck(8)", URL: "https://man7.org/linux/man-pages/man8/pwck.8.html"},
	},
}

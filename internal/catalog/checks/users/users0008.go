package users

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0008 is USERS-0005 for the group database.
var Check0008 = catalog.Check{
	ID:     "USERS-0008",
	Module: "USERS",
	Title:  "No gid or group name is used by more than one entry",
	Description: `Two groups sharing a gid are one group to the kernel. File
permissions are enforced against the numeric gid, never the name, so granting
somebody membership of "developers" also grants them everything the other group
holding that gid can reach, and nothing in either group's definition says so.
The reverse is equally true when reading an audit trail: a gid in a log or a
directory listing no longer identifies which group was meant.

Two entries sharing a name are a different failure. Group resolution returns
the first match, so the second entry is unreachable: its gid and its member
list are silently ignored. An administrator who adds a user to the second copy
has made no change at all, and 'getent group <name>' will confirm the first
entry's contents back to them without any indication that another exists.

Both states are produced by ordinary accidents, a package postinstall that
allocated a gid already taken, a configuration-management run that appended
rather than replaced, and both are also an unremarkable-looking way to widen
access to a set of files.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"users", "groups", "attribution"},
	Requires:     []fact.ID{fact.GroupID},
	SinceCatalog: 5,

	Eval: func(fs *fact.Set) catalog.Outcome {
		g := groupFact(fs)

		dupGIDs := g.DuplicateGIDs()
		dupNames := g.DuplicateNames()

		if len(dupGIDs) == 0 && len(dupNames) == 0 {
			return unknownIfGroupIncomplete(g, catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"Every one of the %d group(s) in %s has a distinct gid and a distinct name.",
					len(g.Entries), g.Path),
			})
		}

		var (
			evidence []finding.Evidence
			parts    []string
			subjects []string
		)

		for _, gid := range dupGIDs {
			shared := g.ByGID(gid)
			names := make([]string, 0, len(shared))
			for _, e := range shared {
				names = append(names, e.Name)
				evidence = append(evidence, groupEvidence(g, e))
			}
			parts = append(parts, fmt.Sprintf("gid %d is shared by %s", gid, joinNames(names)))
			subjects = append(subjects, names...)
		}

		for _, name := range dupNames {
			var lines []int
			for _, e := range g.Entries {
				if e.Name == name {
					lines = append(lines, e.Line)
					evidence = append(evidence, groupEvidence(g, e))
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
				"%s contains duplicate group identities: %s. Permissions are enforced against the gid, so a shared gid silently merges the access of both groups; a shared name makes the later entry unreachable, so memberships recorded there are not in force.",
				g.Path, joinNames(parts)),
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Give every group a unique gid and a unique name.",
		Effort:  "MEDIUM",
		Steps: []string{
			"List the collisions: 'awk -F: '\\''{print $3}'\\'' /etc/group | sort | uniq -d' for gids, and the same on $1 for names.",
			"For a duplicated gid, decide which group should keep it and record what the other one owns before changing anything: 'find / -xdev -gid <gid> -print > /root/gid-<gid>.list'.",
			"Allocate a free gid and apply it: 'groupmod -g <newgid> <name>', then re-own the recorded files with 'chgrp'.",
			"For a duplicated name, confirm which entry is actually in force with 'getent group <name>', it returns the first, and check whether the memberships in the unreachable entry were meant to be active before removing it.",
			"Verify with 'grpck', which reports both conditions.",
		},
		Commands: []string{
			"grpck -r",
			"awk -F: '{print $3}' /etc/group | sort | uniq -d",
		},
		Caution: "Changing a gid does not change the group ownership of files already on disk; those files become owned by whatever group now holds the old gid, which can silently widen rather than narrow access. Record the file list before making the change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AU-6"},
	},

	References: []finding.Reference{
		{Title: "grpck(8)", URL: "https://man7.org/linux/man-pages/man8/grpck.8.html"},
		{Title: "group(5)", URL: "https://man7.org/linux/man-pages/man5/group.5.html"},
	},
}

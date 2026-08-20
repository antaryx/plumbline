package users

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0007 tests that group 0 belongs to root and to nothing else.
//
// The check is deliberately narrower than "no account has primary gid 0",
// which is the form this rule usually takes and which is wrong on a large
// fraction of real hosts. Red Hat-family distributions ship several system
// accounts in group 0 by default — operator, halt, shutdown and sync all carry
// "0" in the fourth field of /etc/passwd — so the naive form reports four
// findings on a stock RHEL installation that no operator can act on and that
// train the reader to skim past this module. See docs/checks/USERS-0007.md.
var Check0007 = catalog.Check{
	ID:     "USERS-0007",
	Module: "USERS",
	Title:  "Group 0 is confined to root",
	Description: `Group 0 is the group half of root's identity. Files created by
root are owned by group 0 unless something says otherwise, and a great many of
them — including, on most distributions, /etc/shadow's directory, the systemd
unit tree and /root itself — grant the group read access that they deny to
everyone else. An ordinary account whose primary group is 0 therefore reads a
substantial part of what root reads, without ever appearing in a listing of
privileged accounts and without triggering any check that looks at uid 0.

Three things have to hold. Root's own primary group must be 0, because the
files root creates are expected to land in it and a root account in some other
group quietly changes the ownership of everything it writes. No ordinary
account may have primary group 0. And the group's supplementary member list —
the fourth field of the "root:x:0:" line in /etc/group — must name nobody,
because every name in it holds group 0 as a secondary group at every login.

System accounts with primary group 0 are reported but not failed. Several
distributions ship them that way, so failing them would produce findings that
are correct about the file and useless to the person reading them.`,

	BaseSeverity: finding.High,
	Tags:         []string{"users", "groups", "privilege"},
	Requires:     []fact.ID{fact.PasswdID, fact.GroupID},
	SinceCatalog: 5,

	Eval: func(fs *fact.Set) catalog.Outcome {
		p := passwdFact(fs)
		g := groupFact(fs)

		// A system with no group 0 is not a system this check understands. It
		// is not a PASS: the group every root-owned file belongs to is missing
		// from the file that is supposed to define it.
		rootGroups := g.ByGID(0)
		if len(rootGroups) == 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"No group in %s holds gid 0. Every Unix system has one — it is the group of every file root creates — so either this file is not the whole group database or it is not what it appears to be.",
					g.Path),
				Evidence: []finding.Evidence{finding.NewEvidence(g.Path, 0, "no gid 0 entry", g.Digest)},
			}
		}

		var rootAcct fact.PasswdEntry
		var haveRoot bool
		for _, e := range p.Entries {
			if e.Name == "root" {
				rootAcct, haveRoot = e, true
				break
			}
		}
		if !haveRoot {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"%s defines no account named root, so root's own primary group cannot be read. USERS-0001 reports which accounts hold uid 0 on this host.",
					p.Path),
				Evidence: []finding.Evidence{finding.NewEvidence(p.Path, 0, "no root entry", p.Digest)},
			}
		}

		var (
			violations []string
			subjects   []string
			evidence   []finding.Evidence
			systemGID0 []string
		)

		// 1. Root's own primary group.
		if rootAcct.GID != 0 {
			violations = append(violations, fmt.Sprintf(
				"root's primary group is %d rather than 0, so files root creates are owned by that group instead",
				rootAcct.GID))
			subjects = append(subjects, "root")
			evidence = append(evidence, passwdEvidence(p, rootAcct))
		}

		// 2. Accounts other than root whose primary group is 0.
		//
		// Accounts holding uid 0 are excluded. Their group is not the finding
		// — they already are root by the only measure the kernel applies — and
		// USERS-0001 reports them with the severity that deserves.
		for _, e := range p.Entries {
			if e.GID != 0 || e.Name == "root" || e.UID == 0 {
				continue
			}
			if isSystemAccount(e.UID) {
				systemGID0 = append(systemGID0, fmt.Sprintf("%s (uid %d)", e.Name, e.UID))
				continue
			}
			violations = append(violations, fmt.Sprintf(
				"%s (uid %d) has primary group 0, so every file it creates is group-owned by root and it reads every root-owned file the group can read",
				e.Name, e.UID))
			subjects = append(subjects, e.Name)
			evidence = append(evidence, passwdEvidence(p, e))
		}

		// 3. Supplementary members of group 0.
		for _, grp := range rootGroups {
			var extra []string
			for _, m := range grp.Members {
				if m != "root" {
					extra = append(extra, m)
				}
			}
			if len(extra) > 0 {
				violations = append(violations, fmt.Sprintf(
					"the %s group (gid %d) lists supplementary members other than root — %s — each of whom holds group 0 at every login",
					grp.Name, grp.GID, joinNames(extra)))
				subjects = append(subjects, extra...)
				evidence = append(evidence, groupEvidence(g, grp))
			}
		}

		if len(violations) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: joinNames(subjects),
				Detail: fmt.Sprintf(
					"Group 0 is not confined to root: %s. Group 0 is the group half of root's identity, and membership in it is not visible to any check that looks only at uid 0.",
					// Joined in the order the propositions are evaluated, not
					// sorted: each clause is a sentence containing commas, and
					// sorting them by their first character would interleave
					// three separate findings into one unreadable run-on.
					// Determinism comes from the evaluation order, which is
					// fixed by file order.
					strings.Join(violations, "; ")),
				Evidence: evidence,
			}
		}

		detail := fmt.Sprintf(
			"root holds primary group 0, no ordinary account in %s does, and the gid 0 group in %s lists no supplementary members.",
			p.Path, g.Path)
		if len(systemGID0) > 0 {
			detail += fmt.Sprintf(
				" %d system account(s) also hold primary group 0 — %s — which is the convention several distributions ship and is not reported as a violation; accounts at or below uid %d are treated as system accounts.",
				len(systemGID0), joinNames(systemGID0), SystemUIDMax)
		}

		return unknownIfIncomplete(p, unknownIfGroupIncomplete(g, catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail,
			Evidence: []finding.Evidence{passwdEvidence(p, rootAcct), groupEvidence(g, rootGroups[0])},
		}))
	},

	Remediation: &finding.Remediation{
		Summary: "Give the account a primary group of its own and remove supplementary members from group 0.",
		Effort:  "MEDIUM",
		Steps: []string{
			"List what is in group 0: 'awk -F: '\\''$4 == 0 {print $1, $3}'\\'' /etc/passwd' for primary members, and 'getent group 0' for supplementary ones.",
			"Record what the account owns before changing its group, because the change does not re-own existing files: 'find / -xdev -user <name> -print > /root/<name>.files'.",
			"Create a group for the account and move it: 'groupadd <name>' then 'usermod -g <name> <name>'.",
			"Re-own the recorded files: 'xargs -a /root/<name>.files chgrp <name>' — check the list first for anything that genuinely should stay group root.",
			"Remove supplementary members: 'gpasswd -d <name> root'.",
			"If root's own primary group is not 0, set it back with 'usermod -g 0 root' and check what root has created since it changed.",
		},
		Commands: []string{
			"awk -F: '$4 == 0 {print $1, $3}' /etc/passwd",
			"getent group 0",
		},
		Caution: "Changing an account's primary group does not change the group ownership of files it already created; those files stay group 0 and stay readable to anything still in that group. Record the file list before the change — afterwards the account's group no longer identifies them.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-2"},
	},

	References: []finding.Reference{
		{Title: "group(5)", URL: "https://man7.org/linux/man-pages/man5/group.5.html"},
		{Title: "usermod(8)", URL: "https://man7.org/linux/man-pages/man8/usermod.8.html"},
	},
}

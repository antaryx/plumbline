package filesys

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests that no file is writable by every account on the host.
var Check0003 = catalog.Check{
	ID:     "FILESYS-0003",
	Module: "FILESYS",
	Title:  "No file is world-writable",
	Description: `A world-writable file is one that every account on the host
may rewrite — including the service accounts that packages create, which is the
part that matters. An attacker who reaches a web server running as www-data has
not got a shell as a person; they have got one as an account nobody thinks of
as a user, and every world-writable file on the host is now theirs to change.

What the change is worth depends on the file. A world-writable shell script
that root runs from cron is root. A world-writable configuration file is
whatever the daemon reading it will do. A world-writable log is an audit trail
somebody else edits. None of these needs an exploit; the permission *is* the
grant.

Symlinks are excluded from this check and the exclusion is load-bearing. A
symlink's own mode is lrwxrwxrwx on Linux and the kernel ignores it entirely —
access is decided by the target — so including them would report thousands of
false findings on a stock host and bury the real ones among them.

Directories are counted separately, by FILESYS-0004 and FILESYS-0005, because a
world-writable directory is a different exposure with a different remedy: /tmp
is world-writable by design and correct.`,

	BaseSeverity: finding.High,
	Tags:         []string{"filesys", "permissions", "integrity"},
	Requires:     []fact.ID{fact.FSFactID(collector.InterestWorldWrite)},
	SinceCatalog: 11,

	Eval: func(fs *fact.Set) catalog.Outcome {
		ww := matches(fs, collector.InterestWorldWrite)

		// Positive: we stat'ed these. A partial walk cannot unmake them.
		if len(ww.Rows) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: ww.Rows[0].Path,
				Detail: fmt.Sprintf(
					"%d file%s writable by every account on this host: %s. That includes the service accounts packages create, so an attacker who reaches a daemon running as www-data or nobody can rewrite each of them — no exploit needed, the permission is the grant.",
					len(ww.Rows), plural(len(ww.Rows), " is", "s are"), paths(ww.Rows)),
				Evidence: rowsEvidence(ww.Rows),
			}
		}

		return mustBeComplete(catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"No world-writable file was found in %d inode(s) examined. Every regular file on this host is writable only by its owner or its group.",
				ww.InodesVisited),
		}, ww)
	},

	Remediation: &finding.Remediation{
		Summary: "Remove the world-write bit, after establishing which account was supposed to be writing the file.",
		Effort:  "LOW",
		Steps: []string{
			"Work out who needs to write it before you take the permission away. A file made world-writable usually got that way because two accounts needed to share it and 'chmod 666' was quicker than creating a group.",
			"Create a group for the accounts that genuinely share it, then 'chgrp <group> <path>' and 'chmod 664 <path>'. That is the fix the world-write bit was standing in for.",
			"Where nothing shares it: 'chmod o-w <path>'.",
			"Look at the file's content as well as its mode if it is a script, a configuration file or anything root reads. World-writable means it may already have been changed, and the mode does not record whether it was.",
			"Check the directory too. A world-writable *directory* lets anyone replace the file regardless of the file's own mode, which makes fixing the file alone insufficient — FILESYS-0004 and FILESYS-0005 cover that.",
		},
		Commands: []string{
			"find / -xdev -type f -perm -0002 -ls",
			"chmod o-w <path>",
		},
		Caution: "Some applications genuinely expect a shared writable file — a lock file, a spool, a socket path. Removing the permission can break them in ways that appear only under load or at the next restart. Identify the writer before changing the mode, and prefer a group to a world-write bit rather than simply removing it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "chmod(1)", URL: "https://man7.org/linux/man-pages/man1/chmod.1.html"},
	},
}

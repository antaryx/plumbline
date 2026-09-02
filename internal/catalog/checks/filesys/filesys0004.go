package filesys

import (
	"fmt"
	"io/fs"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	factpkg "github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests that world-writable directories carry the sticky bit.
var Check0004 = catalog.Check{
	ID:     "FILESYS-0004",
	Module: "FILESYS",
	Title:  "World-writable directories have the sticky bit set",
	Description: `Write permission on a directory is permission to *delete and
replace* the files inside it, whoever owns them. That is not obvious, and it is
the whole of this check.

In a world-writable directory without the sticky bit, any account can remove
any other account's file and put its own there under the same name. The victim
opens the path they have always opened and reads content somebody else wrote.
Nothing about the file's own mode prevents it. The file was not modified. It
was replaced.

The sticky bit closes exactly this. On a directory it means "only the file's
owner, the directory's owner, or root may unlink or rename an entry". /tmp
carries it on every distribution, which is why /tmp being world-writable is
correct rather than alarming: mode 1777 is a shared workspace, mode 0777 is a
free-for-all.

Where it goes wrong is almost never /tmp itself. It is a spool directory, an
upload directory, or a shared drop point created with 'mkdir -m 777' by
somebody who wanted two services to exchange files and did not know the bit
existed.

FILESYS-0005 asks a different question about the same directories: whether they
should be world-writable at all. A directory can pass this check and fail that
one, a sticky world-writable /usr/bin is still catastrophic.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"filesys", "permissions", "sticky-bit", "integrity"},
	Requires:     []factpkg.ID{factpkg.FSFactID(collector.InterestWorldDir)},
	SinceCatalog: 11,

	Eval: func(set *factpkg.Set) catalog.Outcome {
		dirs := matches(set, collector.InterestWorldDir)

		bad := filter(dirs.Rows, func(r factpkg.FSRow) bool { return r.Mode&fs.ModeSticky == 0 })

		// Positive: we stat'ed these. A partial walk cannot unmake them.
		if len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: bad[0].Path,
				Detail: fmt.Sprintf(
					"%d world-writable director%s the sticky bit: %s. Write permission on a directory is permission to delete and replace the files in it whoever owns them, so any account can swap another's file for its own under the same name — the victim opens the path they always open and reads what somebody else wrote. The sticky bit restricts unlink and rename to the file's owner, which is why /tmp is 1777 rather than 0777.",
					len(bad), plural(len(bad), "y lacks", "ies lack"), paths(bad)),
				Evidence: rowsEvidence(bad),
			}
		}

		detail := fmt.Sprintf(
			"All %d world-writable director%s the sticky bit, so only a file's own owner may delete or rename it. Whether these directories should be world-writable at all is FILESYS-0005's question.",
			len(dirs.Rows), plural(len(dirs.Rows), "y carries", "ies carry"))
		if len(dirs.Rows) == 0 {
			detail = fmt.Sprintf(
				"No world-writable directory was found in %d inode(s) examined, so there is none that could be missing the sticky bit. Note that a host without a world-writable /tmp is unusual rather than hardened — most software expects one.",
				dirs.InodesVisited)
		}
		return mustBeComplete(catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail,
			Evidence: rowsEvidence(dirs.Rows),
		}, dirs)
	},

	Remediation: &finding.Remediation{
		Summary: "Set the sticky bit, or replace the world-write permission with a group.",
		Effort:  "LOW",
		Steps: []string{
			"Ask first whether the directory needs to be world-writable. A shared drop point between two services wants a group, 'chgrp shared <dir>' and 'chmod 2770 <dir>', not world write. That removes the problem rather than containing it.",
			"Where it genuinely is a shared workspace: 'chmod +t <dir>'. The mode becomes 1777 and the directory behaves like /tmp.",
			"Check what is already in it. Without the sticky bit, files there may already have been replaced, and their modification times will look ordinary because the replacement is a new file rather than an edit.",
			"Watch for the pattern that creates these: 'mkdir -m 777' in an install script or a Dockerfile. Fixing the directory without fixing the script means it returns at the next deployment.",
		},
		Commands: []string{
			"find / -xdev -type d -perm -0002 ! -perm -1000 -ls",
			"chmod +t <dir>",
			"ls -ld /tmp",
		},
		Caution: "The sticky bit stops one account deleting another's files, which is occasionally what a workflow was relying on, a cleanup job running as a service account will start failing on files it does not own. Check what removes files from the directory before setting it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "chmod(1), the restricted deletion flag", URL: "https://man7.org/linux/man-pages/man1/chmod.1.html"},
	},
}

package filesys

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests that no setuid or setgid executable can be rewritten by an
// unprivileged account.
var Check0001 = catalog.Check{
	ID:     "FILESYS-0001",
	Module: "FILESYS",
	Title:  "No setuid or setgid executable is writable by group or other",
	Description: `A setuid executable runs with its owner's privileges rather
than the caller's, usually root's. That is the entire point of the mechanism
and it is why passwd, sudo and mount work at all. It also means the file's
*contents* are executed as root by anybody who runs it.

So a setuid binary that a non-root account can write is not a permissions
problem. It is a root shell with a waiting period: the unprivileged account
overwrites the file with anything it likes, waits for the next person to run it
, or runs it themselves, and the code executes as the owner. No exploit, no
vulnerability, no authentication step. The same reasoning applies to setgid,
one privilege level down.

This check needs no allowlist, which is what makes it trustworthy. It does not
ask whether a particular binary should be setuid; it asserts a property that
**no** legitimate setuid executable has on any distribution. A finding here is
wrong only if the file is not really setuid or not really writable, and both
came from the same stat.

The usual causes are mundane: a chmod -R that swept up a bin directory, a
package built with the wrong umask, a deployment that chowns its tree to a
service account and happens to ship a setuid helper.`,

	BaseSeverity: finding.Critical,
	Tags:         []string{"filesys", "suid", "privilege-escalation", "permissions"},
	Requires: []fact.ID{
		fact.FSFactID(collector.InterestSUID),
		fact.FSFactID(collector.InterestSGID),
	},
	SinceCatalog: 11,

	Eval: func(fs *fact.Set) catalog.Outcome {
		suid := matches(fs, collector.InterestSUID)
		sgid := matches(fs, collector.InterestSGID)

		writable := func(r fact.FSRow) bool { return r.Mode.Perm()&0o022 != 0 }
		bad := concat(filter(suid.Rows, writable), filter(sgid.Rows, writable))

		// Positive: we stat'ed these inodes. A walk that stopped early cannot
		// unmake a setuid binary it already found.
		if len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: bad[0].Path,
				Detail: fmt.Sprintf(
					"%d setuid or setgid executable%s writable by group or other: %s. Whoever can write one of these decides what runs as its owner — root, in almost every case — so this is not a permissions problem but a root shell waiting for the next person to run the file.",
					len(bad), plural(len(bad), " is", "s are"), paths(bad)),
				Evidence: rowsEvidence(bad),
			}
		}

		total := len(suid.Rows) + len(sgid.Rows)
		detail := fmt.Sprintf(
			"All %d setuid and setgid executable%s writable by their owner alone, so nothing but root decides what they run.",
			total, plural(total, " is", "s are"))
		if total == 0 {
			// "All 0 executables are writable by their owner alone" is true
			// and reads like a parsing accident. A PASS drawn from an empty
			// set should say so, because the reader's next question is
			// whether the walk actually looked.
			detail = fmt.Sprintf(
				"This host has no setuid or setgid executables at all: none was found in %d inode(s) examined, so there is nothing here for an unprivileged account to rewrite.",
				suid.InodesVisited)
		}
		return mustBeComplete(catalog.Outcome{Result: finding.Pass, Detail: detail}, suid, sgid)
	},

	Remediation: &finding.Remediation{
		Summary: "Remove group and other write from the file, then establish whether it was already modified.",
		Effort:  "LOW",
		Steps: []string{
			"Treat the file as possibly already replaced, not merely as misconfigured. Anyone who could write it could have rewritten it, and the mode tells you nothing about whether they did.",
			"Compare it against the package's own copy before changing anything: 'rpm -Vf <path>' or 'dpkg --verify <package>' names the files whose size, mode or checksum no longer match what was installed.",
			"Remove the write bits: 'chmod go-w <path>'. The conventional mode for a setuid binary is 4755.",
			"Ask whether it needs to be setuid at all. Many binaries carry the bit for historical reasons and work without it; 'chmod u-s <path>' and testing the workflow costs less than leaving an unnecessary escalation path in place.",
			"Find out how it happened, or it will happen again. Ownership or mode drift on a bin directory almost always comes from a deployment step running chmod -R or chown -R on a tree it did not fully understand.",
		},
		Commands: []string{
			"find / -xdev -type f -perm /6000 -perm /022 -ls",
			"rpm -Vf <path>",
			"dpkg --verify",
		},
		Caution: "Removing the setuid bit from a binary that genuinely needs it breaks whatever depends on it, sometimes only for non-root users and sometimes only at the next reboot. Remove the *write* bits first, that closes the escalation immediately and changes nothing else, and evaluate the setuid bit separately.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "chmod(1), setuid and setgid", URL: "https://man7.org/linux/man-pages/man1/chmod.1.html"},
	},
}

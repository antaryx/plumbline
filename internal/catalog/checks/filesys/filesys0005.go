package filesys

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// SystemDirs are the trees whose contents the operating system depends on.
//
// A world-writable directory anywhere is worth a look; one of these is
// different in kind, because what lives under them is executed, loaded or read
// by root as a matter of routine.
var SystemDirs = []string{
	"/bin", "/sbin", "/lib", "/lib64",
	"/usr", "/etc", "/boot", "/opt", "/root",
	"/var/lib", "/var/spool/cron", "/var/www",
}

// Check0005 tests that no directory the system depends on is world-writable.
var Check0005 = catalog.Check{
	ID:     "FILESYS-0005",
	Module: "FILESYS",
	Title:  "No system directory is world-writable",
	Description: `FILESYS-0004 asks whether a world-writable directory has the
sticky bit. This asks a question the sticky bit does not answer: whether the
directory should be world-writable at all.

The sticky bit restricts deleting and renaming *existing* entries. It does
nothing about creating new ones. So a world-writable /usr/bin with the sticky
bit set still lets any account add a file — and adding a file to a directory on
$PATH is enough on its own. The account creates something plausible, waits for
an administrator to mistype a command or for a script to call a binary by name
rather than by path, and their code runs as whoever ran it.

Under /etc it is worse, because so much of what lives there is read by root at
boot: a new file in /etc/cron.d, /etc/sudoers.d or /etc/systemd/system is root
on a timer. Under /boot it survives reinstalling the operating system above it.

This is the same escalation the CRON and SERVICES modules check from their own
angles — CRON-0002 for the cron drop-in directories, SERVICES-0005 for the unit
directories. This check covers the tree those live in, and it fires whether or
not the sticky bit is present, because the sticky bit was never the control
that mattered here.`,

	BaseSeverity: finding.Critical,
	Tags:         []string{"filesys", "permissions", "privilege-escalation", "integrity"},
	Requires:     []fact.ID{fact.FSFactID(collector.InterestWorldDir)},
	SinceCatalog: 11,

	Eval: func(fs *fact.Set) catalog.Outcome {
		dirs := matches(fs, collector.InterestWorldDir)

		bad := filter(dirs.Rows, func(r fact.FSRow) bool { return under(r.Path, SystemDirs...) })

		// Positive: we stat'ed these. A partial walk cannot unmake them.
		if len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: bad[0].Path,
				Detail: fmt.Sprintf(
					"%d director%s the operating system depends on %s world-writable: %s. The sticky bit does not help here — it restricts deleting existing entries and says nothing about creating new ones, and creating one is the whole attack. A new file under a $PATH directory runs when somebody mistypes; a new file under /etc/cron.d or /etc/systemd/system runs as root on a schedule.",
					len(bad), plural(len(bad), "y", "ies"), plural(len(bad), "is", "are"), paths(bad)),
				Evidence: rowsEvidence(bad),
			}
		}

		return mustBeComplete(catalog.Outcome{
			Result: finding.Pass,
			Detail: "No directory the operating system depends on is world-writable: nothing under /usr, /etc, /bin, /sbin, /lib, /boot, /opt, /root or /var/lib may be added to by an unprivileged account.",
		}, dirs)
	},

	Remediation: &finding.Remediation{
		Summary: "Remove world write from the directory and audit everything currently in it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Audit the contents before fixing the mode. Anyone could have added a file, and a file that is already there keeps working after you remove the permission. 'ls -la' with an eye on ownership and timestamps, and for a package-owned directory 'rpm -Vf <dir>' or 'dpkg --verify' to name what does not belong.",
			"Remove the permission: 'chmod o-w <dir>'. The conventional mode is 0755.",
			"Pay particular attention to drop-in directories under /etc — cron.d, sudoers.d, systemd/system, profile.d, ld.so.conf.d. A single file left in one of those is a persistent root shell that survives the permission fix.",
			"Establish how it happened. This mode is almost always set by an install script or a container build doing 'chmod -R 777' on a tree to make an application work, and it will come back at the next deployment unless that is changed.",
			"Where an application genuinely needs to write inside a system tree, give it a subdirectory it owns rather than write access to the parent.",
		},
		Commands: []string{
			"find /usr /etc /bin /sbin /lib /boot /opt -xdev -type d -perm -0002 -ls",
			"ls -la <dir>",
			"chmod o-w <dir>",
		},
		Caution: "Treat this as possible compromise rather than as untidiness, and audit the directory's contents before changing the mode. Fixing the permission stops new files being added and removes nothing that is already there — a cron drop-in or a systemd unit left behind keeps running as root afterwards.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "MITRE ATT&CK T1574 — Hijack Execution Flow", URL: "https://attack.mitre.org/techniques/T1574/"},
	},
}

package filesys

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// SystemBinDirs are the directories a package manager installs executables
// into.
//
// This is a **location** rule, not a name allowlist, and the difference is the
// point. A list of blessed binary names silently excuses whatever an attacker
// names their implant after; a list of directories cannot, because the
// directories are root-owned and writing to them already requires the
// privilege the setuid binary would grant.
var SystemBinDirs = []string{
	"/bin", "/sbin",
	"/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib", "/usr/lib64",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/libexec", "/usr/local/lib",
	"/opt",
	// snap and flatpak ship setuid helpers under their own roots on hosts that
	// use them. Omitting these would fail every Ubuntu desktop for doing
	// something its vendor designed.
	"/snap", "/var/lib/snapd", "/var/lib/flatpak",
}

// Check0002 tests that setuid and setgid executables live where packages put
// them.
var Check0002 = catalog.Check{
	ID:     "FILESYS-0002",
	Module: "FILESYS",
	Title:  "No setuid or setgid executable outside the system binary directories",
	Description: `A setuid binary in /home, /tmp, /var/tmp or /srv is one of
the oldest persistence artifacts there is. An attacker who gains root once
copies a shell, sets the setuid bit and owns it to root; from then on they
regain root by running a file in their own home directory, with no exploit and
nothing that looks unusual in a log. The technique survives password changes,
key rotation and the patch that closed the original hole.

It is also, occasionally, an accident: a backup of /usr/bin restored into
/var/tmp, a build tree that preserved modes, an archive extracted as root with
'tar -p'. Those are not attacks and they are still the same escalation path.

The rule here is about **location**, not about names, and that is deliberate.
A list of blessed binary names would silently excuse whatever an attacker
chooses to call their implant. A list of directories cannot, because writing
into those directories already requires the privilege that the setuid bit
would grant — so a setuid file there tells you far less than one outside them.

What this check cannot do is tell an attacker's binary from a legitimate one
inside those directories. FILESYS-0001 covers the property that is decidable
without a name list; establishing that /usr/bin holds only what the package
manager put there is a job for 'rpm -Va' or 'dpkg --verify', and it needs
package metadata this tool does not collect.`,

	BaseSeverity: finding.High,
	Tags:         []string{"filesys", "suid", "persistence", "privilege-escalation"},
	Requires: []fact.ID{
		fact.FSFactID(collector.InterestSUID),
		fact.FSFactID(collector.InterestSGID),
	},
	SinceCatalog: 11,

	Eval: func(fs *fact.Set) catalog.Outcome {
		suid := matches(fs, collector.InterestSUID)
		sgid := matches(fs, collector.InterestSGID)

		outside := func(r fact.FSRow) bool { return !under(r.Path, SystemBinDirs...) }
		bad := concat(filter(suid.Rows, outside), filter(sgid.Rows, outside))

		// Positive: these inodes were stat'ed. A partial walk cannot unmake
		// them.
		if len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: bad[0].Path,
				Detail: fmt.Sprintf(
					"%d setuid or setgid executable%s outside the directories a package manager installs into: %s. A setuid binary in a home directory or a temporary directory is the classic way to keep root after the hole that granted it is closed — it survives password changes, key rotation and the patch — and it is indistinguishable from the accidental version produced by restoring an archive with modes preserved.",
					len(bad), plural(len(bad), " sits", "s sit"), paths(bad)),
				Evidence: rowsEvidence(bad),
			}
		}

		total := len(suid.Rows) + len(sgid.Rows)
		detail := fmt.Sprintf(
			"All %d setuid and setgid executable%s in the directories a package manager installs into. Whether each of them should carry the bit is a question this check does not answer — it needs package metadata Plumbline does not collect.",
			total, plural(total, " is", "s are"))
		if total == 0 {
			detail = fmt.Sprintf(
				"This host has no setuid or setgid executables at all: none was found in %d inode(s) examined, so none sits outside the directories a package manager installs into.",
				suid.InodesVisited)
		}
		return mustBeComplete(catalog.Outcome{Result: finding.Pass, Detail: detail}, suid, sgid)
	},

	Remediation: &finding.Remediation{
		Summary: "Establish what the file is before removing it; if it is not accounted for, treat the host as compromised.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Do not delete it first. Record it — 'ls -la', 'stat', 'sha256sum' — and check the hash against a malware reputation service and against the same binary in /usr/bin. A setuid copy of /bin/bash owned by root in somebody's home directory is not ambiguous.",
			"Establish when it appeared. The inode change time ('stat -c %z') is harder to forge than the modification time, and it usually bounds when the host was first touched.",
			"If it is not accounted for by a deployment or an archive extraction you can name, treat the host as compromised rather than as misconfigured. Somebody had root to create it, and this file is the artifact rather than the cause.",
			"If it is accounted for — a restored backup, a build tree — remove the bit rather than the file: 'chmod u-s,g-s <path>'.",
			"Prevent the recurrence: mount /home, /tmp and /var/tmp with nosuid, which makes the bit inert on those filesystems whatever the mode says. FILESYS-0007 and FILESYS-0009 check exactly that.",
		},
		Commands: []string{
			"find / -xdev -type f -perm /6000 -ls",
			"stat <path>",
			"sha256sum <path>",
		},
		Caution: "If this is an attacker's artifact, deleting it destroys the evidence and does not remove their access — they had root to create it and may have other paths back. Preserve it and treat the finding as an incident before cleaning up.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SI-4"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
	},

	References: []finding.Reference{
		{Title: "MITRE ATT&CK T1548.001 — Setuid and Setgid", URL: "https://attack.mitre.org/techniques/T1548/001/"},
	},
}

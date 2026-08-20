package filesys

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0006 tests that no device node exists outside /dev.
var Check0006 = catalog.Check{
	ID:     "FILESYS-0006",
	Module: "FILESYS",
	Title:  "No device node exists outside /dev",
	Description: `A device node is a doorway to hardware, and the kernel does
not care where the doorway is. /dev/sda is not special because of its path — it
is a block device node with a major and minor number, and an identical node
created in /tmp or in a home directory reaches the same disk.

That is what makes one outside /dev worth reporting. Reading a raw block device
bypasses every file permission on the filesystem stored on it: an account that
cannot read /etc/shadow through the filesystem can read the bytes of /etc/shadow
straight off the disk. A character device node for /dev/mem or /dev/kmem
bypasses the kernel's own memory protection. Creating one needs root, so a node
outside /dev is either a mistake made by root or an artifact left by somebody
who had root — and in the second case it is a way back in that survives the
patch which closed the original hole.

The mistakes are real too. Extracting an archive as root with 'tar -p', or
restoring a backup of /dev into the wrong place, produces exactly this. Neither
is an attack and both are the same doorway.

Creating the node requires privilege; **using** it requires only the
permissions on the node itself, which is why a node an attacker leaves
world-readable is usable by any account afterwards.

This is one reason the walker stats non-regular files rather than skipping
them, and never opens one.`,

	BaseSeverity: finding.High,
	Tags:         []string{"filesys", "device", "privilege-escalation", "persistence"},
	Requires:     []fact.ID{fact.FSFactID(collector.InterestDevice)},
	SinceCatalog: 11,

	Eval: func(fs *fact.Set) catalog.Outcome {
		dev := matches(fs, collector.InterestDevice)

		// Positive: we stat'ed these. A partial walk cannot unmake them.
		if len(dev.Rows) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: dev.Rows[0].Path,
				Detail: fmt.Sprintf(
					"%d device node%s outside /dev: %s. The kernel resolves a device by its major and minor number, not by its path, so a node here reaches the same hardware as the one in /dev — reading a raw block device bypasses every file permission on the filesystem stored on it. Creating one needs root, so this is either a mistake made by root or something left behind by somebody who had it.",
					len(dev.Rows), plural(len(dev.Rows), " exists", "s exist"), paths(dev.Rows)),
				Evidence: rowsEvidence(dev.Rows),
			}
		}

		return mustBeComplete(catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"No block or character device node exists outside /dev in %d inode(s) examined.",
				dev.InodesVisited),
		}, dev)
	},

	Remediation: &finding.Remediation{
		Summary: "Record the node and establish where it came from before removing it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Record it first: 'ls -l' shows the major and minor numbers in place of a size, and 'stat' shows when the inode was created. Which device it points at tells you what it was for — 8,x is a SCSI or SATA disk, 1,1 is /dev/mem.",
			"Work out whether anything on the host explains it. Extracting an archive as root with 'tar -p', or restoring a backup of /dev to the wrong path, produces exactly this and is not an attack.",
			"If nothing explains it, treat the host as compromised. Creating a device node requires root, so whoever made it already had the privilege this node would grant — the node is the artifact, not the cause.",
			"Remove it once it is recorded: 'rm <path>'.",
			"Prevent the recurrence by mounting /home, /tmp and /var/tmp with nodev, which makes device nodes on those filesystems inert whatever their mode. FILESYS-0007 through FILESYS-0009 check that.",
		},
		Commands: []string{
			"find / -xdev \\( -type b -o -type c \\) ! -path '/dev/*' -ls",
			"stat <path>",
		},
		Caution: "If this is an attacker's artifact, deleting it destroys evidence and does not remove their access. Record it — path, major and minor numbers, timestamps — and treat the finding as an incident before cleaning up.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-4"},
	},

	References: []finding.Reference{
		{Title: "mknod(2)", URL: "https://man7.org/linux/man-pages/man2/mknod.2.html"},
	},
}

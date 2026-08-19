package filesys

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0008 tests that /dev/shm carries nodev, nosuid and noexec.
var Check0008 = catalog.Check{
	ID:     "FILESYS-0008",
	Module: "FILESYS",
	Title:  "/dev/shm is mounted with nodev, nosuid and noexec",
	Description: `/dev/shm is POSIX shared memory: a tmpfs that every account
on the host can write to, present on essentially every Linux system, and
invisible to the people who think of /tmp as the writable directory.

That invisibility is the point. It is world-writable like /tmp, it is backed by
RAM so nothing touches a disk, and it is not what anybody watches. A payload
written there leaves no trace on storage, survives until reboot, and is missed
by the file-integrity monitoring and the forensic image alike. Attackers use it
for exactly that reason, and it is a routine finding in intrusions where /tmp
was hardened and this was not.

The same three options apply for the same three reasons as /tmp — noexec so
nothing written there runs, nosuid so a setuid binary there does not escalate,
nodev so a device node there reaches nothing.

Unlike /tmp, there is essentially no legitimate workload that needs to execute
from /dev/shm. It exists for shared memory segments, which are mapped rather
than executed, so noexec here costs almost nothing. On many distributions the
defaults are already nosuid and nodev but **not** noexec, which is why this
check is worth running on a host that looks fine.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"filesys", "mount", "hardening", "anti-forensics"},
	Requires:     []fact.ID{fact.MountsID},
	SinceCatalog: 11,

	Eval: func(set *fact.Set) catalog.Outcome {
		return evalMount(set, mountRule{
			Point:    "/dev/shm",
			Required: []string{"nodev", "nosuid", "noexec"},
			Why:      "/dev/shm is world-writable, backed by RAM rather than by storage, and unwatched — a payload there leaves nothing on disk for file-integrity monitoring or a forensic image to find",
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Add an fstab entry for /dev/shm with nodev,nosuid,noexec and remount it.",
		Effort:  "LOW",
		Steps: []string{
			"Add the entry, because the default mount is made by the kernel or by systemd without these options and there is usually no fstab line to edit: 'tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0'.",
			"Apply it without rebooting: 'mount -o remount /dev/shm'.",
			"Verify the options are actually in force rather than merely written down: 'findmnt /dev/shm'. An fstab entry for an already-mounted filesystem does nothing until the remount.",
			"Expect this to be the cheapest of the three mount checks to satisfy. /dev/shm holds shared memory segments, which are mapped rather than executed, so noexec breaks essentially nothing.",
			"On a systemd host, confirm nothing re-mounts it without the options at boot — 'systemctl show -p Options dev-shm.mount' shows what systemd believes it should be.",
		},
		Commands: []string{
			"findmnt /dev/shm",
			"mount -o remount,nodev,nosuid,noexec /dev/shm",
		},
		Caution: "A small number of database and HPC products place executable helpers in /dev/shm, and PostgreSQL's dynamic shared memory uses it heavily though not for execution. Check the workload before making the change permanent, but expect no impact on an ordinary host.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SC-2"},
	},

	References: []finding.Reference{
		{Title: "shm_overview(7)", URL: "https://man7.org/linux/man-pages/man7/shm_overview.7.html"},
	},
}

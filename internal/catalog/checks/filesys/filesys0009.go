package filesys

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0009 tests that /home is a separate mount with nodev and nosuid.
//
// noexec is deliberately observed rather than required; see the description.
var Check0009 = catalog.Check{
	ID:     "FILESYS-0009",
	Module: "FILESYS",
	Title:  "/home is a separate mount with nodev and nosuid",
	Description: `Home directories are writable by the people who own them,
which makes /home the second place — after /tmp — that anything a user brings
to the host ends up. Two of the three usual hardening options belong there
without argument:

- **nosuid** makes a setuid binary in a home directory inert. That is the
  classic persistence artifact FILESYS-0002 reports, and nosuid removes the
  capability rather than the file.
- **nodev** makes a device node there reach nothing, closing the raw-disk path
  FILESYS-0006 reports.

Neither costs a user anything. Nobody's workflow depends on being able to set
the setuid bit in their own home directory, and nobody's depends on creating a
device node there.

**noexec is reported and not required, and that is a deliberate judgement.**
Enforcing it on /home breaks Python virtual environments, local Go and Rust
builds, node_modules with native binaries, and every '~/.local/bin' on the
host — which is to say most of what a developer workstation exists to do. CIS
treats it as a separate, stricter item for that reason. On a server where
nobody builds or runs anything from a home directory it is worth setting, and
the finding says so; on a workstation, requiring it would produce a failure
that the right answer is to ignore, and a check whose right answer is to ignore
it teaches people to ignore the next one.

Being a separate filesystem also bounds the damage a user filling their home
directory can do: without it, /home fills the root filesystem and the host
stops being able to log.

A host with no /home at all — a single-purpose appliance, a container — has no
subject here rather than a failure.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"filesys", "mount", "hardening"},
	Requires:     []fact.ID{fact.MountsID},
	SinceCatalog: 11,

	Eval: func(set *fact.Set) catalog.Outcome {
		return evalMount(set, mountRule{
			Point:    "/home",
			Required: []string{"nodev", "nosuid"},
			Observed: []string{"noexec"},
			Why:      "home directories are writable by the people who own them, so /home is where a setuid binary or a device node an attacker leaves behind would sit — and nosuid and nodev make both inert without costing any user anything",
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Mount /home as its own filesystem with nodev and nosuid; consider noexec only where nobody builds.",
		Effort:  "MEDIUM",
		Steps: []string{
			"If /home is already a separate filesystem, this is an fstab edit and a remount: add 'nodev,nosuid' to its options and run 'mount -o remount /home'.",
			"If it is not, it needs a filesystem — a partition, an LVM volume, or a loopback file on a host you cannot repartition. Moving an existing /home means copying with 'rsync -aHAX' to preserve ownership, ACLs and extended attributes, from single-user mode or with nobody logged in.",
			"Verify with 'findmnt /home' that the options are in force rather than merely written in fstab.",
			"Decide about noexec separately and on evidence. On a server where no one builds anything it is worth adding. On any host where people use virtualenvs, language toolchains or '~/.local/bin', it breaks their work and the right response to the resulting failure is to remove the option again.",
			"If you do add noexec, tell the people who use the host before rather than after. The failure mode is a permission-denied error on a binary that plainly exists, which is one of the more confusing things a workstation can do.",
		},
		Commands: []string{
			"findmnt /home",
			"mount -o remount,nodev,nosuid /home",
			"lsblk -f",
		},
		Caution: "Moving /home onto a new filesystem copies data while people may be using it. Do it with nobody logged in, use 'rsync -aHAX' so ownership, ACLs and extended attributes survive, and keep the old copy until the new mount has been verified — a botched /home migration locks every non-root account out of its own files.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SC-2"},
	},

	References: []finding.Reference{
		{Title: "mount(8) — filesystem-independent mount options", URL: "https://man7.org/linux/man-pages/man8/mount.8.html"},
	},
}

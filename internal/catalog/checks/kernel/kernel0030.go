package kernel

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0030 tests whether hardlink protection is written to the sysctl
// configuration.
var Check0030 = catalog.Check{
	ID:     "KERNEL-0030",
	Module: "KERNEL",
	Title:  "Hardlink protection is written to the sysctl configuration",

	Description: `A hardlink is a second name for the same inode, and creating
one traditionally needed no permission on the file at all, only write access to
the directory the new name goes in. That is the whole problem. An unprivileged
user with a writable directory could link a file they cannot read, and the link
kept the original's contents and permissions while sitting somewhere they
control.

Two things follow, and both were real vulnerability classes:

  - **A file that gets processed later gets processed at the attacker's path.**
    Link /etc/shadow into a directory some privileged job cleans up, rotates or
    chowns, and the job acts on the attacker's chosen inode.
  - **Deletion stops being deletion.** A setuid program's temporary file, or a
    file about to be shredded, survives under a name the attacker kept.

fs.protected_hardlinks = 1 requires that the user creating a link either owns
the file or can read and write it. It closed a run of CVEs at a stroke and has
essentially no compatibility cost, which is why every distribution enables it
and why almost none of them write it down.

**The kernel defaults this to 1 on any current build, so most hosts are
protected while failing this check.** That is the subject: a default is not a
decision. Nothing on the host records that anyone chose it, and nothing stops a
drop-in from setting 0.

This is a check about files. KERNEL-0010 asks what the running kernel does.`,

	// High. Turning it off reopens a class of local privilege escalation that
	// needs no exploit and no race — just a writable directory and a
	// privileged process that touches a path. It sits with the other findings
	// that hand a local user a route to root.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "privilege-escalation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 31,

	Eval: protectedHardlinks.eval,

	Remediation: &finding.Remediation{
		Summary: "Write fs.protected_hardlinks = 1 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn protected_hardlinks /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. systemd ships it in 50-default.conf on most systemd hosts, and Ubuntu in 99-protect-links.conf; the RPM family commonly relies on the kernel default and writes nothing.",
			"Create or extend a drop-in containing fs.protected_hardlinks = 1. Write it down even though the running kernel reports 1: that is the kernel's built-in default rather than a decision on this host, and a drop-in setting 0 would win without anything recording that 1 was intended.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl fs.protected_hardlinks.",
			"Set fs.protected_symlinks in the same file, the two close halves of the same problem and are always configured together. KERNEL-0031 covers it.",
		},
		Commands: []string{
			"sysctl fs.protected_hardlinks",
			"grep -rn protected_hardlinks /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Effectively none. The restriction only refuses links to files the linking user could not already read and write, which no ordinary workload does. Very old backup or packaging tools that hardlink across ownership boundaries as root are unaffected, since root is exempt.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, fs.protected_hardlinks", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-hardlinks"},
		{Title: "Linux kernel commit 800179c9b8a1, hardlink restrictions", URL: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=800179c9b8a1"},
	},
}

// protectedHardlinks is the parameter, and the three sentences that make the
// shared reading say something specific about it.
var protectedHardlinks = linkProtection{
	key:    "fs.protected_hardlinks",
	caveat: persistCaveatFor("KERNEL-0010"),
	unset:  "Any current kernel defaults this to 1, which is correct — but nothing on this host records that, and a drop-in setting 0 would restore a class of local privilege escalation that needs no exploit: a writable directory and a privileged process that touches a path by name.",
	on:     "a hardlink may only be created to a file the user already owns or can read and write, which is what stops an unprivileged user parking a copy of a file they cannot read somewhere a privileged process will act on it.",
	off:    "any user may hardlink a file they cannot read into a directory they control, preserving its contents and permissions at a path of their choosing, where a privileged job that cleans up, rotates or chowns will act on it — and where deleting the original no longer deletes anything.",
}

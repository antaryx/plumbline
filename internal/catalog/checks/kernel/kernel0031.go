package kernel

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0031 tests whether symlink protection is written to the sysctl
// configuration.
var Check0031 = catalog.Check{
	ID:     "KERNEL-0031",
	Module: "KERNEL",
	Title:  "Symlink protection is written to the sysctl configuration",

	Description: `The classic local privilege escalation is four lines long. A
privileged program opens a predictable path in /tmp; an unprivileged user
replaces that path with a symlink to somewhere they should not be able to write;
the privileged program follows it and writes there. It is a race, it is easy to
win because the attacker chooses when to run, and it has been the mechanism
behind a very long run of CVEs.

fs.protected_symlinks = 1 breaks it in the kernel rather than in each program.
In a world-writable sticky directory — /tmp, /var/tmp, /dev/shm — a symlink is
only followed when the person following it owns the link, or owns the directory.
An attacker's link in /tmp is therefore not followed by root, and the race
becomes unwinnable regardless of how the program was written.

This is defence for code you did not write and cannot audit: every shell script
that redirects into /tmp, every package post-install, every log rotator. The
restriction applies only in sticky world-writable directories, so nothing
outside that pattern is affected.

**The kernel defaults this to 1 on any current build, so most hosts are
protected while failing this check.** That is the subject: a default is not a
decision, and nothing here stops a drop-in from setting 0.

This is a check about files. KERNEL-0009 asks what the running kernel does.`,

	// High, matching KERNEL-0030. The two close halves of the same problem and
	// splitting their severity would be arbitrary — turning either off reopens
	// a route from an unprivileged local account to root that needs no exploit
	// beyond winning a race the attacker starts.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "privilege-escalation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 31,

	Eval: protectedSymlinks.eval,

	Remediation: &finding.Remediation{
		Summary: "Write fs.protected_symlinks = 1 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn protected_symlinks /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. systemd ships it in 50-default.conf on most systemd hosts, and Ubuntu in 99-protect-links.conf; the RPM family commonly relies on the kernel default and writes nothing.",
			"Create or extend a drop-in containing fs.protected_symlinks = 1. Write it down even though the running kernel reports 1: that is the kernel's built-in default rather than a decision on this host.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl fs.protected_symlinks.",
			"Set fs.protected_hardlinks in the same file — the two close halves of the same problem and are always configured together. KERNEL-0030 covers it.",
			"Consider fs.protected_regular = 2 and fs.protected_fifos = 1 alongside them: they extend the same idea from following a link to opening a file or FIFO another user planted. KERNEL-0011 and KERNEL-0012 read the running values.",
		},
		Commands: []string{
			"sysctl fs.protected_symlinks",
			"grep -rn protected_symlinks /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Effectively none. The restriction applies only inside world-writable sticky directories and only to links whose owner differs from both the follower and the directory owner, which is a pattern legitimate software does not rely on. A program that genuinely needs to follow another user's link in /tmp is describing the vulnerability rather than a requirement.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SI-10"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — fs.protected_symlinks", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks"},
		{Title: "Linux kernel commit 800179c9b8a1 — symlink restrictions", URL: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=800179c9b8a1"},
	},
}

// protectedSymlinks is the parameter, and the three sentences that make the
// shared reading say something specific about it.
var protectedSymlinks = linkProtection{
	key:    "fs.protected_symlinks",
	caveat: persistCaveatFor("KERNEL-0009"),
	unset:  "Any current kernel defaults this to 1, which is correct — but nothing on this host records that, and a drop-in setting 0 would restore the classic /tmp symlink race against every privileged program that opens a predictable path, including the ones nobody here wrote or audited.",
	on:     "a symlink in a world-writable sticky directory such as /tmp is only followed when the follower owns the link or owns the directory, which makes the classic race unwinnable no matter how the privileged program was written.",
	off:    "a privileged program that opens a path in /tmp by name will follow a symlink an unprivileged user planted there, which is the classic local privilege escalation and works against every program that has not defended itself individually.",
}

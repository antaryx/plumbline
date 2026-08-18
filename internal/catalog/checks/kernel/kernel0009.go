package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0009 tests that symlinks in world-writable sticky directories are
// protected.
var Check0009 = catalog.Check{
	ID:     "KERNEL-0009",
	Module: "KERNEL",
	Title:  "Symlink following is restricted in world-writable directories",
	Description: `The oldest reliable local privilege escalation on Unix is to
plant a symlink in /tmp pointing at a file you cannot write, and wait for a
privileged program to open it by name. The privileged program follows the link
and writes where the attacker chose.

fs.protected_symlinks set to 1 makes the kernel refuse to follow a symlink in a
world-writable sticky directory unless the follower owns the link, or the
directory owner owns it. That breaks the attack at the point of use, without
requiring every privileged program in the distribution to be audited for the
race it depends on.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "filesystem", "privilege-escalation", "toctou"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"fs.protected_symlinks",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			if ok {
				return fmt.Sprintf("fs.protected_symlinks is %d; symlinks in world-writable sticky directories are only followed when the follower or the directory owner owns the link.", n)
			}
			return "fs.protected_symlinks is 0; a privileged program that opens a path in /tmp by name will follow a symlink an unprivileged user planted there, which is the classic local privilege escalation this setting exists to break."
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set fs.protected_symlinks to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w fs.protected_symlinks=1",
			"Persist it: write 'fs.protected_symlinks = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl fs.protected_symlinks",
		},
		Commands: []string{
			"sysctl -w fs.protected_symlinks=1",
			"sysctl fs.protected_symlinks",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation — fs.protected_symlinks", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks"},
	},
}

package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0010 tests that hardlink creation is restricted.
var Check0010 = catalog.Check{
	ID:     "KERNEL-0010",
	Module: "KERNEL",
	Title:  "Hardlink creation is restricted to files the user can already read",
	Description: `Without this restriction, any user may create a hardlink to any
file whose directory they can write, including files they cannot read. That
turns two harmless-looking permissions into an attack: link a shadow file or a
setuid binary into a directory you control, wait for a privileged process or a
package upgrade to act on it, and inherit the result. It also defeats quota and
retention controls, because the original file cannot be freed while the
attacker's link exists.

fs.protected_hardlinks set to 1 permits a hardlink only when the user owns the
source file, or can both read and write it.`,

	// High from catalog 33, raised to meet KERNEL-0030 on the same parameter,
	// and matching KERNEL-0009 for the reason KERNEL-0031 matches KERNEL-0030:
	// the two protections close halves of one problem and splitting their
	// severity would be arbitrary. Turning this off lets an unprivileged user
	// park a link to a file they cannot read at a path a privileged job will
	// act on, which is a class of local privilege escalation rather than an
	// instance of one.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "filesystem", "privilege-escalation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"fs.protected_hardlinks",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			if ok {
				return fmt.Sprintf("fs.protected_hardlinks is %d; a hardlink may only be created to a file the user owns or can read and write.", n)
			}
			return "fs.protected_hardlinks is 0; any user may hardlink a file they cannot read into a directory they control, which preserves the file's contents and permissions somewhere a privileged process may later act on."
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set fs.protected_hardlinks to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w fs.protected_hardlinks=1",
			"Persist it: write 'fs.protected_hardlinks = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl fs.protected_hardlinks",
			"If a backup or deduplication tool starts failing, it is hardlinking files it cannot read and should run with the ownership or capability that entitles it to.",
		},
		Commands: []string{
			"sysctl -w fs.protected_hardlinks=1",
			"sysctl fs.protected_hardlinks",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation, fs.protected_hardlinks", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-hardlinks"},
	},
}

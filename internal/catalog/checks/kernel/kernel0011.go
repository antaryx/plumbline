package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0011 tests that opening someone else's FIFO in a shared directory is
// restricted.
var Check0011 = catalog.Check{
	ID:     "KERNEL-0011",
	Module: "KERNEL",
	Title:  "Opening another user's FIFO in a shared directory is restricted",
	Description: `A program that creates a file in /tmp with O_CREAT gets whatever
is already at that path. If an attacker put a FIFO there first, the program
does not create a file — it opens the attacker's pipe. Writing to it blocks
until the attacker chooses to read, which hangs the program; reading from it
returns whatever the attacker decided to supply, which the program then trusts
as its own data.

fs.protected_fifos set to 1 refuses an O_CREAT open of a FIFO the caller does
not own inside a world-writable sticky directory. Set to 2 the restriction also
covers group-writable sticky directories.

The parameter appeared in Linux 4.19 and does not exist on kernels older than
that, where this check is NOT_APPLICABLE.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "filesystem", "toctou", "denial-of-service"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"fs.protected_fifos",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "fs.protected_fifos is 1; an O_CREAT open of another user's FIFO in a world-writable sticky directory is refused."
			case ok:
				return fmt.Sprintf("fs.protected_fifos is %d; the restriction covers group-writable sticky directories as well as world-writable ones.", n)
			default:
				return "fs.protected_fifos is 0; a program creating a file in a shared directory may instead open a FIFO an attacker planted at that path, which lets the attacker block it indefinitely or feed it data of their choosing."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set fs.protected_fifos to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w fs.protected_fifos=1",
			"Persist it: write 'fs.protected_fifos = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl fs.protected_fifos",
			"Consider 2 if nothing on this host relies on group-writable shared directories.",
		},
		Commands: []string{
			"sysctl -w fs.protected_fifos=1",
			"sysctl fs.protected_fifos",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-5"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation — fs.protected_fifos", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-fifos"},
	},
}

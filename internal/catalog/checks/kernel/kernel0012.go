package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0012 tests that opening someone else's regular file in a shared
// directory is restricted.
var Check0012 = catalog.Check{
	ID:     "KERNEL-0012",
	Module: "KERNEL",
	Title:  "Opening another user's file in a shared directory is restricted",
	Description: `This is the same weakness KERNEL-0011 covers, for ordinary files
rather than FIFOs. A privileged program creating a predictably named file in
/tmp with O_CREAT will happily open a file an attacker created there first,
then write its output into a file the attacker owns and can read afterwards,
or read the attacker's content believing it to be its own.

fs.protected_regular set to 1 refuses an O_CREAT open of a regular file the
caller does not own, in a world-writable sticky directory, when the file's owner
differs from the directory's owner. Set to 2 the restriction also covers
group-writable sticky directories.

The parameter appeared in Linux 4.19 and does not exist on kernels older than
that, where this check is NOT_APPLICABLE.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "filesystem", "toctou", "information-disclosure"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"fs.protected_regular",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "fs.protected_regular is 1; an O_CREAT open of another user's file in a world-writable sticky directory is refused."
			case ok:
				return fmt.Sprintf("fs.protected_regular is %d; the restriction covers group-writable sticky directories as well as world-writable ones.", n)
			default:
				return "fs.protected_regular is 0; a program creating a file in a shared directory may instead open one an attacker planted at that path, writing its output somewhere the attacker can read it or reading content the attacker supplied."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set fs.protected_regular to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w fs.protected_regular=1",
			"Persist it: write 'fs.protected_regular = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl fs.protected_regular",
			"Consider 2 if nothing on this host relies on group-writable shared directories.",
		},
		Commands: []string{
			"sysctl -w fs.protected_regular=1",
			"sysctl fs.protected_regular",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation, fs.protected_regular", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-regular"},
	},
}

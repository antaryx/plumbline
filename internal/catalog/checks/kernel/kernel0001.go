package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests that full address-space layout randomisation is enabled.
var Check0001 = catalog.Check{
	ID:     "KERNEL-0001",
	Module: "KERNEL",
	Title:  "Address-space layout randomisation is fully enabled",
	Description: `Address-space layout randomisation places the stack, the heap,
shared libraries and, for position-independent executables, the program image
itself at addresses that differ on every execution. Without it, an attacker who
finds a memory-corruption bug knows in advance where everything is, and a
crash-only bug becomes reliable code execution.

kernel.randomize_va_space takes three values. 0 disables randomisation
entirely. 1 randomises the stack, the shared libraries and the mmap base but
leaves the heap where the linker put it, which leaves heap-grooming attacks
intact. 2 also randomises the brk-managed heap and is the value every
current distribution ships.`,

	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "memory-protection", "exploit-mitigation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"kernel.randomize_va_space",
		func(n int) bool { return n == 2 },
		func(n int) finding.Severity {
			// Partial randomisation is materially better than none, and the
			// severity says so rather than treating every non-2 alike.
			if n == 1 {
				return finding.Medium
			}
			return finding.High
		},
		func(n int, ok bool) string {
			switch {
			case ok:
				return "kernel.randomize_va_space is 2; the stack, heap, shared libraries and mmap base are all randomised."
			case n == 1:
				return "kernel.randomize_va_space is 1; the stack, shared libraries and mmap base are randomised but the brk-managed heap is not, which leaves heap layout predictable to an attacker."
			case n == 0:
				return "kernel.randomize_va_space is 0; address-space layout randomisation is disabled entirely and every mapping is at a predictable address."
			default:
				return fmt.Sprintf("kernel.randomize_va_space is %d, which is not one of the documented values 0, 1 or 2; the kernel's behaviour for this value is not specified.", n)
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.randomize_va_space to 2 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w kernel.randomize_va_space=2",
			"Persist it: write 'kernel.randomize_va_space = 2' to /etc/sysctl.d/60-hardening.conf",
			"Confirm the file is applied at boot: sysctl --system",
			"Verify the running value: sysctl kernel.randomize_va_space",
		},
		Commands: []string{
			"sysctl -w kernel.randomize_va_space=2",
			"sysctl kernel.randomize_va_space",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "proc(5), /proc/sys/kernel/randomize_va_space", URL: "https://man7.org/linux/man-pages/man5/proc.5.html"},
	},
}

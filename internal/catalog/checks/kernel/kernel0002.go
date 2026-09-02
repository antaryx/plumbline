package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests that kernel pointers are hidden from unprivileged readers.
var Check0002 = catalog.Check{
	ID:     "KERNEL-0002",
	Module: "KERNEL",
	Title:  "Kernel pointers are not exposed to unprivileged users",
	Description: `Kernel virtual addresses printed in /proc/kallsyms, /proc/modules
and various other interfaces tell an attacker where the kernel actually is in
memory. That is precisely the information kernel address-space layout
randomisation exists to withhold, and leaking it turns a local privilege
escalation that would have needed an information leak into one that does not.

kernel.kptr_restrict takes three values. 0 prints addresses to everyone. 1
replaces them with zeros for processes without CAP_SYSLOG. 2 replaces them for
everyone, including root, which is stricter and occasionally breaks
profiling tools such as perf.`,

	// High from catalog 33, raised to meet KERNEL-0018 on the same parameter.
	//
	// The two disagreed by a band because the persistence check was written
	// under an argument — a boundary scheduled to fall down outranks one you
	// can see today — that catalog 32's runtime tiering retired. With it gone
	// the parameter needs one severity, and Medium was the wrong one to keep:
	// kptr_restrict at 0 hands the kernel's layout to any local account
	// through a text file, which is a KASLR defeat by exactly the mechanism
	// KERNEL-0004 was re-rated to High for at catalog 27. Two checks on two
	// parameters that break the same mitigation the same way should not be
	// rated a band apart.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "information-disclosure", "exploit-mitigation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"kernel.kptr_restrict",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "kernel.kptr_restrict is 1; kernel pointers are hidden from processes without CAP_SYSLOG."
			case ok:
				return fmt.Sprintf("kernel.kptr_restrict is %d; kernel pointers are hidden from all users.", n)
			default:
				return "kernel.kptr_restrict is 0; kernel virtual addresses are printed in full to any user that can read /proc/kallsyms, which discloses the kernel's memory layout."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.kptr_restrict to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w kernel.kptr_restrict=1",
			"Persist it: write 'kernel.kptr_restrict = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl kernel.kptr_restrict",
			"If profiling tools stop resolving symbols, they need CAP_SYSLOG rather than a lower setting.",
		},
		Commands: []string{
			"sysctl -w kernel.kptr_restrict=1",
			"sysctl kernel.kptr_restrict",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation, kptr_restrict", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict"},
	},
}

package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests that ptrace is restricted by the Yama LSM.
var Check0003 = catalog.Check{
	ID:     "KERNEL-0003",
	Module: "KERNEL",
	Title:  "Debugging other processes with ptrace is restricted",
	Description: `ptrace lets one process read and write another's memory. With
the default permissive policy, any process may attach to any other process
running as the same user, so a single compromised program can read the
credentials, session tokens and private keys held by every other program that
user is running, without needing a privilege escalation at all.

The Yama LSM's kernel.yama.ptrace_scope restricts this. 0 is classic
permissive behaviour. 1 allows attachment only to a process's own descendants,
which is what a debugger launching its target does. 2 requires CAP_SYS_PTRACE.
3 disables ptrace entirely until reboot and cannot be lowered again.

Yama is not compiled into every kernel. Where it is absent this check is
NOT_APPLICABLE rather than a failure: there is no parameter to set, and the
restriction has to come from somewhere else.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "lsm", "credential-theft", "lateral-movement"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"kernel.yama.ptrace_scope",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "kernel.yama.ptrace_scope is 1; a process may only attach to its own descendants."
			case ok && n == 2:
				return "kernel.yama.ptrace_scope is 2; attaching requires CAP_SYS_PTRACE."
			case ok && n == 3:
				return "kernel.yama.ptrace_scope is 3; ptrace attachment is disabled entirely and cannot be re-enabled without a reboot."
			case ok:
				return fmt.Sprintf("kernel.yama.ptrace_scope is %d, which restricts ptrace attachment.", n)
			default:
				return "kernel.yama.ptrace_scope is 0; any process may attach to any other process of the same user and read its memory, including credentials and keys held by unrelated programs."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.yama.ptrace_scope to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what relies on cross-process attachment first: debuggers attaching to already-running processes, and some crash reporters, need scope 0 or CAP_SYS_PTRACE.",
			"Apply immediately: sysctl -w kernel.yama.ptrace_scope=1",
			"Persist it: write 'kernel.yama.ptrace_scope = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl kernel.yama.ptrace_scope",
		},
		Commands: []string{
			"sysctl -w kernel.yama.ptrace_scope=1",
			"sysctl kernel.yama.ptrace_scope",
		},
		Caution: "Value 3 is irreversible until the machine reboots. Do not set 3 unless you are certain nothing on the host needs ptrace, including the crash handlers of services that are not currently running.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-2"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation. Yama ptrace_scope", URL: "https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html"},
	},
}

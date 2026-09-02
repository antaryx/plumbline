package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0006 tests that unprivileged users cannot load BPF programs.
var Check0006 = catalog.Check{
	ID:     "KERNEL-0006",
	Module: "KERNEL",
	Title:  "Unprivileged users cannot load BPF programs",
	Description: `The bpf() system call compiles user-supplied bytecode and runs it
inside the kernel. The verifier that is supposed to prove such a program safe
is one of the most complex pieces of the kernel and has been a recurring source
of local privilege escalations; leaving it reachable by unprivileged users
gives every local account a large and complicated attack surface for no benefit on a
server.

kernel.unprivileged_bpf_disabled set to 1 refuses unprivileged bpf() and cannot
be re-enabled without a reboot. Set to 2 it refuses them but can still be
raised to 1. Set to 0 unprivileged loading is permitted.

The parameter does not exist on kernels built without BPF, where this check is
NOT_APPLICABLE.`,

	// High from catalog 33, raised to meet KERNEL-0017 on the same parameters.
	//
	// KERNEL-0017's own comment recorded the gap and the argument that opened
	// it, and catalog 32 retired that argument. Closing the gap upward rather
	// than downward is the honest direction here: unprivileged BPF loading is
	// an attacker-supplied program run inside the kernel, gated only by a
	// verifier that has been the subject of a long run of local privilege
	// escalations. Every current distribution ships 2 for that reason, so a
	// host at 0 has either an old kernel or a deliberate change, and both are
	// worth more than a Medium.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "bpf", "privilege-escalation", "attack-surface"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"kernel.unprivileged_bpf_disabled",
		func(n int) bool { return n == 1 || n == 2 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "kernel.unprivileged_bpf_disabled is 1; unprivileged bpf() is refused and the setting is locked until reboot."
			case ok:
				return "kernel.unprivileged_bpf_disabled is 2; unprivileged bpf() is refused, and the setting may still be raised to 1 to lock it."
			case n == 0:
				return "kernel.unprivileged_bpf_disabled is 0; any local user may load BPF programs, exposing the in-kernel verifier as a privilege-escalation surface."
			default:
				return fmt.Sprintf("kernel.unprivileged_bpf_disabled is %d, which is not one of the documented values 0, 1 or 2.", n)
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.unprivileged_bpf_disabled to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Confirm nothing unprivileged on this host loads BPF: some observability agents and container runtimes do, though they usually run privileged.",
			"Apply immediately: sysctl -w kernel.unprivileged_bpf_disabled=1",
			"Persist it: write 'kernel.unprivileged_bpf_disabled = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl kernel.unprivileged_bpf_disabled",
		},
		Commands: []string{
			"sysctl -w kernel.unprivileged_bpf_disabled=1",
			"sysctl kernel.unprivileged_bpf_disabled",
		},
		Caution: "Value 1 cannot be lowered again without rebooting. On a host where an unprivileged agent turns out to need bpf(), recovery requires a reboot.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation, unprivileged_bpf_disabled", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled"},
	},
}

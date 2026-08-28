package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests that the kernel ring buffer is restricted to privileged users.
var Check0004 = catalog.Check{
	ID:     "KERNEL-0004",
	Module: "KERNEL",
	Title:  "The kernel ring buffer is not readable by unprivileged users",
	Description: `dmesg output routinely contains kernel addresses, module load
addresses, hardware identifiers, filesystem paths and the register dumps left
by earlier crashes. An unprivileged process that can read it gets a running
commentary on the kernel's internal state, which is the raw material for
defeating address-space randomisation.

kernel.dmesg_restrict set to 1 requires CAP_SYSLOG to read the ring buffer.`,

	// **Re-rated from Low to High at catalog 27**, and the old rating was the
	// mistake rather than this one being an inflation. The reasoning that
	// produced Low read the ring buffer as verbose logging that happens to be
	// untidy; what it actually holds is kernel and module load addresses, and
	// on a host where kptr_restrict is 0 — which is most of them, see
	// KERNEL-0018 — an unprivileged `dmesg` defeats KASLR outright. That is
	// not a step towards an attack, it is the step, and it needs no privilege
	// and leaves no trace.
	//
	// The mismatch surfaced when KERNEL-0019 was written to check the same
	// parameter's *persistence* and rated High: a configuration check
	// outranking the runtime check it persists by two bands says a file
	// matters more than the kernel, which is backwards. One of the two had to
	// move and it was this one.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "information-disclosure"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"kernel.dmesg_restrict",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			if ok {
				return fmt.Sprintf("kernel.dmesg_restrict is %d; reading the kernel ring buffer requires CAP_SYSLOG.", n)
			}
			return "kernel.dmesg_restrict is 0; any user may read the kernel ring buffer, which exposes kernel addresses and hardware detail useful for building an exploit."
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.dmesg_restrict to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w kernel.dmesg_restrict=1",
			"Persist it: write 'kernel.dmesg_restrict = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl kernel.dmesg_restrict",
		},
		Commands: []string{
			"sysctl -w kernel.dmesg_restrict=1",
			"sysctl kernel.dmesg_restrict",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation — dmesg_restrict", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#dmesg-restrict"},
	},
}

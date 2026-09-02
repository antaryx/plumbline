package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0013 tests that unprivileged access to the performance-monitoring
// subsystem is restricted.
var Check0013 = catalog.Check{
	ID:     "KERNEL-0013",
	Module: "KERNEL",
	Title:  "Unprivileged access to performance counters is restricted",
	Description: `perf_event_open() is the entry point to the kernel's
performance-monitoring subsystem. Left open to unprivileged users it is two
problems at once. It is a side channel: hardware performance counters and
instruction sampling leak the behaviour of other processes precisely enough to
recover cryptographic keys, and every speculative-execution attack of the last
decade has used it as a measurement device. It is also a large and historically
fragile piece of kernel code, and has produced its own local privilege
escalations.

kernel.perf_event_paranoid restricts it. -1 imposes no restriction at all.
0 requires CAP_PERFMON for raw tracepoint access, 1 also for CPU-wide events,
and 2 also for kernel profiling. Value 3, refuse
perf_event_open() entirely without CAP_PERFMON, exists only on kernels
carrying the Debian, Ubuntu or Android patch, so this check requires 2 rather
than 3: demanding a value a mainline kernel cannot express would fail hosts
that are configured as strictly as they are able to be.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "side-channel", "information-disclosure", "attack-surface"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"kernel.perf_event_paranoid",
		func(n int) bool { return n >= 2 },
		func(n int) finding.Severity {
			// -1 is not merely "less restricted"; it is the documented value
			// for no restriction whatsoever, including raw tracepoints.
			if n < 0 {
				return finding.High
			}
			return finding.Medium
		},
		func(n int, ok bool) string {
			switch {
			case ok && n >= 3:
				return fmt.Sprintf("kernel.perf_event_paranoid is %d; perf_event_open() is refused entirely without CAP_PERFMON. This value is available only on kernels carrying the Debian, Ubuntu or Android patch.", n)
			case ok:
				return "kernel.perf_event_paranoid is 2; unprivileged users may not profile the kernel, take CPU-wide measurements, or read raw tracepoints."
			case n < 0:
				return "kernel.perf_event_paranoid is -1; the performance-monitoring subsystem is entirely unrestricted, so any local user may profile the kernel and other processes, which is a precise side channel against cryptographic operations."
			case n == 0:
				return "kernel.perf_event_paranoid is 0; unprivileged users may take CPU-wide measurements and profile the kernel, which leaks the behaviour of other processes."
			default:
				return "kernel.perf_event_paranoid is 1; unprivileged users may still profile the kernel, which leaks kernel behaviour and addresses useful for building an exploit."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set kernel.perf_event_paranoid to 2 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what profiles on this host: perf, some eBPF front-ends and several APM agents call perf_event_open(). They should hold CAP_PERFMON rather than rely on a permissive setting.",
			"Apply immediately: sysctl -w kernel.perf_event_paranoid=2",
			"Persist it: write 'kernel.perf_event_paranoid = 2' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl kernel.perf_event_paranoid",
			"On a Debian or Ubuntu kernel, 3 is available and stricter; use it only if nothing on the host profiles at all.",
		},
		Commands: []string{
			"sysctl -w kernel.perf_event_paranoid=2",
			"sysctl kernel.perf_event_paranoid",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
	},

	References: []finding.Reference{
		{Title: "perf_event_open(2), perf_event_paranoid", URL: "https://man7.org/linux/man-pages/man2/perf_event_open.2.html"},
	},
}

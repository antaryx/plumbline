package kernel

import (
	"fmt"
	"strconv"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0022 tests whether unprivileged perf access is restricted, in the
// configuration rather than in the running kernel.
var Check0022 = catalog.Check{
	ID:     "KERNEL-0022",
	Module: "KERNEL",
	Title:  "Perf event restriction is written to the sysctl configuration",

	Description: `perf_event_open is a system call that asks the kernel to
instrument the hardware: cycle counters, cache misses, branch mispredictions,
and the addresses being executed while it counts. It exists for profiling and it
is very good at it, which is the problem, the same measurements that show a
developer where their program spends its time show an attacker what another
process is doing, at instruction granularity.

kernel.perf_event_paranoid decides how much of that an unprivileged process may
ask for:

  - -1, everything, including raw tracepoints and kernel measurements.
  -  0, no raw tracepoint access; CPU events still allowed.
  -  1, no CPU event access for unprivileged users.
  -  2, no kernel profiling. The upstream default since Linux 4.6.
  -  3, no unprivileged perf at all. A Debian and Ubuntu patch, not upstream.

**Below 2 the call is a side-channel primitive and a KASLR oracle.** Kernel
measurements return addresses from the kernel's own execution, which is a direct
read of the layout randomisation is meant to hide; and the counter resolution is
fine enough to have carried practical cache-timing attacks against
cryptographic code in another process. Neither needs a bug, this is the
interface working as documented.

2 is the bar because it is upstream's own default and because 3 does not exist
on a kernel without the Debian patch, so requiring it would fail every RPM-family
host for shipping a kernel that cannot have it. Where 3 is available it is
better, and a host running it is told so rather than merely passed.

This is a check about files. KERNEL-0013 asks what the running kernel does; a
host set with sysctl -w and nothing on disk passes that and reverts at the next
boot.`,

	// Medium. It is a powerful primitive and it is not a boundary: an attacker
	// needs something to measure and something to do with the measurement,
	// which is a real exploitation step that the socket and ptrace findings do
	// not require. It sits below KERNEL-0020 for that reason and above the
	// SysRq check because it needs no console.
	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "sysctl", "persistence", "side-channel"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 28,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{perfKey}, persistPerfCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(perfKey)
		if !found {
			detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so after the next reboot it is whatever the kernel defaults to. Upstream has defaulted to 2 since Linux 4.6, which is adequate — but a default is not a decision, and a kernel built with a lower value, or a boot parameter that lowers it, leaves unprivileged processes able to measure the kernel's own execution.", perfKey)
			if r, ok := sc.Run(perfKey); ok && r.State == fact.SysctlObserved {
				if v, isInt := r.Int(); isInt {
					if v >= 2 {
						detail += fmt.Sprintf(" The running kernel has it at %d, so this host is adequate now on its default and has not written that down.", v)
					} else {
						detail += fmt.Sprintf(" The running kernel has it at %d, which is below the bar as well: unprivileged perf can measure %s right now.", v, perfExposure(v))
					}
				}
			}
			return tierAbsence(catalog.Outcome{
				Result:   finding.Fail,
				Subject:  perfKey,
				Detail:   detail,
				Evidence: searchedEvidence(sc, nil),
			}, sc, perfTiering, persistPerfCaveat)
		}

		level, err := strconv.Atoi(set.Value)
		if err != nil {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       perfKey,
				Detail: fmt.Sprintf("%s is %q at %s:%d, which is not a number. What the kernel does with a value it cannot parse depends on the build, so what this host allows after a reboot cannot be determined from the file.%s",
					perfKey, set.Value, set.File, set.Line, persistPerfCaveat),
				Evidence: configuredEvidence(sc, perfKey),
			}
		}

		if level >= 3 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: perfKey,
				Detail: fmt.Sprintf("%s is %d at %s:%d, so unprivileged processes may not call perf_event_open at all. That is stricter than upstream's own default of 2 and is available only on a kernel carrying the Debian and Ubuntu patch, so it is a deliberate choice rather than an inherited one.%s%s",
					perfKey, level, set.File, set.Line, runningMismatch(sc, perfKey, set.Value), persistPerfCaveat),
				Evidence: configuredEvidence(sc, perfKey),
			}
		}
		if level == 2 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: perfKey,
				Detail: fmt.Sprintf("%s is 2 at %s:%d, so unprivileged processes may not profile the kernel — which is what closes the address oracle — and the setting survives a reboot. 3 is stricter and exists only on Debian-family kernels.%s%s",
					perfKey, set.File, set.Line, runningMismatch(sc, perfKey, set.Value), persistPerfCaveat),
				Evidence: configuredEvidence(sc, perfKey),
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: perfKey,
			Detail: fmt.Sprintf("%s is %d at %s:%d, which is written down and below upstream's own default of 2. Unprivileged processes may measure %s, which is a KASLR oracle and a side-channel primitive rather than a bug to be exploited.%s%s",
				perfKey, level, set.File, set.Line, perfExposure(level),
				runningMismatch(sc, perfKey, set.Value), persistPerfCaveat),
			Evidence: configuredEvidence(sc, perfKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.perf_event_paranoid = 2 to a file in /etc/sysctl.d/, or 3 on a Debian-family kernel.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn perf_event_paranoid /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d.",
			"Create or extend a drop-in containing kernel.perf_event_paranoid = 2. Write it down even if the running kernel already reports 2: upstream's default is not a decision, and a kernel rebuild or a boot parameter can lower it without anything on this host changing.",
			"Use 3 on Debian and Ubuntu, where the patch exists, unless something on the host profiles as a non-root user. On an RPM-family kernel 3 is not available and setting it does nothing useful.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.perf_event_paranoid.",
			"Find out what profiles before restricting it. perf, bpftrace, some APM agents and Java Flight Recorder all use perf_event_open; at 2 a non-root user can still profile their own userspace processes, and at 3 they cannot profile at all. The usual answer for a legitimate profiler is CAP_PERFMON on the unit rather than lowering the value host-wide.",
		},
		Commands: []string{
			"sysctl kernel.perf_event_paranoid",
			"grep -rn perf_event_paranoid /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Unprivileged profiling stops working. perf top, bpftrace and Java Flight Recorder are the usual casualties, and at 3 they stop for everyone without CAP_PERFMON. Grant the capability to the units that need it rather than lowering the value for the whole host.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, perf_event_paranoid", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#perf-event-paranoid"},
		{Title: "perf_event_open(2)", URL: "https://man7.org/linux/man-pages/man2/perf_event_open.2.html"},
	},
}

const perfKey = "kernel.perf_event_paranoid"

// persistPerfCaveat names the check that reads the running value.
var persistPerfCaveat = persistCaveatFor("KERNEL-0013")

// perfExposure renders what a level below 2 leaves reachable, so the finding
// says what an attacker gets rather than that the number is too low.
func perfExposure(level int) string {
	switch {
	case level < 0:
		return "the kernel's own execution and raw tracepoints, which is a direct read of the layout KASLR randomises"
	case level == 0:
		return "CPU events and the kernel's own execution, which is a direct read of the layout KASLR randomises"
	default:
		return "the kernel's own execution, which is a direct read of the layout KASLR randomises"
	}
}

// perfTiering is the runtime cross-reference for the absence case.
var perfTiering = []requirement{{key: perfKey, accept: func(n int) bool { return n >= 2 }}}

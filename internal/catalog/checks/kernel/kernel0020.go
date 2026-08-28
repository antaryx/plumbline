package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0020 tests whether ptrace restriction survives a reboot.
var Check0020 = catalog.Check{
	ID:     "KERNEL-0020",
	Module: "KERNEL",
	Title:  "Yama ptrace restriction is written to the sysctl configuration",

	Description: `ptrace lets one process read and write another's memory. That
is what a debugger is, and it is also what credential theft is: an attacker who
lands as an ordinary user and finds a browser, an ssh-agent, a password manager
or a running deployment script belonging to the same uid can read the secrets
out of it without any privilege escalation at all, and can write instructions
into it without dropping a file on disk.

The Yama LSM gates that, and kernel.yama.ptrace_scope chooses how far:

  - 0 — classic behaviour. Any process may trace any other with the same uid.
  - 1 — a process may trace only its own descendants, unless the target has
        opted in with PR_SET_PTRACER.
  - 2 — only a process with CAP_SYS_PTRACE may trace anything.
  - 3 — no process may trace another, ever, and the value cannot be lowered
        without a reboot.

**Anything above 0 passes**, because the right level depends on what the host
runs and a system that chose 1 deliberately is not the problem this exists to
find. 1 is enough to stop the sideways read that matters: a compromised
process cannot reach into an unrelated one belonging to the same user, which
is the whole of the credential-theft path above.

This is a check about files. KERNEL-0003 asks what the running kernel does; a
host hardened with sysctl -w and nothing on disk passes that and reverts at the
next boot, and KERNEL-0007 does not see it because a parameter no file mentions
has nothing to drift from.

**A kernel without Yama is not a failure.** The parameter does not exist unless
the LSM is built in and enabled, and asking a file to set a parameter the
kernel does not implement would be asking for a line that does nothing.`,

	// High, matching the other persistence checks in this group and above
	// KERNEL-0003's Medium for the reason given there: a boundary scheduled to
	// fall down at the next reboot, on a host whose runtime check passes, is
	// worth more than one an operator can see today.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "credential-access"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 27,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{ptraceKey}, persistPtraceCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(ptraceKey)
		if !found {
			detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so after the next reboot ptrace scope is whatever the kernel defaults to — 0 on most builds, meaning any process may read and write the memory of any other process owned by the same user.", ptraceKey)
			if r, ok := sc.Run(ptraceKey); ok && r.State == fact.SysctlObserved {
				if v, isInt := r.Int(); isInt && v > 0 {
					detail += fmt.Sprintf(" The running kernel has it at %d, so this host is protected now and will not be after the next reboot unless something sets it again outside these files.", v)
				}
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  ptraceKey,
				Detail:   detail + persistPtraceCaveat,
				Evidence: searchedEvidence(sc, nil),
			}
		}

		switch set.Value {
		case "1", "2", "3":
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: ptraceKey,
				Detail: fmt.Sprintf("%s is %s at %s:%d, so %s, and it stays that way across a reboot.%s%s",
					ptraceKey, set.Value, set.File, set.Line, ptraceLevels[set.Value],
					runningMismatch(sc, ptraceKey, set.Value), persistPtraceCaveat),
				Evidence: configuredEvidence(sc, ptraceKey),
			}

		case "0":
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: ptraceKey,
				Detail: fmt.Sprintf("%s is 0 at %s:%d, which is the classic behaviour: any process may attach to any other owned by the same user and read or write its memory. An attacker who lands as an ordinary user reads the secrets out of a browser, an ssh-agent or a running deployment script without escalating at all, and writes into one without dropping a file on disk. Setting it to 1 stops that and still allows a debugger to trace its own children.%s%s",
					ptraceKey, set.File, set.Line, runningMismatch(sc, ptraceKey, "0"), persistPtraceCaveat),
				Evidence: configuredEvidence(sc, ptraceKey),
			}
		}

		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonAmbiguousState,
			Subject:       ptraceKey,
			Detail: fmt.Sprintf("%s is %q at %s:%d, which is not one of the documented values 0, 1, 2 or 3. What Yama does with it depends on the kernel build, so what this host allows after a reboot cannot be determined from the file.%s",
				ptraceKey, set.Value, set.File, set.Line, persistPtraceCaveat),
			Evidence: configuredEvidence(sc, ptraceKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.yama.ptrace_scope = 1 to a file in /etc/sysctl.d/ and apply it.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn ptrace_scope /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. Ubuntu ships 1 in a vendor file; most others ship nothing.",
			"Create or extend a drop-in containing kernel.yama.ptrace_scope = 1. That is the level to start at: it stops a process reading an unrelated one owned by the same user, and leaves an ordinary debugger able to trace the children it started.",
			"Go to 2 only where no unprivileged debugging happens at all, and to 3 only where nothing debugs anything — 3 cannot be lowered again without a reboot, which is the point of it and also the reason to be sure.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.yama.ptrace_scope.",
			"Check what debugs what before rolling it out. gdb attaching to a running process, strace on something already started, and some crash reporters and profilers all use ptrace across the process tree. Under 1 the answer for a legitimate debugger is usually to start the target from it rather than attach, or PR_SET_PTRACER on the target.",
		},
		Commands: []string{
			"sysctl kernel.yama.ptrace_scope",
			"grep -rn ptrace_scope /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Attaching a debugger or strace to an already-running process stops working for unprivileged users at 1 and for everyone without CAP_SYS_PTRACE at 2. Crash reporters and APM agents are the usual casualties. Level 3 cannot be undone without rebooting.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — Yama ptrace_scope", URL: "https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const ptraceKey = "kernel.yama.ptrace_scope"

// persistPtraceCaveat names the check that reads the running value.
var persistPtraceCaveat = persistCaveatFor("KERNEL-0003")

// ptraceLevels renders what each accepted level actually restricts, so a pass
// says what the host is protected from rather than repeating the number.
var ptraceLevels = map[string]string{
	"1": "a process may trace only its own descendants and one that opted in with PR_SET_PTRACER",
	"2": "only a process holding CAP_SYS_PTRACE may trace anything",
	"3": "no process may trace another at all, and the value cannot be lowered again without a reboot",
}

// runningMismatch adds the running value when it differs from the configured
// one, which is drift and belongs to KERNEL-0007 — but a reader of a
// persistence check has just been told what the file says and needs to know
// whether it is true yet.
func runningMismatch(sc fact.Sysctl, key, configured string) string {
	r, ok := sc.Run(key)
	if !ok || r.State != fact.SysctlObserved || r.Value == configured {
		return ""
	}
	return fmt.Sprintf(" The running kernel has it at %s, which does not match the file; see KERNEL-0007.", r.Value)
}

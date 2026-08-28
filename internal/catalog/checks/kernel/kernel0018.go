package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0018 tests whether kernel pointers are hidden from everyone, in the
// configuration rather than in the running kernel.
var Check0018 = catalog.Check{
	ID:     "KERNEL-0018",
	Module: "KERNEL",
	Title:  "Kernel pointer restriction is written to the sysctl configuration",

	Description: `KASLR moves the kernel's text and data to a different address
on every boot, so an attacker with a memory-corruption bug does not know where
to aim. **Every one of those addresses is useless the moment the kernel prints
a pointer to user space**, because one leaked pointer gives away the offset and
the whole layout with it.

kptr_restrict decides who gets to see them, and it has three settings:

  - 0 — %pK prints the real address. Anything that reads /proc/kallsyms,
        /proc/modules, /proc/timer_list or a dozen other files learns the
        layout.
  - 1 — the address is printed as zeros unless the reader holds CAP_SYSLOG.
  - 2 — the address is printed as zeros for everyone, privileged or not.

**1 is the value that looks safe and is not, which is why this check asks for
2.** CAP_SYSLOG is not a rare thing to hold: a container given it for logging,
a monitoring agent, anything that reads the kernel ring buffer. Under 1 all of
those defeat KASLR for the whole host, and the leak is a read of a text file
rather than an exploit. 2 removes the distinction.

This is a check about files. KERNEL-0002 asks what the running kernel does; this
asks whether it will still do it after a reboot, which is a different question
and is not covered by KERNEL-0007 either — that compares running against
configured and skips a parameter no file mentions, because there is nothing to
compare it against.

**Expect this to fail on a stock distribution.** Ubuntu ships
kernel.kptr_restrict = 1 in /usr/lib/sysctl.d and most others ship nothing at
all. A host at 1 has done something and not enough, and is reported one severity
band below a host that has done nothing — the finding is the same and the
conversation is not.`,

	// High, matching KERNEL-0017 and above KERNEL-0002's Medium for the reason
	// KERNEL-0017 sits above KERNEL-0006: a boundary scheduled to fall down at
	// the next reboot, on a host whose runtime check passes, is worth more
	// than one an operator can see today. The value-1 case is overridden to
	// Medium below.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "information-disclosure", "kaslr"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 26,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{kptrKey}, persistKptrCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(kptrKey)
		if !found {
			return tierAbsence(catalog.Outcome{
				Result:   finding.Fail,
				Subject:  kptrKey,
				Detail:   kptrMissingDetail(sc),
				Evidence: searchedEvidence(sc, nil),
			}, sc, kptrTiering, persistKptrCaveat)
		}

		switch set.Value {
		case "2":
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: kptrKey,
				Detail: fmt.Sprintf("%s is 2 at %s:%d, so %%pK prints zeros for every reader, privileged or not, and a leaked pointer cannot give away the kernel's layout after the next reboot.%s%s",
					kptrKey, set.File, set.Line, kptrRunningNote(sc, "2"), persistKptrCaveat),
				Evidence: configuredEvidence(sc, kptrKey),
			}

		case "1":
			// Written down, and at the value that still hands the layout to
			// anything holding CAP_SYSLOG. A band below the host that
			// configured nothing: the same finding, and not the same
			// conversation. The precedent is CONTAINERS-0006's loopback
			// override.
			return catalog.Outcome{
				Result:   finding.Fail,
				Severity: finding.Medium,
				Subject:  kptrKey,
				Detail: fmt.Sprintf("%s is 1 at %s:%d, so kernel pointers are hidden from ordinary readers and printed in full to anything holding CAP_SYSLOG — a container granted it for logging, a monitoring agent, anything that reads the ring buffer. One such reader defeats KASLR for the whole host with a read of a text file. Set it to 2, which removes the distinction.%s%s",
					kptrKey, set.File, set.Line, kptrRunningNote(sc, "1"), persistKptrCaveat),
				Evidence: configuredEvidence(sc, kptrKey),
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: kptrKey,
			Detail: fmt.Sprintf("%s is %s at %s:%d. Anything other than 2 prints kernel addresses to some reader — 0 to everyone, 1 to anything holding CAP_SYSLOG — and one leaked pointer gives away the offset KASLR randomised.%s%s",
				kptrKey, set.Value, set.File, set.Line, kptrRunningNote(sc, set.Value), persistKptrCaveat),
			Evidence: configuredEvidence(sc, kptrKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.kptr_restrict = 2 to a file in /etc/sysctl.d/ and apply it.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it first: grep -rn kptr_restrict /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. On Ubuntu a vendor file sets 1, and a drop-in in /etc/sysctl.d overrides it only because /etc is walked after /usr/lib — number yours above whatever you find.",
			"Create /etc/sysctl.d/60-kptr.conf containing kernel.kptr_restrict = 2.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.kptr_restrict.",
			"Establish what breaks before rolling it out widely. perf, systemtap, bcc/bpftrace and some crash-dump tooling read kernel symbols, and at 2 they see zeros even as root. Where a profiler is genuinely needed, 1 with a tightly held CAP_SYSLOG is a defensible position — record it as an exception rather than leaving the file unset.",
			"Verify what actually took effect: systemd-analyze cat-config sysctl.d shows the merged configuration in application order on a systemd host.",
		},
		Commands: []string{
			"sysctl kernel.kptr_restrict",
			"grep -rn kptr_restrict /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "At 2 kernel addresses read as zeros for root as well, which breaks perf, bpftrace and kernel crash analysis. Test the tooling this host depends on before setting it fleet-wide; the setting is trivial to apply and the breakage appears the next time somebody profiles something.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — kptr_restrict", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const kptrKey = "kernel.kptr_restrict"

// persistKptrCaveat names the check that reads the running value.
var persistKptrCaveat = persistCaveatFor("KERNEL-0002")

// kptrMissingDetail renders the failure for a parameter no file sets, leading
// with the trap: hardened now, unhardened after a reboot, and every other
// KERNEL check reporting the host as fine.
func kptrMissingDetail(sc fact.Sysctl) string {
	detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so the value after the next reboot is whatever the kernel defaults to — which on most builds is 0, printing kernel addresses to every local reader.", kptrKey)
	if r, ok := sc.Run(kptrKey); ok && r.State == fact.SysctlObserved {
		if v, isInt := r.Int(); isInt && v > 0 {
			detail += fmt.Sprintf(" The running kernel has it at %d, so this host is protected now and will not be after the next reboot unless something sets it again outside these files.", v)
		}
	}
	return detail
}

// kptrRunningNote adds the running value when it differs from the configured
// one, which is drift and belongs to KERNEL-0007 — but a reader of this check
// has just been told what the file says and needs to know it is not yet true.
func kptrRunningNote(sc fact.Sysctl, configured string) string {
	r, ok := sc.Run(kptrKey)
	if !ok || r.State != fact.SysctlObserved {
		return ""
	}
	if r.Value == configured {
		return ""
	}
	return fmt.Sprintf(" The running kernel has it at %s, which does not match the file; see KERNEL-0007.", r.Value)
}

// kptrTiering is the runtime cross-reference for the absence case.
//
// It accepts only 2, which is what this check accepts in a file. 1 is the
// "insufficient effort" value this check already reports at MEDIUM when it is
// written down, and a running 1 should not buy a downgrade for a file that
// says nothing.
var kptrTiering = []requirement{{key: kptrKey, accept: func(n int) bool { return n == 2 }}}

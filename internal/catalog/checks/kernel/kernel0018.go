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

**1 is the baseline and 2 is the hardened position.** 1 closes the
unprivileged leak, which is the exposure: an ordinary local account reads zeros.
What it leaves open is CAP_SYSLOG, and that is not a rare thing to hold — a
container given it for logging, a monitoring agent, anything that reads the ring
buffer. 2 removes the distinction, at a cost this check does not get to impose:
perf, bpftrace and crash analysis see zeros as root too.

So 1 and 2 both pass and the verdict says which one is there. **Until catalog 33
a configured 1 failed here**, on the same host where KERNEL-0002 passed the
identical running value — one report carrying a PASS and a FAIL about one
number. The runtime check was the one describing the exposure correctly, and
this one now agrees with it.

This is a check about files. KERNEL-0002 asks what the running kernel does; this
asks whether it will still do it after a reboot, which is a different question
and is not covered by KERNEL-0007 either — that compares running against
configured and skips a parameter no file mentions, because there is nothing to
compare it against.

**Expect a stock distribution to pass or to say nothing.** Ubuntu and Debian
ship kernel.kptr_restrict = 1 in a vendor file and Red Hat ships it in
50-redhat.conf; those pass. Distributions that ship nothing fail, and if their
running kernel is already at 1 or 2 the failure is reported at LOW, because what
is missing there is the record rather than the protection.`,

	// High, and KERNEL-0002 was raised to match it at catalog 33 rather than
	// this one being lowered to match KERNEL-0002.
	//
	// The old comment here justified the gap by saying a boundary scheduled to
	// fall down outranks one an operator can see today. Catalog 32's runtime
	// tiering retired that argument — it is now the case that gets downgraded,
	// not promoted — which left the two checks on this parameter a band apart
	// for no reason at all. One severity per parameter, and this is it: what
	// this check fails on is kptr_restrict at 0, which hands the kernel's
	// layout to any local reader through a text file. That is the same KASLR
	// defeat KERNEL-0004 was re-rated to High for at catalog 27, by the same
	// mechanism, and rating it differently here would be arbitrary.
	//
	// There is no longer a severity override below: the value that used to
	// take one — a configured 1 — passes.
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
			// A pass, and the verdict says what it does not cover. This is the
			// value every mainstream distribution ships, and it is the one
			// KERNEL-0002 passes on the running kernel — a file recording it
			// is a host that has written down the protection it is running.
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: kptrKey,
				Detail: fmt.Sprintf("%s is 1 at %s:%d, so %%pK prints zeros to every reader without CAP_SYSLOG, and it stays that way across a reboot. That closes the unprivileged leak: an ordinary local account reading /proc/kallsyms or /proc/modules learns nothing about the layout. It leaves CAP_SYSLOG holders — a container granted it for logging, a monitoring agent — reading pointers in full; 2 removes that distinction, at the cost of showing zeros to root as well and breaking perf, bpftrace and crash analysis with it.%s%s",
					kptrKey, set.File, set.Line, kptrRunningNote(sc, "1"), persistKptrCaveat),
				Evidence: configuredEvidence(sc, kptrKey),
			}

		case "0":
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: kptrKey,
				Detail: fmt.Sprintf("%s is 0 at %s:%d, so %%pK prints real kernel addresses to every local reader — /proc/kallsyms, /proc/modules, /proc/timer_list and a dozen other files — and one of them gives away the offset KASLR randomised. It is written down, so it survives a reboot and a `sysctl -w` will not fix it.%s%s",
					kptrKey, set.File, set.Line, kptrRunningNote(sc, "0"), persistKptrCaveat),
				Evidence: configuredEvidence(sc, kptrKey),
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: kptrKey,
			Detail: fmt.Sprintf("%s is %s at %s:%d, which is not one of the documented values 0, 1 or 2. The kernel refuses a write outside that range, so this line does not apply at boot and the parameter keeps whatever it had — which is the kernel default of 0 on most builds.%s%s",
				kptrKey, set.Value, set.File, set.Line, kptrRunningNote(sc, set.Value), persistKptrCaveat),
			Evidence: configuredEvidence(sc, kptrKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.kptr_restrict = 1 to a file in /etc/sysctl.d/ and apply it; 2 if nothing here profiles the kernel.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it first: grep -rn kptr_restrict /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. On Ubuntu a vendor file sets 1, and a drop-in in /etc/sysctl.d overrides it only because /etc is walked after /usr/lib — number yours above whatever you find.",
			"Create /etc/sysctl.d/60-kptr.conf containing kernel.kptr_restrict = 1. That is what this check requires: it hides pointers from every unprivileged reader, which is the exposure.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.kptr_restrict.",
			"Consider 2 rather than 1 where nothing on the host profiles the kernel. 1 still prints pointers in full to anything holding CAP_SYSLOG, and a container granted it for logging is enough. 2 closes that and is what KSPP recommends.",
			"Establish what breaks before going to 2. perf, systemtap, bcc/bpftrace and some crash-dump tooling read kernel symbols, and at 2 they see zeros even as root. Where a profiler is genuinely needed, 1 with a tightly held CAP_SYSLOG is the documented position rather than a compromise.",
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

// kptrTiering is the runtime cross-reference for the absence case, and it
// restates what this check accepts in a file: 1 or 2.
//
// It accepted only 2 until catalog 33, which was the same disagreement with
// KERNEL-0002 in a second place — and a stricter one, because it meant the
// downgrade never fired on any realistic host. Every mainstream distribution
// runs 1.
var kptrTiering = []requirement{{key: kptrKey, accept: func(n int) bool { return n >= 1 }}}

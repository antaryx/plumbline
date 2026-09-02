package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0019 tests whether the kernel ring buffer is restricted to root, in the
// configuration rather than in the running kernel.
var Check0019 = catalog.Check{
	ID:     "KERNEL-0019",
	Module: "KERNEL",
	Title:  "Kernel ring buffer restriction is written to the sysctl configuration",

	Description: `dmesg is the other end of the same leak KERNEL-0018 describes.
kptr_restrict decides whether a pointer is printed as zeros; dmesg_restrict
decides who may read the buffer those lines are printed into.

At 0 any local user runs dmesg. What they get is not a log so much as a
narrated tour of the kernel's memory: driver initialisation with device
addresses, stack traces from anything that has oopsed since boot, module load
addresses, and, on a host that has not set kptr_restrict, pointers in the
clear. It is also where a great deal of hardware and topology detail lives,
which is reconnaissance rather than exploitation but is reconnaissance an
unprivileged process should not be handed.

At 1 the buffer is readable only with CAP_SYSLOG. There is no third value: this
is a boolean wearing an integer's clothes, so the check is correspondingly
simple.

**The two settings are worth doing together and are separate checks on
purpose.** Restricting dmesg while leaving kptr_restrict at 0 still leaks
pointers through /proc/kallsyms and friends; hiding pointers while leaving
dmesg open still hands over stack traces and the hardware inventory. A host
that has done one and not the other should see one finding, which is what two
checks give it.

This reads the files. KERNEL-0004 asks what the running kernel does.`,

	// High, and level with KERNEL-0004 on the running parameter.
	//
	// This comment used to record an open disagreement: KERNEL-0004 rated the
	// *running* ring buffer Low while this rated the file High, and it argued
	// that the runtime check was the miscalibrated half. It was. KERNEL-0004
	// was re-rated Low to High at catalog 27, and the catalog 33 audit of every
	// runtime/persistence pair found this one already aligned and left it
	// alone — the only pair in the module that needed nothing.
	//
	// What the pair agrees on is the substance: an open ring buffer holds
	// kernel and module load addresses, so an unprivileged `dmesg` defeats
	// KASLR outright. That is not an untidiness in either half.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "information-disclosure"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 26,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{dmesgKey}, persistDmesgCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(dmesgKey)
		if !found {
			detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so after the next reboot the ring buffer is readable by whatever the kernel defaults to — 0 on most builds, meaning any local user can run dmesg and read stack traces, module addresses and the hardware inventory.", dmesgKey)
			if r, ok := sc.Run(dmesgKey); ok && r.State == fact.SysctlObserved && r.Value == "1" {
				detail += " The running kernel has it at 1, so this host is protected now and will not be after the next reboot unless something sets it again outside these files."
			}
			return tierAbsence(catalog.Outcome{
				Result:   finding.Fail,
				Subject:  dmesgKey,
				Detail:   detail,
				Evidence: searchedEvidence(sc, nil),
			}, sc, dmesgTiering, persistDmesgCaveat)
		}

		if set.Value == "1" {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: dmesgKey,
				Detail: fmt.Sprintf("%s is 1 at %s:%d, so the kernel ring buffer requires CAP_SYSLOG to read and stays that way across a reboot.%s%s",
					dmesgKey, set.File, set.Line, dmesgRunningNote(sc, "1"), persistDmesgCaveat),
				Evidence: configuredEvidence(sc, dmesgKey),
			}
		}

		reason := "so any local user can run dmesg"
		if set.Value != "0" {
			reason = fmt.Sprintf("which is not one of the documented values 0 or 1, so what the kernel does with it depends on the build")
		}
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: dmesgKey,
			Detail: fmt.Sprintf("%s is %s at %s:%d, %s and read the stack traces, module load addresses and hardware inventory the kernel has printed since boot.%s%s",
				dmesgKey, set.Value, set.File, set.Line, reason, dmesgRunningNote(sc, set.Value), persistDmesgCaveat),
			Evidence: configuredEvidence(sc, dmesgKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.dmesg_restrict = 1 to a file in /etc/sysctl.d/ and apply it.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn dmesg_restrict /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d.",
			"Create or extend a drop-in, the same file as kernel.kptr_restrict is the natural home, since the two settings close the same leak from opposite ends, containing kernel.dmesg_restrict = 1.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.dmesg_restrict.",
			"Check what reads dmesg as a non-root user before rolling it out. Some hardware-monitoring and crash-reporting agents do; the answer for those is usually CAP_SYSLOG on the unit rather than an open buffer for everyone.",
			"Do KERNEL-0018 at the same time if it is also failing. Restricting dmesg while kernel pointers are still printed in the clear leaves the leak open through /proc/kallsyms, and hiding pointers while dmesg is world-readable leaves the stack traces.",
		},
		Commands: []string{
			"sysctl kernel.dmesg_restrict",
			"grep -rn dmesg_restrict /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "An unprivileged process that legitimately reads dmesg stops working. That is usually a monitoring agent, and the fix is AmbientCapabilities=CAP_SYSLOG on its unit rather than reopening the buffer to everyone.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "AU-9"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, dmesg_restrict", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#dmesg-restrict"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const dmesgKey = "kernel.dmesg_restrict"

// persistDmesgCaveat names the check that reads the running value.
var persistDmesgCaveat = persistCaveatFor("KERNEL-0004")

// dmesgRunningNote adds the running value when it differs from the configured
// one. See kptrRunningNote.
func dmesgRunningNote(sc fact.Sysctl, configured string) string {
	r, ok := sc.Run(dmesgKey)
	if !ok || r.State != fact.SysctlObserved || r.Value == configured {
		return ""
	}
	return fmt.Sprintf(" The running kernel has it at %s, which does not match the file; see KERNEL-0007.", r.Value)
}

// dmesgTiering is the runtime cross-reference for the absence case: the
// requirement this check would have been satisfied by.
var dmesgTiering = []requirement{{key: dmesgKey, accept: func(n int) bool { return n == 1 }}}

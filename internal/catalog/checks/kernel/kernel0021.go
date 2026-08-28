package kernel

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0021 tests whether the magic SysRq key is disabled in the
// configuration.
var Check0021 = catalog.Check{
	ID:     "KERNEL-0021",
	Module: "KERNEL",
	Title:  "The magic SysRq key is disabled in the sysctl configuration",

	Description: `Magic SysRq is a direct line into the kernel from the console.
It bypasses everything above it: no login, no permission check, no audit record,
no userspace at all. That is what makes it valuable when a machine is wedged and
what makes it a liability the rest of the time.

kernel.sysrq is a bitmask, and the functions it can enable are not equivalent:

  - 2   — change the console log level, which can silence kernel logging
  - 4   — keyboard control, including turning off raw mode
  - 8   — debugging dumps: registers, memory, every task's stack
  - 16  — sync all filesystems
  - 32  — remount everything read-only
  - 64  — signal processes, including SIGKILL to every task
  - 128 — reboot or power off immediately
  - 256 — renice all real-time tasks

0 disables the lot; 1 enables the lot. **The dangerous half is not the reboot.**
It is 8, which dumps kernel memory and task state to the console and defeats
address-space randomisation in one keystroke, and 2, which turns the logging
level down far enough that what happens next is not recorded. 64 lets an
attacker at the console kill the audit daemon before doing anything else.

**This needs console access, which is why it is rated below the leak checks
beside it.** But "console" includes a serial console on a management network, a
hypervisor's virtual console, an IPMI or iDRAC session and a cloud provider's
web terminal — none of which is the locked room the phrase suggests, and
several of which are reachable by anyone who has the management credentials
rather than the host's.

A value that enables only harmless functions is a smaller finding than one that
enables everything, and the verdict says which by decoding the mask rather than
printing the number. A host with kernel.sysrq = 16 has thought about this and
chosen to keep the emergency sync; a host with 1 has not.`,

	// Medium. It needs console access of some kind, which is a real barrier and
	// is not the barrier operators picture. The dangerous-subset case stays at
	// Medium and a mask limited to benign functions is reported at Low: the
	// same "insufficient effort versus total absence" distinction KERNEL-0018
	// draws, applied to a bitmask instead of a level.
	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "sysctl", "persistence", "physical-access"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 27,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{sysrqKey}, persistSysrqCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(sysrqKey)
		if !found {
			detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so after the next reboot the magic SysRq key is whatever the kernel was built with — commonly 1, every function enabled, or a distribution's own default.", sysrqKey)
			if r, ok := sc.Run(sysrqKey); ok && r.State == fact.SysctlObserved {
				detail += fmt.Sprintf(" The running kernel has it at %s (%s).", r.Value, describeSysrq(r.Value))
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  sysrqKey,
				Detail:   detail + persistSysrqCaveat,
				Evidence: searchedEvidence(sc, nil),
			}
		}

		value := strings.TrimSpace(set.Value)
		if mask, err := parseSysrqMask(value); err == nil && mask == 0 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: sysrqKey,
				Detail: fmt.Sprintf("%s is 0 at %s:%d, so the magic SysRq key is disabled and stays disabled across a reboot. Nothing at the console can reach the kernel through it.%s%s",
					sysrqKey, set.File, set.Line, runningMismatch(sc, sysrqKey, "0"), persistSysrqCaveat),
				Evidence: configuredEvidence(sc, sysrqKey),
			}
		}

		mask, err := parseSysrqMask(value)
		if err != nil {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       sysrqKey,
				Detail: fmt.Sprintf("%s is %q at %s:%d, which is not a number. What the kernel does with a value it cannot parse depends on the build, so what this host allows at the console after a reboot cannot be determined from the file.%s",
					sysrqKey, set.Value, set.File, set.Line, persistSysrqCaveat),
				Evidence: configuredEvidence(sc, sysrqKey),
			}
		}

		out := catalog.Outcome{
			Result:   finding.Fail,
			Subject:  sysrqKey,
			Evidence: configuredEvidence(sc, sysrqKey),
		}
		// A mask that enables only the functions with no security consequence
		// is a smaller finding than one that enables the dumps, the log-level
		// control or the process signalling. Both are failures; only one is a
		// host that has thought about it.
		if dangerous := dangerousSysrq(mask); len(dangerous) == 0 {
			out.Severity = finding.Low
			out.Detail = fmt.Sprintf("%s is %d at %s:%d, which enables %s. None of those hands an attacker at the console anything beyond the disruption itself, so this is a deliberate and narrow choice rather than the default — and 0 is still the value to reach for unless the emergency use is real.%s%s",
				sysrqKey, mask, set.File, set.Line, describeSysrq(value),
				runningMismatch(sc, sysrqKey, value), persistSysrqCaveat)
			return out
		} else {
			out.Detail = fmt.Sprintf("%s is %d at %s:%d, which enables %s. The consequential part is %s, reachable by anyone at the console — and console here includes a serial line on a management network, a hypervisor's virtual console and a cloud provider's web terminal.%s%s",
				sysrqKey, mask, set.File, set.Line, describeSysrq(value), strings.Join(dangerous, "; "),
				runningMismatch(sc, sysrqKey, value), persistSysrqCaveat)
		}
		return out
	},

	Remediation: &finding.Remediation{
		Summary: "Write kernel.sysrq = 0 to a file in /etc/sysctl.d/ and apply it.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn 'kernel.sysrq' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. systemd ships a default in /usr/lib/sysctl.d/50-default.conf, so a drop-in in /etc/sysctl.d is what overrides it.",
			"Create or extend a drop-in containing kernel.sysrq = 0.",
			"Decide first whether anyone actually uses it. On a physical machine with an operations team that recovers wedged hosts from a console, the sync and remount-read-only functions are genuinely valuable and the honest answer may be 16 or 48 rather than 0 — a narrow mask, chosen and written down, which this check reports at Low rather than as a plain failure.",
			"Never leave the debugging dumps enabled. Bit 8 prints registers, memory and every task's stack to the console, which defeats address-space randomisation for anyone who can read it.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.sysrq.",
			"Remember the kernel command line can set it too: sysrq_always_enabled in the bootloader configuration overrides this and is not visible to a check that reads sysctl files.",
		},
		Commands: []string{
			"sysctl kernel.sysrq",
			"grep -rn 'kernel.sysrq' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Disabling SysRq removes the last resort for recovering a machine whose userspace is gone. Where that matters — physical hosts with console access and an operations team who use it — a narrow mask is a better answer than 0, and better than leaving the default in place.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "PE-3"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — Magic SysRq key", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const sysrqKey = "kernel.sysrq"

// persistSysrqCaveat is this group's caveat with no runtime counterpart to
// name: nothing in the catalog reads the running kernel.sysrq, so the sentence
// that points at one would be pointing at nothing.
const persistSysrqCaveat = " This reads the sysctl configuration files, which describe what the kernel will do after the next reboot. No check in this catalog reads the running value, and the kernel command line can enable SysRq in a way no sysctl file records — sysrq_always_enabled in the bootloader configuration is not visible here."

// sysrqBits maps each bit of the mask to what it turns on, in bit order.
//
// Decoding it is the difference between a finding that says "kernel.sysrq is
// 176" and one an operator can act on. The numbers are documented in
// Documentation/admin-guide/sysrq.rst and are stable.
var sysrqBits = []struct {
	bit  int
	what string
	// why is non-empty for the functions with a security consequence, and is
	// what the finding leads with.
	why string
}{
	{2, "changing the console log level", "log-level control, which can silence kernel logging while something else happens"},
	{4, "keyboard control, including turning off raw mode", "keyboard control, which can be used to disrupt a console session"},
	{8, "debugging dumps of registers, memory and every task's stack", "the debugging dumps, which print kernel memory to the console and defeat address-space randomisation in one keystroke"},
	{16, "syncing all filesystems", ""},
	{32, "remounting all filesystems read-only", ""},
	{64, "signalling processes, up to SIGKILL for every task", "process signalling, which can kill the audit daemon before anything else happens"},
	{128, "immediate reboot or power off", ""},
	{256, "renicing all real-time tasks", ""},
}

// parseSysrqMask reads a mask the way the kernel does.
//
// **Base 0, not base 10**, because the kernel's proc_get_long parses with
// simple_strtoul(p, &p, 0) and systemd ships `kernel.sysrq = 0x01b6` in
// /usr/lib/sysctl.d/50-default.conf — a real value on a real host, which a
// decimal-only parse reports as "not a number". A leading 0 is octal for the
// same reason: matching the kernel matters more than matching what an operator
// probably meant, because the kernel is what will be running.
func parseSysrqMask(v string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 64)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// describeSysrq renders a mask as the functions it enables.
func describeSysrq(value string) string {
	v := strings.TrimSpace(value)
	if mask, err := parseSysrqMask(v); err == nil {
		switch mask {
		case 0:
			return "nothing: SysRq is disabled"
		case 1:
			return "every SysRq function"
		}
	}
	mask, err := parseSysrqMask(v)
	if err != nil {
		return "an unrecognised value"
	}
	var on []string
	for _, b := range sysrqBits {
		if mask&b.bit != 0 {
			on = append(on, b.what)
		}
	}
	if len(on) == 0 {
		return "no documented function"
	}
	return strings.Join(on, ", ")
}

// dangerousSysrq returns the reasons a mask matters, or nothing when it enables
// only the functions with no security consequence.
//
// 1 is every function and therefore every reason. Sync, remount-read-only,
// reboot and renice are disruptive and disclose nothing, which is why a host
// that chose those deliberately is reported below one that left the default.
func dangerousSysrq(mask int) []string {
	if mask == 1 {
		mask = 0x1ff
	}
	var why []string
	for _, b := range sysrqBits {
		if b.why != "" && mask&b.bit != 0 {
			why = append(why, b.why)
		}
	}
	return why
}

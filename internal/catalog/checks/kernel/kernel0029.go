package kernel

import (
	"fmt"
	"strconv"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0029 tests whether the setuid core-dump policy is written to the sysctl
// configuration.
var Check0029 = catalog.Check{
	ID:     "KERNEL-0029",
	Module: "KERNEL",
	Title:  "The setuid core-dump policy is written to the sysctl configuration",

	Description: `A core dump is the crashing process's memory written to disk.
For an ordinary program that is a debugging convenience. For a setuid program it
is a copy of whatever the program held while running as somebody else, a
password read from a terminal, a private key, a Kerberos ticket, a session token
, plus the addresses everything sat at, which is a defeat of layout
randomisation thrown in.

fs.suid_dumpable decides what happens when a setuid or setgid program crashes:

  - 0, no dump. The upstream default.
  - 1, dump like any other process, owned by the *running* user. An
    unprivileged user crashes a setuid binary and reads privileged memory out
    of the resulting file. This is the value that must never be set.
  - 2, dump, readable only by root. "suidsafe": what systemd-coredump needs to
    capture a crash of a setuid binary at all.

**0 and 2 both pass, and they are not equivalent.** At 2 the privileged memory
still reaches the disk, where it outlives the process, is picked up by backups,
and is readable by anything that reaches root. It is a considered trade for a
host that needs crash reports, not a hardened setting, and this check says so
rather than passing it silently.

KERNEL-0005 reads the running value and, since catalog 32, accepts the same two
values this check does. The pair used to disagree about 2, which put a PASS and
a FAIL on the same parameter in one report.

This is a check about files. The kernel already defaults to 0, so most hosts
fail this while being safe today, which is the point: a default is not a
decision, and nothing on the host records that anyone chose it.`,

	// High. This is the parameter's own severity rather than the severity of
	// the common failure, and the two differ more here than anywhere else in
	// the module: a file setting 1 hands unprivileged users the contents of
	// privileged memory, and a file setting nothing leaves a safe default
	// undocumented.
	//
	// Both of those questions have since been answered elsewhere and this
	// rating survived both. Catalog 32's runtime tiering separated them by
	// severity after all — the undocumented-but-safe host now reports LOW —
	// and the catalog 33 audit raised KERNEL-0005 from Medium to High rather
	// than lowering this, because what suid_dumpable = 1 does is disclose one
	// user's privileged memory to another.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "sysctl", "persistence", "information-leak"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 31,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{suidDumpableKey}, persistSuidDumpableCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(suidDumpableKey)
		if !found {
			detail := fmt.Sprintf("%s, so after the next reboot it is whatever the kernel defaults to. Upstream defaults to 0, which is correct — but a default is not a decision, and a debugging drop-in, a crash-reporting package or a sysctl -w in a start-up script can set it to 1 without anything here recording that 0 was ever intended.", notConfigured(sc, suidDumpableKey))
			if r, ok := sc.Run(suidDumpableKey); ok && r.State == fact.SysctlObserved {
				if v, isInt := r.Int(); isInt {
					switch v {
					case 0:
						detail += " The running kernel has it at 0, so this host is safe now on a default nobody wrote down."
					case 1:
						detail += " The running kernel has it at 1, which is the dangerous value and is live right now: any local user can crash a setuid binary and read privileged memory out of the dump."
					default:
						detail += fmt.Sprintf(" The running kernel has it at %d.", v)
					}
				}
			}
			return tierAbsence(catalog.Outcome{
				Result:   finding.Fail,
				Subject:  suidDumpableKey,
				Detail:   detail,
				Evidence: searchedEvidence(sc, nil),
			}, sc, suidDumpableTiering, persistSuidDumpableCaveat)
		}

		n, err := strconv.Atoi(set.Value)
		if err != nil {
			return unparseableConfig(sc, suidDumpableKey, set, persistSuidDumpableCaveat)
		}

		switch n {
		case 0:
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: suidDumpableKey,
				Detail: fmt.Sprintf("%s is 0 %s, so a setuid or setgid program that crashes writes no core dump at all, and nothing it held while running as somebody else reaches the disk. It stays that way across a reboot.%s%s",
					suidDumpableKey, configuredAt(sc, suidDumpableKey, set),
					runningMismatch(sc, suidDumpableKey, set.Value), persistSuidDumpableCaveat),
				Evidence: configuredEvidence(sc, suidDumpableKey),
			}

		case 2:
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: suidDumpableKey,
				Detail: fmt.Sprintf("%s is 2 %s, so a setuid program's core dump is written but only root may read it — which is what systemd-coredump needs to capture such a crash at all, and is a deliberate choice rather than an inherited default. It is not the same as 0: the privileged memory still reaches the disk, where it outlives the process, is picked up by backups and is readable by anything that reaches root.%s%s",
					suidDumpableKey, configuredAt(sc, suidDumpableKey, set),
					runningMismatch(sc, suidDumpableKey, set.Value), persistSuidDumpableCaveat),
				Evidence: configuredEvidence(sc, suidDumpableKey),
			}

		case 1:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: suidDumpableKey,
				Detail: fmt.Sprintf("%s is 1 %s, which is the one value that must never be set: a setuid program's core dump is owned by the user who ran it, so any local user can crash one and read privileged memory — credentials, keys and tokens the program held while running as somebody else, along with the addresses they sat at. This is written down, so it is a decision somebody made rather than a default nobody set.%s%s",
					suidDumpableKey, configuredAt(sc, suidDumpableKey, set),
					runningMismatch(sc, suidDumpableKey, "1"), persistSuidDumpableCaveat),
				Evidence: configuredEvidence(sc, suidDumpableKey),
			}
		}

		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonAmbiguousState,
			Subject:       suidDumpableKey,
			Detail: fmt.Sprintf("%s is %d %s, which is not one of the documented values 0, 1 or 2. What the kernel does with it depends on the build, so what this host does with a setuid program's core dump after a reboot cannot be determined from the file.%s",
				suidDumpableKey, n, configuredAt(sc, suidDumpableKey, set), persistSuidDumpableCaveat),
			Evidence: configuredEvidence(sc, suidDumpableKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write fs.suid_dumpable = 0 to a file in /etc/sysctl.d/, or 2 where crash reports for setuid binaries are needed.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn suid_dumpable /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. Expect nothing on most hosts, the kernel defaults to 0 and no distribution in this project's corpus writes it down.",
			"Create or extend a drop-in containing fs.suid_dumpable = 0. Write it down even though the running kernel almost certainly reports 0 already: that is the built-in default rather than a decision, and a debugging or crash-reporting package that sets 1 will win silently.",
			"Use 2 instead only where crashes of setuid binaries genuinely have to be captured, systemd-coredump cannot collect them at 0. Understand what that buys the attacker who reaches root, and make sure the dumps are not swept into a backup or a log shipper.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl fs.suid_dumpable.",
			"Check where dumps land if you set 2: kernel.core_pattern decides, and a pattern piping to a program runs that program as root. KERNEL-0014 covers it.",
		},
		Commands: []string{
			"sysctl fs.suid_dumpable",
			"grep -rn suid_dumpable /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"sysctl kernel.core_pattern",
		},
		Caution: "At 0 a crashing setuid binary produces nothing to debug with, which matters if you are actually chasing a crash in one. That is the intended trade. Note that 2 is not a middle setting for safety, it is a middle setting for debuggability, and the memory still reaches the disk.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, fs.suid_dumpable", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#suid-dumpable"},
		{Title: "core(5)", URL: "https://man7.org/linux/man-pages/man5/core.5.html"},
	},
}

const suidDumpableKey = "fs.suid_dumpable"

// persistSuidDumpableCaveat names the check that reads the running value.
var persistSuidDumpableCaveat = persistCaveatFor("KERNEL-0005")

// suidDumpableTiering is the runtime cross-reference for the absence case.
var suidDumpableTiering = []requirement{{key: suidDumpableKey, accept: func(n int) bool { return n == 0 || n == 2 }}}

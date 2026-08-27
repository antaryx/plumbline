package kernel

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0017 tests whether BPF hardening survives a reboot.
var Check0017 = catalog.Check{
	ID:     "KERNEL-0017",
	Module: "KERNEL",
	Title:  "BPF hardening is written to the sysctl configuration",

	Description: `This is a check about files, not about the running kernel.
KERNEL-0006 asks whether unprivileged bpf() is refused *now*; this one asks
whether it will still be refused after the next reboot.

The gap between those is real and is not covered by KERNEL-0007. That check
compares each running parameter against its configured value and reports drift
— but a parameter that no file mentions at all is skipped, because there is
nothing to compare it to. So a host hardened with

	sysctl -w kernel.unprivileged_bpf_disabled=1

and nothing written to disk passes KERNEL-0006 and passes KERNEL-0007, and
comes back after a reboot with unprivileged BPF wide open. Runtime hardening
that nobody persisted is the most common way a host silently un-hardens itself,
and it is invisible to every check that reads only /proc/sys.

Two parameters have to be on disk, and they do different jobs:

  - **kernel.unprivileged_bpf_disabled** decides who may call bpf() at all. At
    1 the call is refused for unprivileged users and the setting is locked
    until reboot; at 2 it is refused and the value may still be raised to 1.
    Either persists, and 1 is the stronger of the two.
  - **net.core.bpf_jit_harden** decides what the JIT emits for the programs
    that do get loaded. At 2 it blinds constants for every program, which
    stops an attacker smuggling a chosen instruction sequence into the
    kernel's instruction stream as an immediate operand and jumping into the
    middle of it. At 1 it does that for unprivileged programs only, which
    leaves the case that matters once something has obtained privilege.

They are independent settings and a host commonly has one without the other,
which is why both are named rather than one standing in for the pair.

**A conflict is not a verdict.** Where two files set the same parameter to
different values, which one wins depends on whether systemd-sysctl or procps
applied them, and this check will not guess — it reports UNKNOWN and names both
files. Getting that wrong would be a confident claim about what the host does
after a reboot, which is the one thing this check exists to describe.`,

	// High. KERNEL-0006 is Medium because it describes a boundary that is up
	// right now; this describes one that is scheduled to fall down, on a host
	// whose operator believes it is hardened and whose other checks agree. A
	// finding nobody will see again until an incident is worth more than one
	// they can see today.
	BaseSeverity: finding.High,
	Tags:         []string{"kernel", "bpf", "sysctl", "persistence", "privilege-escalation"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 25,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		// A kernel that implements neither parameter has nothing to persist,
		// and a file setting them would do nothing. NOT_APPLICABLE for the
		// reason the module applies everywhere else: there is nothing to
		// harden, and reporting ignorance or a failure would bury the real
		// findings in noise.
		if out, stop := bpfUnsupported(sc); stop {
			return out
		}

		// No configuration at all, and nothing that stopped us reading it.
		// There is no file to have an opinion about — a host whose sysctl
		// settings arrive some other way, an image built without them, or a
		// system that does not use sysctl.d. Reporting FAIL here would be a
		// finding about a file that was never meant to exist.
		if len(sc.Files) == 0 && len(sc.UnreadableFiles) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "No sysctl configuration file exists on this host: neither /etc/sysctl.conf nor any .conf file in the sysctl.d directories. There is no persistent kernel configuration to report on, and what the running kernel currently does is KERNEL-0006's subject.",
			}
		}

		// A file we could not read may hold either setting, so an absence
		// cannot be concluded. This comes before the value tests because the
		// verdict below rests on *not* finding something.
		if out, stop := configUnreadable(sc); stop {
			return out
		}

		var (
			failed   []string
			weak     []string
			evidence []finding.Evidence
		)
		for _, want := range bpfPersistent {
			set, found := sc.EffectiveConfigured(want.key)
			if !found {
				failed = append(failed, fmt.Sprintf("%s is not set in any sysctl configuration file", want.key))
				continue
			}
			if sc.ConfiguredConflict(want.key) {
				var files []string
				for _, s := range sc.Configured[want.key] {
					files = append(files, fmt.Sprintf("%s:%d sets %s", s.File, s.Line, s.Value))
					evidence = append(evidence, evidenceForSetting(sc, s))
				}
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       want.key,
					Detail: fmt.Sprintf("%s is set to different values in more than one configuration file (%s). Which one is in force after a reboot depends on whether systemd-sysctl or procps applied them and in what order, so what this host does on its next boot cannot be determined from the files alone.%s",
						want.key, strings.Join(files, "; "), persistCaveat),
					Evidence: evidence,
				}
			}

			evidence = append(evidence, evidenceForSetting(sc, set))
			value := strings.TrimSpace(set.Value)
			switch {
			case want.accept(value):
				if want.weak(value) {
					weak = append(weak, fmt.Sprintf("%s is %s at %s:%d, and %s", want.key, value, set.File, set.Line, want.weakNote))
				}
			default:
				failed = append(failed, fmt.Sprintf("%s is %s at %s:%d, and %s", want.key, value, set.File, set.Line, want.wantNote))
			}
		}

		if len(failed) > 0 {
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  "sysctl configuration",
				Detail:   bpfFailureDetail(sc, failed) + persistCaveat,
				Evidence: searchedEvidence(sc, evidence),
			}
		}

		detail := "Both BPF hardening parameters are written to the sysctl configuration, so unprivileged bpf() stays refused and the JIT keeps blinding constants across a reboot."
		if len(weak) > 0 {
			detail = fmt.Sprintf("Both BPF hardening parameters are written to the sysctl configuration, so the hardening survives a reboot. %s.",
				capitaliseFirst(strings.Join(weak, "; ")))
		}
		return catalog.Outcome{
			Result:   finding.Pass,
			Subject:  "sysctl configuration",
			Detail:   detail + runningNote(sc) + persistCaveat,
			Evidence: evidence,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write both parameters to a file in /etc/sysctl.d/ and apply them.",
		Effort:  "LOW",
		Steps: []string{
			"Create /etc/sysctl.d/60-bpf-hardening.conf containing two lines: kernel.unprivileged_bpf_disabled = 1 and net.core.bpf_jit_harden = 2.",
			"Number the file so it sorts after anything that might set the same keys. Drop-ins are applied in lexicographic order of filename across the directories, so 60- beats 10- and a file in /etc/sysctl.d beats one in /usr/lib/sysctl.d only because of the directory order, not the number.",
			"Check nothing else sets them to something weaker first: grep -rn 'unprivileged_bpf_disabled\\|bpf_jit_harden' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. Two files disagreeing is worse than neither setting it, because which wins depends on which tool applied them.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden.",
			"Note that unprivileged_bpf_disabled can be raised but never lowered while the kernel runs. If it is currently 0, the file makes the next boot correct and sysctl --system will set it now; if it is already 1, it is locked and the file simply makes that survive.",
			"Verify the file is what takes effect rather than something else: systemd-analyze cat-config sysctl.d shows the merged configuration in application order on a systemd host.",
		},
		Commands: []string{
			"sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden",
			"grep -rn 'unprivileged_bpf_disabled\\|bpf_jit_harden' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Disabling unprivileged BPF breaks unprivileged tooling that uses it — some observability agents, and seccomp-bpf is unaffected but eBPF-based tracing run as a normal user is not. Check what on this host loads BPF programs before changing it. JIT hardening costs a little throughput on hot paths for programs that are loaded, which is rarely measurable outside a packet-processing workload.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-6"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel — unprivileged_bpf_disabled", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled"},
		{Title: "Linux kernel — bpf_jit_harden", URL: "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html#bpf-jit-harden"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

// bpfPersistent are the parameters that have to be on disk, with what counts
// as acceptable and what counts as merely adequate.
//
// The two-tier shape — accept and weak — is the one SERVICES-0008 uses for
// ProtectHome=read-only, and for the same reason. A value that satisfies the
// check while leaving part of its rationale unaddressed should pass and say
// so, rather than being failed (which would be wrong) or passed silently
// (which would claim more than it delivers).
var bpfPersistent = []struct {
	key      string
	accept   func(string) bool
	weak     func(string) bool
	weakNote string
	wantNote string
}{
	{
		key: "kernel.unprivileged_bpf_disabled",
		// 1 and 2 both refuse unprivileged bpf(). 1 additionally locks the
		// value for the rest of the boot. Requiring exactly 1 would fail a
		// host that is not exposed, which is the class of false positive that
		// teaches an operator to stop reading the report.
		accept:   func(v string) bool { return v == "1" || v == "2" },
		weak:     func(v string) bool { return v == "2" },
		weakNote: "unprivileged bpf() is refused; 1 additionally locks the setting so nothing can lower it for the rest of the boot",
		wantNote: "any local user may load BPF programs after the next reboot — set it to 1, or to 2 if something on this host needs to raise it later",
	},
	{
		key: "net.core.bpf_jit_harden",
		// Only 2 hardens every program. 1 covers unprivileged programs, which
		// is precisely the case that no longer matters once an attacker has
		// obtained privilege.
		accept:   func(v string) bool { return v == "2" },
		weak:     func(string) bool { return false },
		wantNote: "the JIT blinds constants for unprivileged programs only at 1, and not at all at 0 — set it to 2 so every loaded program is hardened",
	},
}

// persistCaveat is appended to every verdict this check draws.
//
// It names the limit that separates this check from KERNEL-0006: a file says
// what the next boot will do, and nothing about what the kernel is doing now.
// A host can pass this and be running with BPF wide open, which is drift and is
// KERNEL-0007's subject.
const persistCaveat = " This reads the sysctl configuration files, which describe what the kernel will do after the next reboot; what it is doing now is KERNEL-0006's subject, and a disagreement between the two is KERNEL-0007's."

// configUnreadable stops the check when a configuration file exists and could
// not be read.
//
// The verdict below rests on *not* finding a setting, and a file nobody opened
// may contain it. That is ADR-0014 in the direction it points here: an
// incomplete examination invalidates a negative result.
func configUnreadable(sc fact.Sysctl) (catalog.Outcome, bool) {
	names := sc.UnreadableFileNames()
	if len(names) == 0 {
		return catalog.Outcome{}, false
	}

	reason := finding.ReasonAmbiguousState
	if kind, ok := sc.WorstUnreadableKind(); ok {
		switch kind {
		case fact.ErrPermission:
			reason = finding.ReasonPermission
		case fact.ErrTruncated:
			reason = finding.ReasonTruncated
		case fact.ErrParse:
			reason = finding.ReasonParse
		}
	}
	var ev []finding.Evidence
	for _, f := range sc.UnreadableFiles {
		ev = append(ev, finding.NewEvidence(f.File, 0, string(f.Kind)+": "+f.Msg, ""))
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       "sysctl configuration",
		Detail: fmt.Sprintf("This verdict would rest on not finding the BPF parameters in any configuration file, and %s could not be read — so a setting for them may be in a file this scan never opened.%s",
			joinKeys(names), persistCaveat),
		Evidence: ev,
	}, true
}

// bpfUnsupported reports the NOT_APPLICABLE for a kernel that implements
// neither parameter.
//
// Both have to be absent. A kernel with one and not the other is a kernel this
// check still has something to say about, and excusing it on the strength of
// the missing half would hide the half that is there.
func bpfUnsupported(sc fact.Sysctl) (catalog.Outcome, bool) {
	var absent []string
	for _, want := range bpfPersistent {
		r, probed := sc.Run(want.key)
		if probed && r.State == fact.SysctlAbsent {
			absent = append(absent, want.key)
		}
	}
	if len(absent) != len(bpfPersistent) {
		return catalog.Outcome{}, false
	}
	return catalog.Outcome{
		Result:  finding.NotApplicable,
		Subject: "sysctl configuration",
		Detail: fmt.Sprintf("This kernel implements neither %s, so there is nothing for a configuration file to persist. Both are absent from /proc/sys, which on a kernel this old means BPF is not present at all rather than that the parameters are turned off.",
			joinKeys(absent)),
	}, true
}

// searchedEvidence guarantees a failure cites something.
//
// When neither parameter is set anywhere there is no line to quote, and a
// finding with no evidence is one an auditor cannot follow up. What they need
// instead is the list of files that *were* read — "I looked in these and it is
// in none of them" — which is also exactly the set an operator has to check
// before adding a new drop-in.
func searchedEvidence(sc fact.Sysctl, ev []finding.Evidence) []finding.Evidence {
	if len(ev) > 0 {
		return ev
	}
	for _, f := range sc.Files {
		ev = append(ev, finding.NewEvidence(f, 0, "read, and sets neither BPF parameter", sc.Digests[f]))
	}
	return ev
}

// bpfFailureDetail renders the failure, leading with what is missing.
func bpfFailureDetail(sc fact.Sysctl, failed []string) string {
	detail := fmt.Sprintf("BPF hardening is not written to this host's sysctl configuration: %s.",
		strings.Join(failed, "; "))

	// The trap this check exists for: hardened now, unhardened after a reboot,
	// and every other KERNEL check reporting the host as fine. Saying so is
	// the difference between a finding an operator acts on and one they read
	// as a duplicate of KERNEL-0006.
	var running []string
	for _, want := range bpfPersistent {
		if _, found := sc.EffectiveConfigured(want.key); found {
			continue
		}
		r, ok := sc.Run(want.key)
		if !ok || r.State != fact.SysctlObserved {
			continue
		}
		if want.accept(strings.TrimSpace(r.Value)) {
			running = append(running, fmt.Sprintf("%s is %s", want.key, strings.TrimSpace(r.Value)))
		}
	}
	if len(running) > 0 {
		detail += fmt.Sprintf(" The running kernel is currently hardened — %s — so this host is protected now and will not be after the next reboot. That is the case KERNEL-0006 reports as a pass and KERNEL-0007 does not see at all, because a parameter no file mentions has nothing to drift from.",
			strings.Join(running, " and "))
	}
	return detail
}

// runningNote adds, to a passing verdict, the fact that the configuration is
// not yet in force.
//
// A file that says the right thing and a kernel that does not is drift, which
// KERNEL-0007 owns — but a reader of *this* check has just been told the
// hardening is persistent, and "and it is not currently applied" is the next
// thing they need to know rather than something to find in another finding.
func runningNote(sc fact.Sysctl) string {
	var pending []string
	for _, want := range bpfPersistent {
		r, ok := sc.Run(want.key)
		if !ok || r.State != fact.SysctlObserved {
			continue
		}
		if !want.accept(strings.TrimSpace(r.Value)) {
			pending = append(pending, fmt.Sprintf("%s is %s", want.key, strings.TrimSpace(r.Value)))
		}
	}
	if len(pending) == 0 {
		return ""
	}
	return fmt.Sprintf(" The configuration is not yet in force: %s in the running kernel, so the file describes the next boot rather than this one. See KERNEL-0007.",
		strings.Join(pending, " and "))
}

func capitaliseFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

package kernel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0007 compares the running kernel against its own configuration.
//
// This is the check the KERNEL module exists to make possible. Every other
// check in the module reads /proc/sys and judges what is running now; this one
// asks whether what is running now will still be running after a reboot. A
// host that is hardened only until it restarts is a host that is not hardened,
// and neither number tells you that on its own.
var Check0007 = catalog.Check{
	ID:     "KERNEL-0007",
	Module: "KERNEL",
	Title:  "The running kernel parameters match the configured ones",
	Description: `/proc/sys is what the kernel is doing now. /etc/sysctl.conf and
the sysctl.d directories are what it will do after the next reboot. They are
different observations and they disagree more often than operators expect.

The disagreement runs in both directions and both matter. A parameter hardened
in a file but not applied means the host is unprotected today and someone
believes otherwise. A parameter hardened at runtime but absent from any file
means the protection disappears at the next reboot, silently, possibly months
later during an unrelated maintenance window.

This check compares every parameter the module probes against the value its
configuration sets, and reports each one that differs.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "configuration-drift", "persistence"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		var (
			drifted    []string
			ambiguous  []string
			configured int
			// notInKernel are parameters a file sets that this kernel does not
			// implement. The setting does nothing; that is worth stating, but
			// it is not drift and does not decide the verdict.
			notInKernel []string
			evidence    []finding.Evidence
		)

		for _, key := range sc.RunningKeys() {
			set, found := sc.EffectiveConfigured(key)
			if !found {
				continue
			}

			if sc.ConfiguredConflict(key) {
				// Two files set this parameter to different values. Which one
				// wins depends on whether systemd-sysctl or procps applied
				// them and in what order, and this check will not guess: a
				// wrong answer here is a confident claim about what the host
				// does after a reboot.
				ambiguous = append(ambiguous, key)
				for _, s := range sc.Configured[key] {
					evidence = append(evidence, evidenceForSetting(sc, s))
				}
				continue
			}

			r, _ := sc.Run(key)
			if r.State != fact.SysctlObserved {
				if r.State == fact.SysctlAbsent {
					// A file sets a parameter this kernel does not implement.
					// The setting does nothing, which is worth stating, but it
					// is not drift and must not be counted as agreement: a
					// parameter that does not exist cannot match.
					notInKernel = append(notInKernel, key)
				}
				// Denied or errored: we cannot compare. The per-parameter
				// check for that key already reports the UNKNOWN; repeating it
				// here would double-count one gap as two findings.
				continue
			}

			// Counted only now, when there is genuinely a running value and a
			// configured value to compare.
			configured++

			if strings.TrimSpace(set.Value) == strings.TrimSpace(r.Value) {
				continue
			}
			drifted = append(drifted, key)
			evidence = append(evidence,
				evidenceFor(r),
				evidenceForSetting(sc, set))
		}

		sort.Strings(drifted)
		sort.Strings(ambiguous)
		sort.Strings(notInKernel)

		// An incomplete view of the configuration cannot support "nothing
		// drifts": the setting that disagrees may be in the file we could not
		// open. It can still support a positive result, because a drift we
		// found is a drift that exists.
		if len(drifted) == 0 && len(sc.UnreadableFiles) > 0 {
			kind, _ := sc.WorstUnreadableKind()
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: unknownReasonFor(kind),
				Detail: fmt.Sprintf(
					"No drift was found among the parameters that could be compared, but %d sysctl configuration file(s) could not be read (%s), so a parameter set there may disagree with the running kernel without this check seeing it.",
					len(sc.UnreadableFiles), joinKeys(sc.UnreadableFileNames())),
				Evidence: unreadableEvidence(sc),
			}
		}

		if len(drifted) == 0 && len(ambiguous) > 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Detail: fmt.Sprintf(
					"%s is set in more than one configuration file with different values; which one applies depends on the order the host's sysctl implementation walks the drop-in directories, so the value after the next reboot cannot be determined from the files alone.",
					joinKeys(ambiguous)),
				Evidence: evidence,
			}
		}

		if len(drifted) > 0 {
			detail := fmt.Sprintf(
				"%d kernel parameter(s) differ between the running kernel and the configuration that will be applied at the next boot: %s. Each is listed in the evidence with both values.",
				len(drifted), joinKeys(drifted))
			if len(ambiguous) > 0 {
				detail += fmt.Sprintf(
					" A further %d parameter(s) are set in more than one file with different values and could not be compared: %s.",
					len(ambiguous), joinKeys(ambiguous))
			}
			if len(notInKernel) > 0 {
				detail += fmt.Sprintf(
					" Separately, the configuration sets %s, which this kernel does not implement; those settings have no effect.",
					joinKeys(notInKernel))
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Detail:   detail,
				Evidence: evidence,
			}
		}

		if configured == 0 {
			// Nothing comparable is configured, so there is no persistent
			// configuration for the running kernel to disagree with. The
			// subject genuinely is not present, which is what NOT_APPLICABLE
			// means; it is not "we could not find it".
			detail := "No sysctl configuration file sets any of the kernel parameters this module probes, so there is no configured value to compare the running kernel against."
			if len(notInKernel) > 0 {
				detail = fmt.Sprintf(
					"The sysctl configuration sets %s, which this kernel does not implement, and sets no other parameter this module probes. Those settings have no effect, so there is nothing to compare the running kernel against.",
					joinKeys(notInKernel))
			}
			return catalog.Outcome{Result: finding.NotApplicable, Detail: detail}
		}

		detail := fmt.Sprintf(
			"All %d configured kernel parameter(s) match the running kernel; the current settings will survive a reboot.",
			configured)
		if len(notInKernel) > 0 {
			detail += fmt.Sprintf(
				" The configuration also sets %s, which this kernel does not implement; those settings have no effect.",
				joinKeys(notInKernel))
		}
		return catalog.Outcome{Result: finding.Pass, Detail: detail}
	},

	Remediation: &finding.Remediation{
		Summary: "Reconcile /proc/sys with the sysctl configuration, then apply the files.",
		Effort:  "LOW",
		Steps: []string{
			"For each parameter in the evidence, decide which value is correct — the running one or the configured one.",
			"Where the configuration is correct and the kernel is not, apply it: sysctl --system",
			"Where the running value is correct and no file sets it, add it to /etc/sysctl.d/60-hardening.conf so it survives a reboot.",
			"Re-run the audit and confirm the parameters agree.",
			"If a parameter reverts after 'sysctl --system', something later in boot is overriding it — check for a drop-in with a higher-sorting name, a container runtime, or a network manager hook.",
		},
		Commands: []string{
			"sysctl --system",
			"sysctl --all",
		},
		Caution: "'sysctl --system' applies every setting in every configuration file at once, not only the drifted ones. On a host whose files have not been applied in a long time this can change networking behaviour immediately. Review the files before running it.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-6"},
		{Framework: "nist-800-53-r5", Control: "CM-2"},
	},

	References: []finding.Reference{
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
		{Title: "sysctl.conf(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.conf.5.html"},
	},
}

// unknownReasonFor maps a fact error kind onto the UNKNOWN reason code that
// describes it, following the table in DATA-MODEL.md §3.
func unknownReasonFor(kind fact.ErrorKind) finding.UnknownReason {
	switch kind {
	case fact.ErrPermission:
		return finding.ReasonPermission
	case fact.ErrTruncated:
		return finding.ReasonTruncated
	case fact.ErrParse:
		return finding.ReasonParse
	default:
		return finding.ReasonAmbiguousState
	}
}

// unreadableEvidence cites each configuration file that could not be read.
func unreadableEvidence(sc fact.Sysctl) []finding.Evidence {
	files := append([]fact.SysctlUnreadableFile(nil), sc.UnreadableFiles...)
	sort.Slice(files, func(i, j int) bool { return files[i].File < files[j].File })

	out := make([]finding.Evidence, 0, len(files))
	for _, f := range files {
		out = append(out, finding.NewEvidence(f.File, 0, f.Msg, ""))
	}
	return out
}

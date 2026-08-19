package filesys

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// mountRule is one mount-hardening check's parameters.
//
// The three checks share an evaluator because they differ only in which
// directory and which options, and three copies of this logic would have
// drifted — the truncation gate and the separate-mount test are exactly the
// parts that get subtly wrong in a copy.
type mountRule struct {
	// Point is the directory being hardened.
	Point string
	// Required are the options whose absence is a FAIL.
	Required []string
	// Observed are options reported in the detail but never failed on. /home
	// gets noexec here: enforcing it breaks virtualenvs, local Go builds and
	// npm, which is most of what a developer workstation does.
	Observed []string
	// Why is a clause completing "…, because <Why>".
	Why string
}

// evalMount is the shared body of FILESYS-0007, 0008 and 0009.
func evalMount(set *fact.Set, rule mountRule) catalog.Outcome {
	m := mountFact(set)

	// An unknown table must never read as an empty one. "/tmp is not a
	// separate mount" is a finding; "we could not find out what /tmp is" is
	// UNKNOWN, and they lead to opposite actions.
	if !m.Known {
		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonTruncated,
			Subject:       rule.Point,
			Detail: fmt.Sprintf(
				"The kernel's mount table could not be read, or came back truncated, so nothing is known about how %s is mounted. A partial mount table is one with entries missing from the end of it, and the missing entry may be exactly this one — so neither the presence nor the absence of a separate mount may be concluded from it.",
				rule.Point),
			Evidence: []finding.Evidence{
				finding.NewEvidence("/proc/self/mountinfo", 0, "unreadable or truncated; the mount table is not trustworthy", ""),
			},
		}
	}

	entry, exact := m.At(rule.Point)
	if !exact {
		// Not a separate filesystem. That is itself the finding: the options
		// are per-mount, so a directory that shares the root filesystem cannot
		// carry them, and it inherits whatever / was mounted with.
		gov, ok := m.Governing(rule.Point)
		govPoint := "/"
		if ok {
			govPoint = gov.Point
		}
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: rule.Point,
			Detail: fmt.Sprintf(
				"%s is not a separate mount: it is part of the filesystem mounted at %s and inherits its options. nodev, nosuid and noexec are per-mount properties, so a directory that is merely a subdirectory of another filesystem cannot carry them — and %s",
				rule.Point, govPoint, rule.Why),
			Evidence: []finding.Evidence{
				finding.NewEvidence("/proc/self/mountinfo", 0,
					fmt.Sprintf("no entry for %s; the governing mount is %s (%s)", rule.Point, govPoint, strings.Join(gov.Options, ",")), ""),
			},
		}
	}

	missing := entry.Missing(rule.Required...)

	// Positive: we read this mount's options. Nothing unread can unmake them.
	if len(missing) > 0 {
		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: rule.Point,
			Detail: fmt.Sprintf(
				"%s is a separate %s mount but is missing %s (mounted %s). %s%s",
				rule.Point, entry.FSType, strings.Join(missing, " and "),
				strings.Join(entry.Options, ","), missingEffect(missing), observedNote(entry, rule)),
			Evidence: []finding.Evidence{mountEvidence(entry)},
		}
	}

	return catalog.Outcome{
		Result:  finding.Pass,
		Subject: rule.Point,
		Detail: fmt.Sprintf(
			"%s is a separate %s mount carrying %s (mounted %s).%s",
			rule.Point, entry.FSType, strings.Join(rule.Required, ", "),
			strings.Join(entry.Options, ","), observedNote(entry, rule)),
		Evidence: []finding.Evidence{mountEvidence(entry)},
	}
}

// missingEffect says what each absent option permits, because "missing nosuid"
// is not self-explanatory to somebody who has not had to learn it.
func missingEffect(missing []string) string {
	var parts []string
	for _, o := range missing {
		switch o {
		case "nosuid":
			parts = append(parts, "without nosuid a setuid binary placed here runs with its owner's privileges, which is the persistence artifact FILESYS-0002 reports")
		case "nodev":
			parts = append(parts, "without nodev a device node created here reaches the hardware it names, bypassing the file permissions above it")
		case "noexec":
			parts = append(parts, "without noexec anything written here can be executed directly, which is the first thing a downloaded payload needs")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return sentence(strings.Join(parts, "; ")) + "."
}

// observedNote reports the options this rule watches but does not fail on.
func observedNote(entry fact.Mount, rule mountRule) string {
	if len(rule.Observed) == 0 {
		return ""
	}
	var have, lack []string
	for _, o := range rule.Observed {
		if entry.Has(o) {
			have = append(have, o)
			continue
		}
		lack = append(lack, o)
	}

	switch {
	case len(lack) == 0:
		return fmt.Sprintf(" It also carries %s, which this check does not require.", strings.Join(have, " and "))
	case len(have) == 0:
		return fmt.Sprintf(" It does not carry %s. That is not failed here: enforcing it on this filesystem breaks virtualenvs, local language toolchains and npm, which is most of what a developer workstation does. It is worth setting on a server where nobody builds anything.",
			strings.Join(lack, " and "))
	default:
		return fmt.Sprintf(" It carries %s and not %s; the latter is reported rather than required.",
			strings.Join(have, " and "), strings.Join(lack, " and "))
	}
}

// mountEvidence cites one mount table entry.
func mountEvidence(entry fact.Mount) finding.Evidence {
	return finding.NewEvidence("/proc/self/mountinfo", 0,
		fmt.Sprintf("%s on %s (%s)", entry.FSType, entry.Point, strings.Join(entry.Options, ",")), "")
}

// sentence capitalises a clause promoted to start a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

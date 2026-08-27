// Package services holds the SERVICES module's checks.
//
// Every check here rests on one fact about systemd that makes offline auditing
// possible at all: **enablement is a symlink**. `systemctl enable` writes no
// database row and sets no flag inside the unit file; it creates a link in
// <target>.wants/, `disable` removes it, and `mask` replaces the unit file
// with a link to /dev/null. The state systemctl would report is therefore
// recoverable from the filesystem alone, which is why this module exists
// without dbus and without root.
//
// Two limits follow from that, and both are stated in the checks rather than
// papered over:
//
//   - **Enabled is not running.** Nothing on disk records whether a process is
//     alive. No check here claims a service is running, and none claims one is
//     stopped. "Enabled" means "systemd will start it at boot", which is the
//     durable property an audit is actually about.
//   - **Not enabled is not never-started.** A *static* unit — one with no
//     [Install] section — cannot be enabled and has no symlink, yet runs
//     because another unit names it in Wants=. Determining that means parsing
//     the whole unit graph. Where it matters, the check says so.
//
// SERVICES-0006 rests on a different fact and reads unit *bodies*, which the
// five checks above deliberately do not. It asks what a unit's sandboxing
// directives say, and that question cannot be answered from a symlink. The
// exception is bounded the way the collector's package doc describes — a named
// list of units, an allowlist of directives applied during the parse,
// ReadOpaque so the bytes stay out of the bundle — and the two gates in this
// package differ accordingly: `applicable` asks whether the host runs systemd
// at all, and `sandboxApplicable` additionally asks whether any of the units
// it was looking for is installed.
package services

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// servicesFact reads the module's fact. The runner's required-fact gate
// guarantees it is present and typed before Eval is entered.
func servicesFact(fs *fact.Set) fact.Services {
	s, _, _ := fact.Get[fact.Services](fs, fact.ServicesID)
	return s
}

// notSystemd is the verdict when the host has no systemd unit directory.
//
// NOT_APPLICABLE and not PASS. "telnet.socket is not enabled" is not a true
// statement about a host running OpenRC, SysVinit or runit — it is a sentence
// with no subject, and the service it names may well be running under a
// mechanism this module cannot see. Reporting PASS would be the exact false
// assurance CONTRIBUTING.md rule 3 forbids, dressed as a compliment.
func notSystemd() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "No systemd unit directory exists on this host (/etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system, /lib/systemd/system), so it does not run systemd. Service enablement here is governed by some other init system — OpenRC, SysVinit, runit — which this module cannot read, and which may well have the service in question running.",
	}
}

// renderPerm formats permission bits the way an operator reads them out of
// `stat -c %a`, which is the form they will type into chmod.
func renderPerm(mode uint32) string { return fmt.Sprintf("%04o", fs.FileMode(mode).Perm()) }

// unknownIfIncomplete converts an outcome that rests on **absence** into
// UNKNOWN when any directory the collector needed could not be fully listed.
//
// It is applied by the call site rather than automatically, because which
// outcome rests on absence differs per check and the compiler cannot tell.
// SERVICES-0001 concludes PASS from finding no enablement symlink; SERVICES-0003
// concludes FAIL from finding no enablement symlink. Both are negative
// conclusions and both are invalidated by a directory we could not read; only
// one of them is a PASS. A helper that guarded PASS alone would have silently
// left the other reporting "no time synchronisation is configured" about a host
// whose configuration it never saw.
//
// The converse is never wrapped. A symlink we *did* find is a fact, and a
// directory we could not read cannot unmake it. That asymmetry is ADR-0014.
func unknownIfIncomplete(s fact.Services, o catalog.Outcome) catalog.Outcome {
	bad := s.Incomplete()
	if len(bad) == 0 {
		return o
	}

	reason := finding.ReasonPermission
	names := make([]string, 0, len(bad))
	ev := make([]finding.Evidence, 0, len(bad))
	for _, d := range bad {
		if d.State == fact.DirError || d.Truncated {
			reason = finding.ReasonAmbiguousState
		}
		names = append(names, d.Path)
		ev = append(ev, dirEvidence(d))
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       o.Subject,
		Detail: fmt.Sprintf(
			"This result rests on not having found an enablement symlink, and %d of the directories that would hold one could not be listed completely (%s). Enablement is a symlink and nothing else records it, so a directory that was not read is a service whose state was not observed.",
			len(bad), strings.Join(names, ", ")),
		Evidence: append(ev, o.Evidence...),
	}
}

// dirEvidence cites one search directory.
//
// There is deliberately no digest. Nothing in this module reads a file, so
// there are no bytes in the evidence store for a digest to point at, and one
// here would be a reference into an archive that does not contain the thing it
// references. Line is 0 for the same reason: the finding is about the inode,
// not about anything inside it.
func dirEvidence(d fact.SearchDir) finding.Evidence {
	switch {
	case d.State == fact.DirRead && d.Truncated:
		return finding.NewEvidence(d.Path, 0, "listing truncated; absence cannot be concluded from it", "")
	case d.State == fact.DirRead:
		return finding.NewEvidence(d.Path, 0,
			fmt.Sprintf("directory: mode %s, uid %d, gid %d", renderPerm(d.Mode), d.UID, d.GID), "")
	case d.State == fact.DirAbsent:
		return finding.NewEvidence(d.Path, 0, "does not exist", "")
	default:
		return finding.NewEvidence(d.Path, 0, string(d.State)+": "+d.Msg, "")
	}
}

// linkEvidence cites one enablement symlink, showing the target as written.
//
// The raw target matters more than the resolved one: it is the string in the
// operator's filesystem, it is what `ls -l` will show them, and where the two
// differ — a relative link — the difference is usually the bug.
func linkEvidence(l fact.UnitLink) finding.Evidence {
	switch {
	case l.Dest == "":
		return finding.NewEvidence(l.Path, 0,
			fmt.Sprintf("%s enabled by %s (a unit file, not a symlink)", l.Unit, l.Target), "")
	case l.DestState == fact.DestDangling:
		return finding.NewEvidence(l.Path, 0,
			fmt.Sprintf("-> %s (resolves to %s, which does not exist)", l.Dest, l.Resolved), "")
	case l.DestState == fact.DestUnknown:
		return finding.NewEvidence(l.Path, 0, fmt.Sprintf("-> %s (%s)", l.Dest, l.Msg), "")
	default:
		return finding.NewEvidence(l.Path, 0, "-> "+l.Dest, "")
	}
}

// unitEvidence cites one unit file.
func unitEvidence(u fact.UnitFile) finding.Evidence {
	switch {
	case u.Masked():
		return finding.NewEvidence(u.Path, 0, "-> /dev/null (masked)", "")
	case u.IsSymlink && u.Dest != "":
		return finding.NewEvidence(u.Path, 0, "-> "+u.Dest, "")
	case u.IsSymlink:
		return finding.NewEvidence(u.Path, 0, "symlink; target unreadable: "+u.DestErr, "")
	default:
		return finding.NewEvidence(u.Path, 0,
			fmt.Sprintf("unit file: mode %s, uid %d, gid %d", renderPerm(u.Mode), u.UID, u.GID), "")
	}
}

// enabledEvidence cites every symlink that enables one unit.
func enabledEvidence(s fact.Services, names []string) []finding.Evidence {
	var ev []finding.Evidence
	for _, n := range names {
		for _, l := range s.LinksTo(n) {
			ev = append(ev, linkEvidence(l))
		}
	}
	return ev
}

// describeStatuses renders what became of a set of unit names that are not
// enabled, so that a PASS says which of them are absent and which are merely
// switched off. The two are the same verdict and different amounts of
// remaining attack surface: an installed-but-disabled service is one
// `systemctl enable` away from running, and survives no package upgrade
// decision at all.
func describeStatuses(s fact.Services, names []string) string {
	var installed, masked []string
	absent := 0
	for _, n := range names {
		switch s.Status(n) {
		case fact.StatusNotEnabled:
			installed = append(installed, n)
		case fact.StatusMasked:
			masked = append(masked, n)
		default:
			absent++
		}
	}

	var parts []string
	if len(installed) > 0 {
		parts = append(parts, fmt.Sprintf("%s %s installed but not enabled, so %s one command away from running",
			join(installed), plural(len(installed), "is", "are"), plural(len(installed), "it is", "they are")))
	}
	if len(masked) > 0 {
		parts = append(parts, fmt.Sprintf("%s %s masked, which nothing can start",
			join(masked), plural(len(masked), "is", "are")))
	}
	if absent > 0 {
		parts = append(parts, fmt.Sprintf("%d of them %s no unit file on this host",
			absent, plural(absent, "has", "have")))
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + sentence(strings.Join(parts, "; ")) + "."
}

// join renders a name list for a detail string.
func join(names []string) string { return strings.Join(names, ", ") }

// plural picks the verb form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sentence capitalises a clause that has been promoted to start a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------------------
// exemptions
// ---------------------------------------------------------------------------

// exemption records a unit a check deliberately does not hold to its standard,
// and why.
//
// **An exemption is not a suppression, and the difference is the whole reason
// this is in the catalog rather than in a config file.** A suppression is an
// operator saying "I have seen this finding and I am accepting it", which
// belongs to the host and lives in a suppressions file. An exemption is this
// tool saying "applying this setting here would break the service, so it is not
// a defect that it is unset" — a property of the software, true on every host
// that runs it, and therefore something the catalog should know rather than
// something every operator should have to rediscover by causing an outage.
//
// The bar for adding one is that the remediation would *break the service*, not
// that it is inconvenient or that a fleet has not got round to it. Two things
// follow, and both are enforced below rather than left to authors:
//
//   - **An exemption never hides a unit this scan could not read.** It says the
//     standard does not apply, which is a claim about a configuration we have
//     seen. A unit whose file was denied has no known configuration, and
//     excusing it would turn "I could not look" into "it is fine".
//   - **An exemption never downgrades a unit that satisfies the check anyway.**
//     A host whose dbus.service does set NoNewPrivileges has a stronger posture
//     than the exemption assumes, and reporting it as skipped would hide work
//     somebody did.
type exemption struct {
	// unit is the unit name, e.g. "dbus.service".
	unit string
	// reason completes the sentence "not held to this standard: it …". It says
	// what breaks, not that something breaks, because the operator's next
	// question is always which of their things stops working.
	reason string
}

// exemptions is a check's exemption list.
//
// A slice rather than a map so the order is the author's and every detail
// string built from it reads the same way on every run; ranging over a map is
// randomised, and a finding whose wording changes between two scans of an
// unchanged host is a finding somebody will diff and misread.
type exemptions []exemption

// reason returns the justification for a unit, and whether it has one.
func (e exemptions) reason(unit string) (string, bool) {
	for _, x := range e {
		if x.unit == unit {
			return x.reason, true
		}
	}
	return "", false
}

// sentence renders the units that were exempted on this host, in list order.
//
// It is always appended when any exemption applied, including to a PASS. A pass
// that did not say which units it skipped would read as "these services are
// hardened" when it means "one of them is, and two were not examined" — and the
// operator who later discovers dbus running without no_new_privs would be right
// to conclude the tool had told them otherwise.
func (e exemptions) sentence(applied []string) string {
	if len(applied) == 0 {
		return ""
	}
	parts := make([]string, 0, len(applied))
	for _, u := range applied {
		if why, ok := e.reason(u); ok {
			parts = append(parts, fmt.Sprintf("%s (%s)", u, why))
		}
	}
	return fmt.Sprintf(" Not held to this standard: %s. An exemption is a documented reason the setting would break the service, not a finding that was suppressed.",
		strings.Join(parts, "; "))
}

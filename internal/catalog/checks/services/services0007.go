package services

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0007 tests whether long-lived root daemons run with /usr read-only.
var Check0007 = catalog.Check{
	ID:     "SERVICES-0007",
	Module: "SERVICES",
	Title:  "Audited system services run with the system directories read-only",

	Description: `ProtectSystem mounts the directories a daemon has no business
writing into read-only, in a mount namespace private to that service. It has
four levels and they are cumulative:

  - no       — the default. The service may write anywhere its uid allows.
  - yes      — /usr and the boot loader directories are read-only.
  - full     — adds /etc.
  - strict   — the entire hierarchy is read-only except /dev, /proc and /sys,
               which is what a daemon with an explicit ReadWritePaths should use.

**Write access to /usr is a persistence vector, not an untidiness.** A daemon
compromised through its own network-facing code can replace a binary that
something else runs as root — a package's helper, a shell that a login invokes,
a systemd generator — and survive the restart of the service that was actually
exploited. Write access to /etc is the same idea one level up: rewrite a PAM
line, a sudoers drop-in, or a unit file, and the next boot hands the attacker
everything. Read-only mounts remove the step entirely rather than making it
harder, which is why this rates above the rest of the sandboxing directives.

Anything from yes upward passes. The check does not insist on strict, because
the right level depends on what the daemon legitimately writes, and a host that
chose yes deliberately is not the problem this exists to find — the problem is
the service that never considered the question and is running with the whole
filesystem writable.

**The value is a superset of the booleans**, in systemd's own resolution order:
true, 1 and on are all yes, and off is no. A build that accepted only the four
enum names would fail a service whose unit says ProtectSystem=true, which is
protected.

**One unit is exempt and one that you might expect to be is not**, and the
contrast is the useful part. cron.service is exempt: it executes arbitrary
operator-supplied jobs inside its own mount namespace, so any filesystem
restriction on the unit silently becomes a restriction on code the packager
never saw. dbus.service is *not* exempt, unlike its exemption from
SERVICES-0006 — its own writes go to /run and /var, and on a systemd host
dbus-activated services are started by systemd as their own units rather than
as children of dbus, so they do not inherit its namespace. The setuid launch
helper that makes NoNewPrivileges unsafe there has nothing to do with where the
daemon may write.`,

	// High. A weakened boundary elsewhere in this module makes a second step
	// easier; this one removes the step. A daemon that can write /usr converts
	// a service compromise into a host compromise that survives reboots, with
	// no exploitation in between — the same reasoning that puts SERVICES-0005
	// (writable unit files) at High, arrived at from the other direction.
	BaseSeverity: finding.High,
	Tags:         []string{"services", "systemd", "sandboxing", "persistence"},
	Requires:     []fact.ID{fact.ServiceHardeningID},
	SinceCatalog: 23,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		h, _, _ := fact.Get[fact.ServiceHardening](fs, fact.ServiceHardeningID)

		if out := sandboxApplicable(h); out != nil {
			return *out
		}

		p := partitionUnits(h, protectSystemExemptions, fact.ServiceSandbox.Protected)
		failed, masked, skipped, unread := p.failed, p.masked, p.skipped, p.unread

		// The level is carried in the name, so a reader can see at a glance that
		// one host is at strict and another merely at yes.
		var passed []string
		for _, s := range p.passed {
			passed = append(passed, fmt.Sprintf("%s (%s)", s.Unit, s.SystemProtection()))
		}

		// ADR-0014: a unit that was read and writes to /usr is a finding
		// whatever else went unread.
		if len(failed) > 0 {
			return protectFailure(failed, passed, masked, skipped, unread)
		}
		if len(unread) > 0 {
			return protectUnknown(unread, passed)
		}

		// Nothing was verified. See SERVICES-0006 for why this is not a pass:
		// an exemption list must be able to make a check stop claiming things,
		// never start claiming everything.
		if len(passed) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf("No unit on this host was held to this standard: of the units this check audits, %s.%s This is the check reporting that it had nothing to examine, not that the host satisfied it.%s",
					describeUnverified(skipped, masked), protectSystemExemptions.sentence(skipped), protectCaveat),
				Evidence: sandboxEvidence(h, skipped),
			}
		}

		detail := fmt.Sprintf("%d of the %d audited service%s installed here %s the system directories read-only: %s. A compromise of %s cannot rewrite a binary under /usr or a boot loader file to survive the service being restarted.",
			len(passed), len(h.Installed()), plural(len(h.Installed()), "", "s"),
			plural(len(passed), "mounts", "mount"), join(passed), plural(len(passed), "it", "them"))
		if len(masked) > 0 {
			detail += fmt.Sprintf(" %s %s masked and %s not examined: systemd will not start %s.",
				join(masked), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"), plural(len(masked), "it", "them"))
		}
		detail += protectSystemExemptions.sentence(skipped)
		return catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail + protectCaveat,
			Evidence: protectEvidence(h, passed, skipped),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set ProtectSystem in a drop-in for each service, starting at full and using ReadWritePaths for what the daemon legitimately writes.",
		Effort:  "LOW",
		Steps: []string{
			"Find out what the service writes before restricting it: systemd-analyze security <unit> gives an overall picture, and running the daemon under strace -f -e trace=file, or simply reading its documentation, tells you which paths it opens for writing.",
			"Start at ProtectSystem=full unless you know the daemon writes to /etc. It covers /usr, the boot loader directories and /etc, and it is the level most system daemons can take unchanged.",
			"Add it as a drop-in rather than editing the vendor unit, so a package upgrade does not undo it: systemctl edit <unit>, then a [Service] section containing ProtectSystem=full.",
			"Where the daemon does write into a protected directory, do not step back down a level — name the exception instead: ReadWritePaths=/etc/example keeps everything else read-only. That is what lets a daemon run at strict.",
			"Reload and restart: systemctl daemon-reload, then systemctl restart <unit>.",
			"Confirm the assembled unit rather than the file you edited: systemctl show -p ProtectSystem <unit> reports what systemd actually loaded, drop-ins and precedence included.",
			"Exercise the service afterwards, including the paths that are rare — a daemon that writes a state file once a day will not fail during the restart.",
		},
		Commands: []string{
			"systemctl show -p ProtectSystem -p ReadWritePaths systemd-journald.service dbus.service",
			"systemd-analyze security dbus.service",
			"systemctl cat dbus.service",
		},
		Caution: "ProtectSystem gives the unit a private mount namespace, so anything the service starts inherits the restriction. That is the point for a daemon and the reason cron.service is exempt: its children are jobs somebody else wrote. Restart services one at a time and check that the daemon still writes what it needs to.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-5"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SI-7"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
	},

	References: []finding.Reference{
		{Title: "systemd.exec(5) — ProtectSystem", URL: "https://man7.org/linux/man-pages/man5/systemd.exec.5.html"},
		{Title: "systemd-analyze(1) — security", URL: "https://man7.org/linux/man-pages/man1/systemd-analyze.1.html"},
	},
}

// protectSystemExemptions are the units this check does not hold to
// ProtectSystem.
//
// **It is one entry where SERVICES-0006 has two, and the difference is the
// point rather than an inconsistency.** An exemption is a claim about a
// specific setting on a specific unit, not a general note that a service is
// awkward, so each check earns its own list. dbus.service is exempt from
// NoNewPrivileges because its launch helper is setuid; nothing about that
// affects where the daemon may write, and on a systemd host dbus-activated
// services are started by systemd as their own units rather than as children
// of dbus, so they do not inherit its mount namespace.
//
// A shared "awkward services" list would have exempted dbus from both, and the
// check would have lost half of what it can actually verify to a reason that
// did not apply to it.
var protectSystemExemptions = exemptions{
	{
		unit: "cron.service",
		reason: "runs arbitrary operator-supplied jobs inside its own mount namespace, so a read-only /usr or /etc " +
			"becomes a restriction on code the packager never saw — a job that updates a package or rewrites a config file " +
			"fails, and fails at the job rather than at the restart",
	},
}

// protectCaveat is appended to every verdict this check draws.
//
// It names three limits. The unit list is fixed; ProtectSystem is one directive
// of a dozen; and the level says what is mounted read-only, not that the daemon
// is confined — a service with ReadWritePaths covering half the host satisfies
// this check and is not sandboxed.
const protectCaveat = " This examines ProtectSystem on a fixed list of units. It says nothing about the other services on this host, nor about the other sandboxing directives on these ones, nor about what a ReadWritePaths= may have opened up again."

// protectFailure builds the FAIL, naming what each unit is missing.
func protectFailure(failed []fact.ServiceSandbox, passed, masked, skipped []string, unread []fact.ServiceSandbox) catalog.Outcome {
	var (
		names []string
		ev    []finding.Evidence
	)
	for _, s := range failed {
		names = append(names, s.Unit)
		ev = append(ev, protectUnitEvidence(s))
	}

	detail := fmt.Sprintf("%s %s the system directories writable, so a compromise of %s can replace a binary under /usr or a boot loader file and survive the service being restarted.",
		join(names), plural(len(failed), "leaves", "leave"), plural(len(failed), "it", "them"))

	// An explicit "no" and an unwritten directive leave the same posture and
	// are different acts, exactly as in SERVICES-0006. The operator who wrote
	// one down considered the question and answered it.
	var written []string
	for _, s := range failed {
		if s.ProtectSystem != "" {
			written = append(written, fmt.Sprintf("%s (%s)", s.Unit, s.ProtectSystem))
		}
	}
	if len(written) > 0 {
		detail += fmt.Sprintf(" In %s the directive is written down and turned off rather than absent, so this is a decision somebody made and not an oversight.",
			join(written))
	}

	var bad []string
	for _, s := range failed {
		for _, m := range s.Malformed {
			if m == "ProtectSystem" {
				bad = append(bad, s.Unit)
			}
		}
	}
	if len(bad) > 0 {
		detail += fmt.Sprintf(" %s %s a ProtectSystem value systemd cannot parse, which it logs and then ignores — so the line is in the file and the mounts are not read-only.",
			join(bad), plural(len(bad), "has", "have"))
	}

	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s.", join(passed), plural(len(passed), "does", "do"))
	}
	if len(masked) > 0 {
		detail += fmt.Sprintf(" %s %s masked and %s not examined.", join(masked), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"))
	}
	if len(unread) > 0 {
		var u []string
		for _, s := range unread {
			u = append(u, s.Unit)
		}
		detail += fmt.Sprintf(" %s could not be read in full, so %s may or may not set it.",
			join(u), plural(len(unread), "it", "them"))
	}
	detail += protectSystemExemptions.sentence(skipped)

	return catalog.Outcome{
		Result:   finding.Fail,
		Subject:  failed[0].Path,
		Detail:   detail + protectCaveat,
		Evidence: ev,
	}
}

// protectUnknown is the verdict when nothing failed and the examination was
// not complete.
func protectUnknown(unread []fact.ServiceSandbox, passed []string) catalog.Outcome {
	reason := finding.ReasonAmbiguousState
	var (
		why []string
		ev  []finding.Evidence
	)
	for _, s := range unread {
		if s.State == fact.UnitDenied {
			reason = finding.ReasonPermission
		}
		for _, f := range s.Incomplete() {
			if f.State == fact.UnitDenied {
				reason = finding.ReasonPermission
			}
			why = append(why, fmt.Sprintf("%s (%s)", f.Path, f.State))
		}
		if s.State != fact.UnitPresent {
			why = append(why, fmt.Sprintf("%s (%s)", s.Path, s.State))
		}
		ev = append(ev, protectUnitEvidence(s))
	}

	detail := fmt.Sprintf("No audited unit was found leaving the system directories writable, but not every unit was read in full, so that is not the same as there being none: %s.",
		strings.Join(why, "; "))
	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s.", join(passed), plural(len(passed), "does", "do"))
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       unread[0].Path,
		Detail:        detail + protectCaveat,
		Evidence:      ev,
	}
}

// protectUnitEvidence cites one unit, showing the level its assembled
// configuration resolves to.
//
// The excerpt distinguishes never-written from written-and-off from
// written-and-rejected, because the remedy differs and the report is where an
// operator finds out which they are looking at. It renders the level as well as
// the text, since "true" and "yes" are the same setting and an operator
// comparing two hosts should not have to know that.
func protectUnitEvidence(s fact.ServiceSandbox) finding.Evidence {
	var excerpt string
	switch {
	case s.State != fact.UnitPresent:
		excerpt = fmt.Sprintf("%s: %s", s.Unit, s.State)
	case len(s.Malformed) > 0 && s.ProtectSystem == "":
		excerpt = s.Unit + ": ProtectSystem set to a value systemd cannot parse"
	case s.ProtectSystem == "":
		excerpt = s.Unit + ": ProtectSystem not set; the default is no"
	default:
		excerpt = fmt.Sprintf("%s: ProtectSystem=%s (%s)", s.Unit, s.ProtectSystem, s.SystemProtection())
	}
	// NewEvidence neutralises the untrusted strings a unit file carries
	// (THREAT-MODEL.md T-03).
	return finding.NewEvidence(s.Path, 0, excerpt, s.Digest)
}

// protectEvidence cites the units behind a passing verdict, the exempt ones
// included so a reader can see their actual state rather than trusting the
// sentence that named them.
func protectEvidence(h fact.ServiceHardening, passed, skipped []string) []finding.Evidence {
	want := make(map[string]bool, len(passed)+len(skipped))
	for _, n := range passed {
		// passed entries carry their level in brackets; the unit name is the
		// part before the space.
		want[strings.SplitN(n, " ", 2)[0]] = true
	}
	for _, n := range skipped {
		want[n] = true
	}
	var ev []finding.Evidence
	for _, s := range h.Services {
		if want[s.Unit] {
			ev = append(ev, protectUnitEvidence(s))
		}
	}
	return ev
}

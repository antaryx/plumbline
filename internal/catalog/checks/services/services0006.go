package services

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0006 tests whether long-lived root daemons set NoNewPrivileges.
var Check0006 = catalog.Check{
	ID:     "SERVICES-0006",
	Module: "SERVICES",
	Title:  "Audited system services set NoNewPrivileges",

	Description: `NoNewPrivileges=yes sets the kernel's no_new_privs bit on a
unit's processes. Once set it cannot be cleared — not by the process, not by
any child it forks, not by exec — and while it is set the kernel refuses to
grant privileges the process did not already have: a setuid binary runs as the
calling user, file capabilities are ignored, and an SELinux or AppArmor
transition that would raise privilege is denied.

What it buys is a smaller second step. A daemon that is compromised through
its own network-facing code has whatever privileges its unit gave it; without
no_new_privs it also has every setuid binary on the host as a way to get more.
The bit turns "find any local escalation" into "escalate with what you already
hold", and it costs nothing at runtime.

**It is not free for every service, and that is the point of reading the unit
rather than assuming.** A daemon that legitimately relies on a setuid helper
breaks outright when the bit is set — the helper simply runs without its
privileges. The remediation below insists on establishing that first, because
setting NoNewPrivileges on the wrong unit is an outage rather than a
regression.

This check reads a fixed, small list of long-lived root daemons rather than
every unit on the host. Reading every unit would mean reading every unit body,
which is what this module exists in order not to do — a bundle would then carry
every ExecStart and every Environment= on the machine.

**A unit that is not installed is skipped, not failed.** cron.service is absent
on a host that uses cronie under another name, and dbus.service on a container
image with no message bus; neither is a finding. If none of the audited units
is installed the check is NOT_APPLICABLE, because there is nothing to have an
opinion about.

Silence is a failure here, and deliberately so. The default is off, so a unit
that never mentions NoNewPrivileges is running without it — the same posture as
one that sets it to no. The two are told apart in the finding anyway, because
they are different acts: an operator who wrote NoNewPrivileges=no had a reason,
and that reason is the first thing to establish before changing it.`,

	// Medium. It is a defence-in-depth measure rather than a boundary: a FAIL
	// means an attacker who already has code execution as the service has an
	// easier second step, not that anything is reachable that was not. It sits
	// below SERVICES-0005, where a writable unit file is the first step rather
	// than the second.
	BaseSeverity: finding.Medium,
	Tags:         []string{"services", "systemd", "sandboxing", "privilege-escalation"},
	Requires:     []fact.ID{fact.ServiceHardeningID},
	SinceCatalog: 22,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		h, _, _ := fact.Get[fact.ServiceHardening](fs, fact.ServiceHardeningID)

		if out := sandboxApplicable(h); out != nil {
			return *out
		}

		var (
			failed []fact.ServiceSandbox
			passed []string
			masked []string
		)
		for _, s := range h.Services {
			switch {
			case !s.Installed():
				// Not on this host. Not a finding: see the description.
				continue
			case s.State == fact.UnitMasked:
				masked = append(masked, s.Unit)
				continue
			case !s.Judgeable():
				// Unreadable. Counted by Unreadable() below rather than here,
				// because it is neither a pass nor a failure.
				continue
			}
			if on, set := fact.OptBool(s.NoNewPrivileges); set && on {
				passed = append(passed, s.Unit)
				continue
			}
			failed = append(failed, s)
		}

		unread := h.Unreadable()

		// A unit that was read and does not set the bit is a finding whatever
		// else went unread — ADR-0014, and the reason this comes first. An
		// incomplete examination invalidates a negative result and never a
		// positive one.
		if len(failed) > 0 {
			return sandboxFailure(failed, passed, masked, unread)
		}

		// No failures found, but the search was not exhaustive. Reporting a
		// pass now would be reporting on units nobody opened.
		if len(unread) > 0 {
			return sandboxUnknown(unread, passed)
		}

		detail := fmt.Sprintf("All %d audited service%s set NoNewPrivileges: %s. A compromise of any of them cannot gain privileges through a setuid binary or file capabilities.",
			len(passed), plural(len(passed), "", "s"), strings.Join(passed, ", "))
		if len(masked) > 0 {
			detail += fmt.Sprintf(" %s %s masked and %s not examined: systemd will not start %s.",
				strings.Join(masked, " and "), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"), plural(len(masked), "it", "them"))
		}
		return catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail + sandboxCaveat,
			Evidence: sandboxEvidence(h, passed),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Add NoNewPrivileges=yes to a drop-in for each service, after establishing that it uses no setuid helper.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Establish what the service needs before changing it. NoNewPrivileges neuters setuid binaries and file capabilities for everything the unit starts, so a daemon that shells out to a setuid helper stops working the moment it is set — and it fails at the helper rather than at startup, so the breakage may not appear until something rare happens.",
			"Two of the units commonly audited here are exactly that case and are worth naming. dbus.service activates system services through dbus-daemon-launch-helper, which is setuid root; setting NoNewPrivileges on it breaks activation. cron.service runs whatever operators put in crontabs, which frequently includes sudo, su or a setuid binary; setting it there breaks those jobs and nothing else reports why.",
			"Where the service is self-contained, add the setting as a drop-in rather than editing the vendor unit, so a package upgrade does not undo it: systemctl edit <unit>, then a [Service] section containing NoNewPrivileges=yes.",
			"Reload and restart: systemctl daemon-reload, then systemctl restart <unit>.",
			"Confirm the assembled unit rather than the file you edited: systemctl show -p NoNewPrivileges <unit> reports what systemd actually loaded, drop-ins and precedence included.",
			"Exercise the service afterwards, including the paths that are rare. A setuid helper that is called once a day will not fail during the restart.",
			"If a service genuinely requires a setuid helper, treat that as the finding and record the exception. The alternative is often to give the unit the one capability it needs — AmbientCapabilities= — and set NoNewPrivileges anyway, which is a smaller grant than every setuid binary on the host.",
		},
		Commands: []string{
			"systemctl show -p NoNewPrivileges -p ProtectSystem -p ProtectHome cron.service systemd-journald.service dbus.service",
			"systemctl cat cron.service",
			"systemd-analyze security cron.service",
		},
		Caution: "Setting NoNewPrivileges on a unit that relies on a setuid helper breaks it, sometimes long after the restart that introduced the change. dbus.service and cron.service are both in that category on most distributions. Establish what each unit actually executes before changing it, and restart services one at a time.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "systemd.exec(5) — NoNewPrivileges", URL: "https://man7.org/linux/man-pages/man5/systemd.exec.5.html"},
		{Title: "Linux kernel — no_new_privs", URL: "https://docs.kernel.org/userspace-api/no_new_privs.html"},
		{Title: "systemd-analyze(1) — security", URL: "https://man7.org/linux/man-pages/man1/systemd-analyze.1.html"},
	},
}

// sandboxCaveat is appended to every verdict this check draws.
//
// It names two limits at once. The unit list is fixed, so a pass says nothing
// about the rest of the host; and NoNewPrivileges is one directive among the
// dozen systemd offers, so a unit that sets it is not thereby sandboxed.
const sandboxCaveat = " This examines NoNewPrivileges on a fixed list of units and says nothing about the other services on this host, nor about the other sandboxing directives on these ones."

// sandboxApplicable gates the check, returning a non-nil outcome when there is
// nothing to judge.
//
// There are two ways to have nothing to judge and they are different
// sentences. A host with no systemd has no units at all; a host with systemd
// and none of the audited units installed runs its cron and its message bus
// under other names, or does not run them. Both are NOT_APPLICABLE and an
// operator reading the report needs to know which.
func sandboxApplicable(h fact.ServiceHardening) *catalog.Outcome {
	if !h.Systemd {
		out := notSystemd()
		return &out
	}
	if len(h.Installed()) == 0 {
		names := make([]string, 0, len(h.Services))
		for _, s := range h.Services {
			names = append(names, s.Unit)
		}
		return &catalog.Outcome{
			Result: finding.NotApplicable,
			Detail: fmt.Sprintf("None of the units this check audits is installed on this host (%s), so there is no unit whose sandboxing to report on. A host may well run the same functions under other unit names, which this check does not look for.",
				strings.Join(names, ", ")),
		}
	}
	return nil
}

// sandboxFailure builds the FAIL, naming every unit and telling the two
// silences apart.
func sandboxFailure(failed []fact.ServiceSandbox, passed, masked []string, unread []fact.ServiceSandbox) catalog.Outcome {
	var (
		names []string
		ev    []finding.Evidence
	)
	for _, s := range failed {
		names = append(names, s.Unit)
		ev = append(ev, sandboxUnitEvidence(s))
	}

	detail := fmt.Sprintf("%s %s not set NoNewPrivileges, so a compromise of %s can gain privileges through any setuid binary or file capability on this host.",
		strings.Join(names, ", "), plural(len(failed), "does", "do"), plural(len(failed), "it", "them"))

	// An explicit "no" and an unwritten directive leave the same posture and
	// are different acts. The operator who wrote one down had a reason, and
	// finding out what it was is the first step of the remediation.
	var written []string
	for _, s := range failed {
		if _, set := fact.OptBool(s.NoNewPrivileges); set {
			written = append(written, s.Unit)
		}
	}
	if len(written) > 0 {
		detail += fmt.Sprintf(" In %s the directive is written down and set to no rather than absent, so this is a decision somebody made and not an oversight.",
			strings.Join(written, " and "))
	}

	// A value systemd would reject is the case an operator most needs telling
	// about: the file looks configured and the setting is not in force.
	var bad []string
	for _, s := range failed {
		for _, m := range s.Malformed {
			if m == "NoNewPrivileges" {
				bad = append(bad, s.Unit)
			}
		}
	}
	if len(bad) > 0 {
		detail += fmt.Sprintf(" %s %s a NoNewPrivileges value systemd cannot parse, which it logs and then ignores — so the line is in the file and the bit is not set.",
			strings.Join(bad, " and "), plural(len(bad), "has", "have"))
	}

	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s set it.", strings.Join(passed, " and "), plural(len(passed), "does", "do"))
	}
	if len(masked) > 0 {
		detail += fmt.Sprintf(" %s %s masked and %s not examined.", strings.Join(masked, " and "), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"))
	}
	if len(unread) > 0 {
		var u []string
		for _, s := range unread {
			u = append(u, s.Unit)
		}
		detail += fmt.Sprintf(" %s could not be read in full, so %s may or may not set it.",
			strings.Join(u, " and "), plural(len(unread), "it", "them"))
	}

	return catalog.Outcome{
		Result:   finding.Fail,
		Subject:  failed[0].Path,
		Detail:   detail + sandboxCaveat,
		Evidence: ev,
	}
}

// sandboxUnknown is the verdict when nothing failed and the examination was
// not complete.
func sandboxUnknown(unread []fact.ServiceSandbox, passed []string) catalog.Outcome {
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
		ev = append(ev, sandboxUnitEvidence(s))
	}

	detail := fmt.Sprintf("No audited unit was found to be missing NoNewPrivileges, but not every unit was read in full, so that is not the same as there being none: %s.",
		strings.Join(why, "; "))
	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s set it.", strings.Join(passed, " and "), plural(len(passed), "does", "do"))
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       unread[0].Path,
		Detail:        detail + sandboxCaveat,
		Evidence:      ev,
	}
}

// sandboxUnitEvidence cites one unit, showing what its assembled configuration
// says about the directive.
//
// The excerpt distinguishes the three ways of not having the bit — never
// written, written as no, written as something systemd rejects — because the
// remedy differs and the report is where an operator finds out which they are
// looking at. Unit fragments are read through ReadOpaque, so the digest is what
// an auditor reproduces on the host rather than something the bundle carries.
func sandboxUnitEvidence(s fact.ServiceSandbox) finding.Evidence {
	var excerpt string
	switch {
	case s.State != fact.UnitPresent:
		excerpt = fmt.Sprintf("%s: %s", s.Unit, s.State)
	case len(s.Malformed) > 0:
		excerpt = s.Unit + ": NoNewPrivileges set to a value systemd cannot parse"
	default:
		on, set := fact.OptBool(s.NoNewPrivileges)
		switch {
		case !set:
			excerpt = s.Unit + ": NoNewPrivileges not set; the default is off"
		case on:
			excerpt = s.Unit + ": NoNewPrivileges=yes"
		default:
			excerpt = s.Unit + ": NoNewPrivileges=no (explicitly disabled)"
		}
	}
	// NewEvidence neutralises the untrusted strings a unit file carries
	// (THREAT-MODEL.md T-03).
	return finding.NewEvidence(s.Path, 0, excerpt, s.Digest)
}

// sandboxEvidence cites the units behind a passing verdict.
func sandboxEvidence(h fact.ServiceHardening, passed []string) []finding.Evidence {
	want := make(map[string]bool, len(passed))
	for _, n := range passed {
		want[n] = true
	}
	var ev []finding.Evidence
	for _, s := range h.Services {
		if want[s.Unit] {
			ev = append(ev, sandboxUnitEvidence(s))
		}
	}
	return ev
}

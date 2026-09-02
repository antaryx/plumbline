package services

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0008 tests whether long-lived root daemons can reach user home
// directories.
var Check0008 = catalog.Check{
	ID:     "SERVICES-0008",
	Module: "SERVICES",
	Title:  "Audited system services cannot reach user home directories",

	Description: `ProtectHome takes /home, /root and /run/user away from a
service, in a mount namespace private to it. It has four levels:

  - no        , the default. The service sees every home directory on the host.
  - yes       , they are empty and inaccessible.
  - read-only , they are mounted read-only. **The contents are still readable.**
  - tmpfs     , they are replaced with empty tmpfs mounts.

**A root daemon that can read /root and /home is one exploit away from every
credential on the estate.** The interesting file is not the user's documents; it
is ~/.ssh/id_ed25519, ~/.aws/credentials, ~/.kube/config, ~/.docker/config.json
and the token some tool cached in ~/.config. None of those is protected by file
permissions against a process already running as root, and all of them are
reusable somewhere else, which turns a single compromised daemon into lateral
movement across every host and cloud account those keys reach. That is why this
sits at High rather than beside the other sandboxing directives: it is the one
whose absence exports the blast radius off the machine.

There is almost never a reason for a system daemon to look. A message bus, a
log writer, a time synchroniser and a name resolver have no business in a user's
home directory, and the ones that do, a backup agent, a file server, are
identifiable and few.

**read-only passes and buys less than the other two.** It stops a daemon
planting an authorized_keys file or a shell profile, which is a real persistence
route closed. It does not stop it reading a private key, which is most of what
the paragraph above is about. The check accepts it, because a host that chose it
deliberately has done something real, and says so in as many words rather than
reporting "home directories are protected" about a service that can still read
every key under /root.

**cron.service is exempt**, for the reason it is exempt from the other two: it
runs arbitrary operator-supplied jobs inside its own mount namespace, and user
cron jobs routinely execute scripts kept in a home directory and read data from
one. dbus.service and systemd-journald.service are audited, neither has any
business in /home, and unlike NoNewPrivileges there is nothing about dbus's
setuid launch helper that bears on where the daemon may read.`,

	// High, and the same as SERVICES-0007 deliberately. That one describes a
	// daemon that can persist on this host; this one describes a daemon that
	// can walk to the next one. Rating them differently would be a claim about
	// which of those is worse, which depends entirely on the estate.
	BaseSeverity: finding.High,
	Tags:         []string{"services", "systemd", "sandboxing", "credential-access", "lateral-movement"},
	Requires:     []fact.ID{fact.ServiceHardeningID},
	SinceCatalog: 24,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		h, _, _ := fact.Get[fact.ServiceHardening](fs, fact.ServiceHardeningID)

		if out := sandboxApplicable(h); out != nil {
			return *out
		}

		p := partitionUnits(h, protectHomeExemptions, fact.ServiceSandbox.HomeProtected)
		failed, masked, skipped, unread := p.failed, p.masked, p.skipped, p.unread

		var passed []string
		for _, s := range p.passed {
			passed = append(passed, fmt.Sprintf("%s (%s)", s.Unit, s.HomeProtection()))
		}

		// ADR-0014: a unit that was read and can reach /root is a finding
		// whatever else went unread.
		if len(failed) > 0 {
			return homeFailure(failed, passed, masked, skipped, unread)
		}
		if len(unread) > 0 {
			return homeUnknown(unread, passed)
		}

		// Nothing was verified. See SERVICES-0006 for why this is not a pass.
		if len(passed) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf("No unit on this host was held to this standard: of the units this check audits, %s.%s This is the check reporting that it had nothing to examine, not that the host satisfied it.%s",
					describeUnverified(skipped, masked), protectHomeExemptions.sentence(skipped), homeCaveat),
				Evidence: sandboxEvidence(h, skipped),
			}
		}

		detail := fmt.Sprintf("%d of the %d audited service%s installed here %s reach user home directories: %s.",
			len(passed), len(h.Installed()), plural(len(h.Installed()), "", "s"),
			plural(len(passed), "cannot", "cannot"), join(passed))

		// read-only is a pass that has to say what it did not buy. A verdict
		// reading "home directories are protected" about a daemon that can
		// still read every private key under /root would be claiming most of
		// this check's own rationale without delivering it.
		var readable []string
		for _, s := range p.passed {
			if s.HomeReadable() {
				readable = append(readable, s.Unit)
			}
		}
		if len(readable) > 0 {
			detail += fmt.Sprintf(" %s %s read-only rather than inaccessible, so %s cannot plant an authorized_keys file or a shell profile there and can still read a private key out of one; yes or tmpfs closes that.",
				join(readable), plural(len(readable), "is", "are"), plural(len(readable), "it", "they"))
		} else {
			detail += " A compromise of any of them cannot read an SSH private key, a cloud credential file or a cached token out of a home directory."
		}

		if len(masked) > 0 {
			detail += fmt.Sprintf(" %s %s masked and %s not examined: systemd will not start %s.",
				join(masked), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"), plural(len(masked), "it", "them"))
		}
		detail += protectHomeExemptions.sentence(skipped)
		return catalog.Outcome{
			Result:   finding.Pass,
			Detail:   detail + homeCaveat,
			Evidence: homeEvidence(h, p.passed, skipped),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set ProtectHome=yes in a drop-in for each service, or tmpfs where the daemon needs the directories to exist.",
		Effort:  "LOW",
		Steps: []string{
			"Establish whether the daemon has any business in a home directory before setting it. Most system services do not; the ones that do, backup agents, file servers, anything that serves user content, are identifiable, and for those the answer is an exemption in your own policy rather than a setting.",
			"Prefer ProtectHome=yes, which makes /home, /root and /run/user empty and inaccessible. Use tmpfs where a daemon needs the directories to exist but not to contain anything.",
			"Use read-only only when the daemon genuinely reads user files. It closes the persistence route, no planted authorized_keys, no altered shell profile, and leaves every private key in those directories readable, which is most of what this check is about.",
			"Add it as a drop-in rather than editing the vendor unit, so a package upgrade does not undo it: systemctl edit <unit>, then a [Service] section containing ProtectHome=yes.",
			"Reload and restart: systemctl daemon-reload, then systemctl restart <unit>.",
			"Confirm the assembled unit rather than the file you edited: systemctl show -p ProtectHome <unit> reports what systemd actually loaded, drop-ins and precedence included.",
			"Treat a daemon that turns out to need /home as the finding rather than the exception: it is the one whose compromise reaches every credential your users keep, and it deserves the attention that discovery just earned it.",
		},
		Commands: []string{
			"systemctl show -p ProtectHome -p ProtectSystem systemd-journald.service dbus.service",
			"systemd-analyze security dbus.service",
			"systemctl cat systemd-journald.service",
		},
		Caution: "ProtectHome gives the unit a private mount namespace, so anything the service starts inherits it. That is the point for a daemon and the reason cron.service is exempt: its children are jobs somebody else wrote, and they routinely live in a home directory. Restart services one at a time.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "systemd.exec(5). ProtectHome", URL: "https://man7.org/linux/man-pages/man5/systemd.exec.5.html"},
		{Title: "systemd-analyze(1), security", URL: "https://man7.org/linux/man-pages/man1/systemd-analyze.1.html"},
	},
}

// protectHomeExemptions are the units this check does not hold to ProtectHome.
//
// One entry, and it is the same unit as SERVICES-0007's for a closely related
// reason: cron executes operator-supplied jobs inside its own mount namespace,
// so any restriction on the unit is a restriction on code the packager never
// saw — and user cron jobs live in home directories more often than they touch
// /usr.
//
// **dbus.service is audited here and by SERVICES-0007, and exempt from
// SERVICES-0006.** That one unit appearing on one of three lists is the clearest
// statement of why the lists are per-check: the setuid launch helper that makes
// NoNewPrivileges unsafe on dbus has nothing to say about where the daemon may
// read. A shared "awkward services" list would have excused it from all three.
var protectHomeExemptions = exemptions{
	{
		unit: "cron.service",
		reason: "runs arbitrary operator-supplied jobs inside its own mount namespace, and user cron jobs " +
			"routinely execute scripts kept in a home directory and read data from one — so the jobs fail, " +
			"and fail at the job rather than at the restart",
	},
}

// homeCaveat is appended to every verdict this check draws.
const homeCaveat = " This examines ProtectHome on a fixed list of units. It says nothing about the other services on this host, nor about the other sandboxing directives on these ones, nor about what a ReadWritePaths= or a BindPaths= may have opened up again."

// homeFailure builds the FAIL, naming what each unit can reach.
func homeFailure(failed []fact.ServiceSandbox, passed, masked, skipped []string, unread []fact.ServiceSandbox) catalog.Outcome {
	var ev []finding.Evidence
	for _, s := range failed {
		ev = append(ev, homeUnitEvidence(s))
	}

	detail := fmt.Sprintf("%s %s /home, /root and /run/user, so a compromise of %s can read an SSH private key, a cloud credential file or a cached token belonging to any user on this host and reuse it elsewhere.",
		join(names(failed)), plural(len(failed), "can reach", "can reach"), plural(len(failed), "it", "them"))

	// An explicit "no" and an unwritten directive leave the same posture and
	// are different acts, as in the two checks beside this one.
	var written []string
	for _, s := range failed {
		if s.ProtectHome != "" {
			written = append(written, fmt.Sprintf("%s (%s)", s.Unit, s.ProtectHome))
		}
	}
	if len(written) > 0 {
		detail += fmt.Sprintf(" In %s the directive is written down and turned off rather than absent, so this is a decision somebody made and not an oversight.",
			join(written))
	}

	// A value systemd rejects is the case worth telling an operator about
	// first: the file says the homes are protected and they are not. "readonly"
	// for "read-only" is the spelling that produces it.
	var bad []string
	for _, s := range failed {
		for _, m := range s.Malformed {
			if m == "ProtectHome" {
				bad = append(bad, s.Unit)
			}
		}
	}
	if len(bad) > 0 {
		detail += fmt.Sprintf(" %s %s a ProtectHome value systemd cannot parse — read-only is hyphenated and nothing else is accepted — which systemd logs and then ignores, so the line is in the file and the home directories are not protected.",
			join(bad), plural(len(bad), "has", "have"))
	}

	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s.", join(passed), plural(len(passed), "does not", "do not"))
	}
	if len(masked) > 0 {
		detail += fmt.Sprintf(" %s %s masked and %s not examined.", join(masked), plural(len(masked), "is", "are"), plural(len(masked), "is", "are"))
	}
	if len(unread) > 0 {
		detail += fmt.Sprintf(" %s could not be read in full, so %s may or may not set it.",
			join(names(unread)), plural(len(unread), "it", "them"))
	}
	detail += protectHomeExemptions.sentence(skipped)

	return catalog.Outcome{
		Result:   finding.Fail,
		Subject:  failed[0].Path,
		Detail:   detail + homeCaveat,
		Evidence: ev,
	}
}

// homeUnknown is the verdict when nothing failed and the examination was not
// complete.
func homeUnknown(unread []fact.ServiceSandbox, passed []string) catalog.Outcome {
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
		ev = append(ev, homeUnitEvidence(s))
	}

	detail := fmt.Sprintf("No audited unit was found able to reach user home directories, but not every unit was read in full, so that is not the same as there being none: %s.",
		strings.Join(why, "; "))
	if len(passed) > 0 {
		detail += fmt.Sprintf(" %s %s.", join(passed), plural(len(passed), "does not", "do not"))
	}
	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       unread[0].Path,
		Detail:        detail + homeCaveat,
		Evidence:      ev,
	}
}

// homeUnitEvidence cites one unit, rendering the level alongside the text so
// that "true" and "yes" do not read as a difference between two hosts.
func homeUnitEvidence(s fact.ServiceSandbox) finding.Evidence {
	var excerpt string
	switch {
	case s.State != fact.UnitPresent:
		excerpt = fmt.Sprintf("%s: %s", s.Unit, s.State)
	case len(s.Malformed) > 0 && s.ProtectHome == "":
		excerpt = s.Unit + ": ProtectHome set to a value systemd cannot parse"
	case s.ProtectHome == "":
		excerpt = s.Unit + ": ProtectHome not set; the default is no"
	default:
		excerpt = fmt.Sprintf("%s: ProtectHome=%s (%s)", s.Unit, s.ProtectHome, s.HomeProtection())
	}
	// NewEvidence neutralises the untrusted strings a unit file carries
	// (THREAT-MODEL.md T-03).
	return finding.NewEvidence(s.Path, 0, excerpt, s.Digest)
}

// homeEvidence cites the units behind a passing verdict, the exempt ones
// included so a reader can see their actual state.
func homeEvidence(h fact.ServiceHardening, passed []fact.ServiceSandbox, skipped []string) []finding.Evidence {
	want := make(map[string]bool, len(passed)+len(skipped))
	for _, s := range passed {
		want[s.Unit] = true
	}
	for _, n := range skipped {
		want[n] = true
	}
	var ev []finding.Evidence
	for _, s := range h.Services {
		if want[s.Unit] {
			ev = append(ev, homeUnitEvidence(s))
		}
	}
	return ev
}

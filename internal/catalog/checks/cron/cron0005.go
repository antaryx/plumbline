package cron

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests whether the schedule is readable by accounts that cannot
// change it.
//
// It ships at LOW and says so in its own detail. Every mainstream distribution
// ships /etc/crontab at 0644 and the drop-in directories at 0755, so this
// fails on a stock host — and unlike CRON-0001 and CRON-0002 the exposure is
// disclosure rather than escalation. Reporting it at the same weight as a
// world-writable cron.d would teach an operator to skim past both.
var Check0005 = catalog.Check{
	ID:     "CRON-0005",
	Module: "CRON",
	Title:  "The cron schedule is not readable by unprivileged accounts",
	Description: `The schedule is reconnaissance. It names what runs as root,
where the scripts live, and — precisely — when. That last part is what makes it
worth restricting: an attacker who knows a backup script runs as root at 03:15
and reads from a directory their account can write knows exactly which file to
place and exactly how long they will wait. Without the schedule they are
guessing at both.

Argument lists are frequently worse than the timing. Cron lines routinely carry
database names, hostnames, API endpoints and occasionally credentials passed on
the command line, all of which a world-readable crontab hands to anyone with a
shell.

**This is a disclosure control, not an escalation one**, and it is reported at
LOW for that reason. CRON-0001 and CRON-0002 cover who may *write* the
schedule, which is the exposure that matters; this check covers who may read
it. The CIS Benchmarks require 0600 on /etc/crontab and 0700 on the drop-in
directories; Debian, Ubuntu, RHEL and Fedora all ship 0644 and 0755, so a host
that has never been hardened fails this by vendor default rather than by
mistake.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"cron", "scheduled-tasks", "information-disclosure"},
	Requires:     []fact.ID{fact.CronID},
	SinceCatalog: 7,

	Eval: func(fs *fact.Set) catalog.Outcome {
		c := cronFact(fs)
		if !c.Installed {
			return notInstalled()
		}

		considered := c.Select(append([]string{cron.CrontabPath}, cron.DropInDirs...)...)
		present := observed(considered)

		if len(present) == 0 && len(c.Unreadable(considered...)) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "Neither the system crontab nor any cron drop-in directory exists on this host, so there is no schedule to disclose.",
			}
		}

		var (
			readable []string
			subjects []string
			evidence []finding.Evidence
		)
		for _, p := range present {
			if p.GroupOrOtherReadable() {
				readable = append(readable, fmt.Sprintf("%s (mode %s)", p.Path, renderPerm(p.Mode)))
				subjects = append(subjects, p.Path)
				evidence = append(evidence, evidenceFor(p))
			}
		}

		if len(readable) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: strings.Join(subjects, ", "),
				Detail: fmt.Sprintf(
					"%d of the %d cron path(s) present on this host can be read by accounts other than root: %s. That discloses what runs as root, from where, and at what time — which is the information an attacker needs to place a file into a job they cannot otherwise reach. This is a disclosure finding at LOW severity, not an escalation one: 0644 and 0755 are the values every mainstream distribution ships, and CRON-0001 and CRON-0002 cover who may write these paths.",
					len(readable), len(present), strings.Join(readable, ", ")),
				Evidence: evidence,
			}
		}

		ev := make([]finding.Evidence, 0, len(present))
		for _, p := range present {
			ev = append(ev, evidenceFor(p))
		}
		return unknownIfUnreadable(c, considered, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d cron path(s) present on this host are readable only by root: %s. What runs as root and when is not disclosed to unprivileged accounts.",
				len(present), joinPaths(present)),
			Evidence: ev,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Remove group and other read permission from the crontab and the drop-in directories.",
		Effort:  "LOW",
		Steps: []string{
			"Decide whether this applies to you first. It is a disclosure control against a local attacker; on a single-user host with no untrusted accounts it protects nothing, and suppressing it with that reason recorded is a legitimate answer.",
			"Tighten the crontab: 'chmod 600 /etc/crontab'.",
			"Tighten the directories: 'chmod 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'.",
			"Check nothing unprivileged depended on reading them: monitoring agents that report scheduled jobs, and configuration-management tools running as a non-root account, are the two that break.",
			"While you are there, look at what the lines actually contain. A credential passed as a command-line argument is visible in 'ps' to every user on the host whatever this file's mode is, so tightening the mode does not fix that one — moving the secret into a root-only environment file does.",
		},
		Commands: []string{
			"stat -c '%n %a %U:%G' /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly",
			"chmod 600 /etc/crontab && chmod 700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly",
		},
		Caution: "run-parts needs no read access for anyone but root, so cron itself is unaffected — but monitoring and configuration-management agents that inventory scheduled jobs as a non-root user will silently start reporting nothing rather than failing loudly. Check what reads these paths before tightening them.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
	},

	References: []finding.Reference{
		{Title: "crontab(5)", URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"},
	},
}

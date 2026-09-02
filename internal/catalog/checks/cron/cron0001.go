package cron

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests who may write the system crontab.
var Check0001 = catalog.Check{
	ID:     "CRON-0001",
	Module: "CRON",
	Title:  "The system crontab is owned by root and writable only by root",
	Description: `/etc/crontab names commands and the accounts they run as, and
cron executes them without asking anything further. Write access to that file
is therefore write access to a root shell that starts on a schedule, no
exploit, no authentication step, and nothing in the file that looks unusual
afterwards, because a crontab entry is what a crontab is supposed to contain.

Two conditions produce it, and they are the same exposure reached two ways. A
file owned by an unprivileged account is one that account can rewrite and
chmod at will, so ownership matters as much as the mode does. A root-owned file
that is group- or world-writable is the same thing without the indirection.

Both are produced by ordinary accidents far more often than by attack: a
deployment script that chowns /etc to a service account, a restored backup that
carried the wrong ownership, an administrator who ran chmod -R on a parent
directory. That is precisely why it is worth checking, nobody remembers doing
it.`,

	BaseSeverity: finding.High,
	Tags:         []string{"cron", "scheduled-tasks", "privilege-escalation", "file-permissions"},
	Requires:     []fact.ID{fact.CronID},
	SinceCatalog: 7,

	Eval: func(fs *fact.Set) catalog.Outcome {
		c := cronFact(fs)
		if !c.Installed {
			return notInstalled()
		}

		p, ok := c.Get(cron.CrontabPath)
		if !ok {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Detail:        "The cron fact carries no record for " + cron.CrontabPath + ".",
				Evidence:      []finding.Evidence{finding.NewEvidence(cron.CrontabPath, 0, "no record", "")},
			}
		}

		switch p.State {
		case fact.CronAbsent:
			// A host can legitimately drive everything from /etc/cron.d and
			// have no /etc/crontab at all. That is not a failure of this rule;
			// there is nothing for the rule to be about. CRON-0002 covers the
			// directories such a host actually uses.
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"%s does not exist. Cron is installed but no system crontab is present, which is normal on a host that schedules everything through %s.",
					cron.CrontabPath, strings.Join(cron.DropInDirs, ", ")),
			}

		case fact.CronDenied, fact.CronError:
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: reasonFor(p),
				Subject:       cron.CrontabPath,
				Detail: fmt.Sprintf(
					"The owner and mode of %s could not be read (%s), so it cannot be established whether an unprivileged account can rewrite what cron runs as root.",
					cron.CrontabPath, p.Msg),
				Evidence: []finding.Evidence{evidenceFor(p)},
			}
		}

		// A symlink is stat'ed as itself, not as its target, so its mode and
		// owner describe the link rather than the file cron actually reads.
		// Concluding either way from that would be describing the wrong inode
		// — and a symlink standing where /etc/crontab should be is exactly the
		// redirection an attacker would install.
		if p.IsSymlink {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       cron.CrontabPath,
				Detail: fmt.Sprintf(
					"%s is a symbolic link. Its owner and mode describe the link rather than the file cron reads through it, and this module does not follow links, so nothing can be concluded about the file actually in force. Resolve the link and audit its target.",
					cron.CrontabPath),
				Evidence: []finding.Evidence{evidenceFor(p)},
			}
		}

		if bad := faults(p); len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: cron.CrontabPath,
				Detail: fmt.Sprintf(
					"%s is %s. Anything written there runs as the account named on the line, and cron does not ask anything further, so this is a root shell on a schedule for whoever holds that write access.",
					cron.CrontabPath, strings.Join(bad, ", and is ")),
				Evidence: []finding.Evidence{evidenceFor(p)},
			}
		}

		return unknownIfUnreadable(c, []fact.CronPath{p}, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"%s is owned by root and writable only by root (%s); no unprivileged account can change what it schedules.",
				cron.CrontabPath, describe(p)),
			Evidence: []finding.Evidence{evidenceFor(p)},
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Restore root ownership and remove group and other write permission.",
		Effort:  "LOW",
		Steps: []string{
			"Read the file before changing anything: 'cat /etc/crontab'. If an unprivileged account could write it, assume it did, and check every line against what you expect to be scheduled.",
			"Restore ownership and mode: 'chown root:root /etc/crontab' then 'chmod 600 /etc/crontab'.",
			"Find out how it happened. A single wrong file is a mistake; a wrong file beside a wrong /etc/cron.d is a chmod -R or a restored backup, and the rest of /etc is likely affected too: 'find /etc -maxdepth 1 ! -user root'.",
			"Check whether the exposure was used: compare the file against configuration management or the package's shipped copy ('dpkg --verify cron' or 'rpm -V cronie'), and look for jobs in the logs that you did not schedule.",
			"There is no reload. cron re-reads the file on its next minute boundary.",
		},
		Commands: []string{
			"stat -c '%n %a %U:%G' /etc/crontab",
			"chown root:root /etc/crontab && chmod 600 /etc/crontab",
		},
		Caution: "Fix the permissions, but do not stop there. If a non-root account could write this file, the correct assumption is that the host is compromised rather than merely misconfigured, read the contents and the logs before you overwrite the evidence.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
	},

	References: []finding.Reference{
		{Title: "crontab(5)", URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"},
	},
}

// reasonFor maps an unreadable path's state to an UNKNOWN reason code.
func reasonFor(p fact.CronPath) finding.UnknownReason {
	if p.State == fact.CronDenied {
		return finding.ReasonPermission
	}
	return finding.ReasonAmbiguousState
}

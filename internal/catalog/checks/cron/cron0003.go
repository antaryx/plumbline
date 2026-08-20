package cron

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests whether access to crontab(1) is restricted by an allow list.
//
// The precedence between the two files is the whole substance of this check,
// and getting it backwards is easy, so it is stated once here and repeated in
// docs/checks/CRON-0003.md:
//
//  1. If /etc/cron.allow EXISTS, only the users named in it may use crontab.
//     /etc/cron.deny is ignored completely — not merged, not consulted.
//  2. If cron.allow does NOT exist and cron.deny does, every user except those
//     named in cron.deny may use crontab.
//  3. If NEITHER exists, the outcome is decided by how the cron package was
//     built, not by anything on the filesystem.
//
// The consequence for the check is that only case 1 is a determinate,
// allow-listed configuration. That is the proposition tested, and it is fully
// decided by which files exist — so cases 2 and 3 are a definite FAIL rather
// than an UNKNOWN, even though case 3's *effect* is unknowable. What cannot be
// determined there is how bad it is, not whether the allow list is missing.
var Check0003 = catalog.Check{
	ID:     "CRON-0003",
	Module: "CRON",
	Title:  "Access to crontab is restricted by an allow list",
	Description: `Who may schedule a job is decided by two files, and they do
not combine. If /etc/cron.allow exists, only the users named in it may run
crontab(1), and /etc/cron.deny is ignored entirely. If cron.allow does not
exist but cron.deny does, everyone except the users named in cron.deny may
schedule jobs. If neither exists, the answer is a compile-time property of the
cron package rather than anything readable on the host: Debian's cron and
Red Hat's cronie make different choices, and both document the behaviour as
site-dependent.

The direction is what matters. An allow list fails closed — an account created
tomorrow is not on it, so it cannot schedule anything until somebody decides it
should. A deny list fails open — the same account is permitted by omission, and
nothing about creating it draws attention to the fact. Every service account a
package installs, every user a directory service introduces, and every account
an attacker adds is admitted by a deny list without a single edit to it.

Scheduled jobs are worth this attention because they are the classic
persistence mechanism. A job survives reboots, runs without a session, and
looks exactly like the legitimate jobs beside it.

This check does not read either file, so it reports which mechanism is in force
rather than who is on the list. An empty cron.allow — the strictest possible
configuration, permitting nobody but root — is indistinguishable here from a
populated one.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"cron", "scheduled-tasks", "access-control", "persistence"},
	Requires:     []fact.ID{fact.CronID},
	SinceCatalog: 7,

	Eval: func(fs *fact.Set) catalog.Outcome {
		c := cronFact(fs)
		if !c.Installed {
			return notInstalled()
		}

		allow, okA := c.Get(cron.AllowPath)
		deny, okD := c.Get(cron.DenyPath)
		if !okA || !okD {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Detail:        "The cron fact carries no record for the access-control files.",
				Evidence:      []finding.Evidence{finding.NewEvidence(cron.AllowPath, 0, "no record", "")},
			}
		}

		// Whether an allow list exists is the entire question, so a cron.allow
		// we could not stat makes the check unanswerable — and it is the one
		// case where cron.deny's state cannot compensate, because an existing
		// cron.allow would render cron.deny irrelevant anyway.
		if allow.State == fact.CronDenied || allow.State == fact.CronError {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: reasonFor(allow),
				Subject:       cron.AllowPath,
				Detail: fmt.Sprintf(
					"Whether %s exists could not be determined (%s). Its presence decides the whole mechanism — it would make %s irrelevant — so neither file's state can be interpreted without it.",
					cron.AllowPath, allow.Msg, cron.DenyPath),
				Evidence: []finding.Evidence{evidenceFor(allow)},
			}
		}

		if allow.State == fact.CronObserved {
			detail := fmt.Sprintf(
				"%s exists, so only the users named in it may schedule jobs and access fails closed: an account created later is not on the list and cannot use crontab until somebody adds it.",
				cron.AllowPath)
			ev := []finding.Evidence{evidenceFor(allow)}

			// Both files present is not a failure, but it is a trap worth
			// naming: cron.deny is ignored outright, so an administrator
			// maintaining it is editing a file with no effect and believing
			// they have removed someone's access. The same shape as the
			// unreachable duplicate entry USERS-0005 reports.
			if deny.State == fact.CronObserved {
				detail += fmt.Sprintf(
					" %s also exists and is being ignored: when %s is present, cron does not consult the deny list at all. Anyone maintaining it is editing a file that has no effect, and should remove it.",
					cron.DenyPath, cron.AllowPath)
				ev = append(ev, evidenceFor(deny))
			}

			return catalog.Outcome{Result: finding.Pass, Detail: detail, Evidence: ev}
		}

		// cron.allow is absent. There is no allow list, and that verdict does
		// not depend on cron.deny — but what happens instead does, so the
		// detail says which of the two open configurations this host is in.
		if deny.State == fact.CronObserved {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: cron.AllowPath,
				Detail: fmt.Sprintf(
					"%s does not exist, so cron falls back to the deny list in %s: every user except those named there may schedule jobs. That fails open — an account created tomorrow is permitted by omission, with no edit to the file and nothing to notice — which is the wrong default for a mechanism whose whole purpose is persistence across reboots.",
					cron.AllowPath, cron.DenyPath),
				Evidence: []finding.Evidence{evidenceFor(allow), evidenceFor(deny)},
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: cron.AllowPath,
			Detail: fmt.Sprintf(
				"Neither %s nor %s exists, so no access-control file governs who may schedule jobs. What happens instead is decided by how this host's cron package was built rather than by anything on the filesystem — Debian's cron and Red Hat's cronie document it as site-dependent and choose differently — so the exposure cannot even be bounded from here. Creating %s resolves both problems at once.",
				cron.AllowPath, cron.DenyPath, cron.AllowPath),
			Evidence: []finding.Evidence{evidenceFor(allow), evidenceFor(deny)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Create /etc/cron.allow listing the accounts that may schedule jobs, and remove /etc/cron.deny.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out who currently schedules anything before restricting it. Per-user crontabs live in the spool — '/var/spool/cron/crontabs' on Debian-family systems, '/var/spool/cron' on Red Hat-family ones — and 'ls' there names every account with a crontab.",
			"Create the allow list with those accounts, one per line: 'printf 'root\\n' > /etc/cron.allow', then add each account you confirmed in the previous step.",
			"Secure the file itself: 'chown root:root /etc/cron.allow' and 'chmod 600 /etc/cron.allow'. CRON-0004 checks this — a writable allow list is an allow list any user can add themselves to.",
			"Remove /etc/cron.deny once cron.allow is in place. Leaving it is not dangerous, but it is inert, and an inert access-control file is one somebody will eventually edit believing it works.",
			"Verify from an unprivileged account that is not on the list: 'crontab -l' should be refused with 'You (user) are not allowed to use this program'.",
		},
		Commands: []string{
			"ls -l /etc/cron.allow /etc/cron.deny",
			"ls /var/spool/cron/crontabs /var/spool/cron 2>/dev/null",
		},
		Caution: "An allow list that omits an account which currently has a crontab does not delete that crontab — the existing job keeps running — but the account can no longer list or edit it, which turns a scheduled job into one nobody can see or change. Enumerate the spool before writing the file, not afterwards.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "crontab(1) — cron.allow and cron.deny", URL: "https://man7.org/linux/man-pages/man1/crontab.1.html"},
	},
}

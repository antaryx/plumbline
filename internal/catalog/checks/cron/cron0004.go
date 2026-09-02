package cron

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests who may write the cron access-control files.
var Check0004 = catalog.Check{
	ID:     "CRON-0004",
	Module: "CRON",
	Title:  "The cron access-control files are owned by root and writable only by root",
	Description: `An access-control file that the accounts it governs can write
is not an access-control file. A writable /etc/cron.allow lets any user append
their own name and schedule jobs; a writable /etc/cron.deny lets them delete
the line that was keeping them out. Either way the restriction CRON-0003
reports as being in force is not in force, and nothing about the configuration
looks wrong. The mechanism is present, correctly named, and doing nothing.

This is the reason CRON-0003 and this check are separate. The first asks which
mechanism governs cron access; this one asks whether that mechanism is beyond
the reach of the people it restricts. A host can pass one and fail the other,
and the combination, an allow list that anyone may edit, is worse than having
no allow list at all, because it produces a report saying access is restricted.

Both files are also world-readable by default on most distributions, which is
harmless: knowing who may schedule jobs is not itself an exposure. Write access
is the whole of the finding here.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"cron", "access-control", "file-permissions"},
	Requires:     []fact.ID{fact.CronID},
	SinceCatalog: 7,

	Eval: func(fs *fact.Set) catalog.Outcome {
		c := cronFact(fs)
		if !c.Installed {
			return notInstalled()
		}

		files := c.Select(cron.AllowPath, cron.DenyPath)
		present := observed(files)

		// Neither file exists. There is nothing here to secure — and the
		// absence is itself CRON-0003's finding, reported there once rather
		// than twice.
		if len(present) == 0 && len(c.Unreadable(files...)) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: fmt.Sprintf(
					"Neither %s nor %s exists, so there is no access-control file whose permissions could be wrong. CRON-0003 reports the absence itself.",
					cron.AllowPath, cron.DenyPath),
			}
		}

		var (
			problems []string
			subjects []string
			evidence []finding.Evidence
		)
		for _, p := range present {
			if bad := faults(p); len(bad) > 0 {
				problems = append(problems, fmt.Sprintf("%s is %s", p.Path, strings.Join(bad, ", and is ")))
				subjects = append(subjects, p.Path)
				evidence = append(evidence, evidenceFor(p))
			}
		}

		if len(problems) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: strings.Join(subjects, ", "),
				Detail: fmt.Sprintf(
					"%s. An access-control file the accounts it governs can write does not restrict them: a user may add their own name to the allow list, or remove it from the deny list, and the restriction CRON-0003 reports as being in force is not.",
					strings.Join(problems, "; ")),
				Evidence: evidence,
			}
		}

		ev := make([]finding.Evidence, 0, len(present))
		for _, p := range present {
			ev = append(ev, evidenceFor(p))
		}
		return unknownIfUnreadable(c, files, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"The cron access-control file(s) present on this host are owned by root and writable only by root: %s.",
				joinPaths(present)),
			Evidence: ev,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Restore root ownership and remove group and other write permission from the access-control files.",
		Effort:  "LOW",
		Steps: []string{
			"Read the file first: 'cat /etc/cron.allow /etc/cron.deny 2>/dev/null'. If an unprivileged account could write it, check every name against who is supposed to be there.",
			"Restore ownership and mode: 'chown root:root /etc/cron.allow' and 'chmod 600 /etc/cron.allow'; the same for /etc/cron.deny if it exists.",
			"Cross-check against the spool. A name added to cron.allow is only useful to an attacker alongside a crontab, so list '/var/spool/cron/crontabs' or '/var/spool/cron' and confirm every entry belongs to somebody who should have one.",
			"Consider removing /etc/cron.deny entirely if /etc/cron.allow exists, cron ignores it, and an ignored file with wrong permissions is a finding nobody can act on usefully.",
		},
		Commands: []string{
			"stat -c '%n %a %U:%G' /etc/cron.allow /etc/cron.deny",
			"chown root:root /etc/cron.allow && chmod 600 /etc/cron.allow",
		},
		Caution: "Changing the mode does not undo anything that was already added while the file was writable. Read the contents and the crontab spool before fixing the permissions, because fixing them first removes the thing that would tell you whether the exposure was used.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
	},

	References: []finding.Reference{
		{Title: "crontab(1)", URL: "https://man7.org/linux/man-pages/man1/crontab.1.html"},
	},
}

package cron

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests who may write the directories cron runs jobs from.
//
// It reports all five directories in one finding rather than one per
// directory. They are a single control — cron executes from all of them
// identically, and an operator who fixes one and leaves another has not
// reduced the exposure at all — so splitting them would produce findings that
// look independently actionable and are not.
var Check0002 = catalog.Check{
	ID:     "CRON-0002",
	Module: "CRON",
	Title:  "The cron drop-in directories are owned by root and writable only by root",
	Description: `cron runs whatever it finds in /etc/cron.d and the four
run-parts directories, and it runs it as root unless the file says otherwise.
Write access to any one of those directories is therefore enough to schedule
arbitrary code as root: an attacker does not need to modify an existing file,
only to create one, which leaves the existing files untouched and every
checksum of them intact.

/etc/cron.d is the sharper of the two shapes, because its files carry a user
field. A file dropped there can name root explicitly regardless of who wrote
it.

The directory's own mode is what matters here, not the modes of the files
inside it. Unix permits creating a file in any directory you can write, whoever
owns the directory's existing contents, so a world-writable /etc/cron.d full of
correctly-owned root files is still a root shell for anyone with an account.`,

	BaseSeverity: finding.High,
	Tags:         []string{"cron", "scheduled-tasks", "privilege-escalation", "file-permissions"},
	Requires:     []fact.ID{fact.CronID},
	SinceCatalog: 7,

	Eval: func(fs *fact.Set) catalog.Outcome {
		c := cronFact(fs)
		if !c.Installed {
			return notInstalled()
		}

		dirs := c.Select(cron.DropInDirs...)
		present := observed(dirs)

		// Not every distribution ships all five. Absent directories are not a
		// finding — cron cannot run anything from a directory that is not
		// there — but if none of them exists there is nothing to assert.
		if len(present) == 0 && len(c.Unreadable(dirs...)) == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "None of the cron drop-in directories exists on this host, so cron runs nothing from them.",
			}
		}

		var (
			problems []string
			subjects []string
			evidence []finding.Evidence
		)
		for _, p := range present {
			var why []string

			// A drop-in path that is not a directory is not the thing this
			// rule is about, and it is worth saying so plainly: a symlink
			// standing where /etc/cron.d should be redirects every job cron
			// runs to a tree somebody else may control.
			if !p.IsDir {
				kind := "not a directory"
				if p.IsSymlink {
					kind = "a symbolic link rather than a directory, so cron runs whatever its target contains and this module does not follow links"
				}
				why = append(why, kind)
			}
			why = append(why, faults(p)...)

			if len(why) > 0 {
				problems = append(problems, fmt.Sprintf("%s is %s", p.Path, strings.Join(why, ", and is ")))
				subjects = append(subjects, p.Path)
				evidence = append(evidence, evidenceFor(p))
			}
		}

		if len(problems) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: strings.Join(subjects, ", "),
				Detail: fmt.Sprintf(
					"%d of the %d cron drop-in director(ies) present on this host can be written by an account other than root: %s. Creating a file in any of them schedules arbitrary code as root, and doing so leaves every existing file — and every checksum of them — untouched.",
					len(problems), len(present), strings.Join(problems, "; ")),
				Evidence: evidence,
			}
		}

		ev := make([]finding.Evidence, 0, len(present))
		for _, p := range present {
			ev = append(ev, evidenceFor(p))
		}
		return unknownIfUnreadable(c, dirs, catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d cron drop-in director(ies) present on this host are owned by root and writable only by root: %s.",
				len(present), joinPaths(present)),
			Evidence: ev,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Restore root ownership and remove group and other write permission from every cron directory.",
		Effort:  "LOW",
		Steps: []string{
			"List what is there before changing it: 'ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'. If a directory was writable, look for files you did not put there — that is the payload, and it will not look out of place.",
			"Restore ownership and mode: 'chown root:root /etc/cron.*' then 'chmod 755 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'. Use 700 instead if you also intend to close CRON-0005.",
			"Check the files inside as well as the directory: 'find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly ! -user root -o -perm /022'.",
			"Establish how it happened. A group-writable cron directory is usually the work of a deployment script that chowned a parent, so the same script has probably done it elsewhere.",
			"There is no reload. cron picks up the change on its next run.",
		},
		Commands: []string{
			"stat -c '%n %a %U:%G' /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly",
			"find /etc/cron.d -type f ! -user root",
		},
		Caution: "Treat a writable cron directory as a compromise until you have shown otherwise. Unlike a modified file, a dropped-in file leaves the rest of the directory byte-identical, so package verification and file-integrity monitoring that only watch known paths will report nothing wrong.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-5"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
	},

	References: []finding.Reference{
		{Title: "cron(8)", URL: "https://man7.org/linux/man-pages/man8/cron.8.html"},
		{Title: "run-parts(8)", URL: "https://man7.org/linux/man-pages/man8/run-parts.8.html"},
	},
}

package logging

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// forbiddenLogBits are the permission bits a log file must not carry: write or
// execute for group, and anything at all for other.
//
// 0640 and 0600 pass; 0644 does not. Group *read* is permitted deliberately —
// it is how an `adm` or `systemd-journal` group gives an operations team read
// access without root, which is a real and desirable arrangement.
const forbiddenLogBits fs.FileMode = 0o037

// rsyslogDefaultFileCreateMode is what rsyslog uses when nothing sets it.
// Documented as 0644 and stable across every rsyslog 5+ release.
const rsyslogDefaultFileCreateMode fs.FileMode = 0o644

// Check0001 tests the permissions rsyslog gives the log files it creates.
var Check0001 = catalog.Check{
	ID:     "LOGGING-0001",
	Module: "LOGGING",
	Title:  "rsyslog creates log files unreadable by other",
	Description: `Log files are the most consistently under-protected sensitive
files on a Unix host. /var/log/auth.log and /var/log/secure record which
accounts authenticated, from where, and by what method; the mail and cron logs
record what runs and when; application logs routinely carry session
identifiers, tokens and query strings that were never meant to leave the
process that wrote them.

rsyslog creates these files itself, with the mode its configuration tells it
to, and its built-in default is 0644 — readable by every account on the host.
An attacker with any unprivileged shell therefore starts with the
authentication history, which tells them which accounts exist, which are used,
and from which addresses a login will not look unusual.

This check requires that group and other cannot write or execute the files, and
that other cannot read them. **Group read is deliberately permitted**: it is
how an 'adm' or 'systemd-journal' group gives an operations team log access
without handing out root, which is a real improvement over the alternative and
should not be reported as a defect.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"logging", "information-disclosure", "file-permissions"},
	Requires:     []fact.ID{fact.RsyslogID},
	SinceCatalog: 8,

	Eval: func(fs *fact.Set) catalog.Outcome {
		r := rsyslogFact(fs)
		if !r.Installed {
			return rsyslogAbsent()
		}

		modes := r.FileCreateModes()

		// Nothing sets it, so rsyslog applies its documented default of 0644 —
		// which other can read. Reporting the default is not a guess: unlike
		// an algorithm list compiled into a binary, this one is a documented
		// scalar that has not changed across the releases in service.
		if len(modes) == 0 {
			out := catalog.Outcome{
				Result:  finding.Fail,
				Subject: "FileCreateMode",
				Detail: fmt.Sprintf(
					"No statement in the %d file(s) read sets the mode of the log files rsyslog creates, so it applies its built-in default of %04o — readable by every account on this host. The authentication log is among the files this affects.",
					len(r.Files), rsyslogDefaultFileCreateMode.Perm()),
				Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
					fmt.Sprintf("neither $FileCreateMode nor a fileCreateMode= parameter is present; built-in default %04o applies",
						rsyslogDefaultFileCreateMode.Perm()))},
			}
			// Here the unresolved-include gate does apply to a FAIL, because
			// the FAIL rests on an *absence* — the statement may be in the
			// file the include was meant to reach.
			if len(r.UnresolvedIncludes) > 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonAmbiguousState,
					Subject:       "FileCreateMode",
					Detail: fmt.Sprintf(
						"No statement setting the log file mode was found, but %d include pattern(s) could not be resolved (%s), so it cannot be established whether one exists in a file this scan never saw.",
						len(r.UnresolvedIncludes), strings.Join(r.UnresolvedIncludes, ", ")),
					Evidence: []finding.Evidence{primaryEvidence(r.Files, r.Digests,
						"unresolved include: "+strings.Join(r.UnresolvedIncludes, ", "))},
				}
			}
			return out
		}

		var (
			bad      []string
			evidence []finding.Evidence
		)
		for _, m := range modes {
			if m.Mode&forbiddenLogBits != 0 {
				bad = append(bad, fmt.Sprintf("%s at %s:%d sets %04o", m.Source, m.File, m.Line, m.Mode.Perm()))
				evidence = append(evidence, modeEvidence(r, m,
					fmt.Sprintf("%04o permits access this check forbids", m.Mode.Perm())))
			}
		}

		if len(bad) > 0 {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "FileCreateMode",
				Detail: fmt.Sprintf(
					"%d of the %d statement(s) setting rsyslog's log file mode grant access beyond the owner and a reading group: %s. Legacy $FileCreateMode is positional — it governs the file actions written after it — so a permissive one applies to whatever follows regardless of what a later line sets.",
					len(bad), len(modes), strings.Join(bad, "; ")),
				Evidence: evidence,
			}
		}

		ev := make([]finding.Evidence, 0, len(modes))
		for _, m := range modes {
			ev = append(ev, modeEvidence(r, m, "restricts group write and all access by other"))
		}
		return unresolvedRsyslog(r, "FileCreateMode", catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d statement(s) setting rsyslog's log file mode restrict it to the owner and a reading group; no account outside that group can read the authentication history.",
				len(modes)),
			Evidence: ev,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Set the log file creation mode to 0640 and fix the files already on disk.",
		Effort:  "LOW",
		Steps: []string{
			"Set the mode in whichever syntax the file already uses. Legacy: '$FileCreateMode 0640' near the top of /etc/rsyslog.conf, before the file actions. RainerScript: add 'fileCreateMode=\"0640\"' to each omfile action, or set it once with a legacy directive — rsyslog accepts both in the same file.",
			"Note that the legacy directive is positional: it governs the actions written after it. Placing it at the bottom of the file changes nothing.",
			"Fix what already exists — the mode only applies to files rsyslog creates from now on: 'chmod o-rwx,g-wx /var/log/*.log' and the same for the rotated copies.",
			"Check logrotate too. 'create' directives in /etc/logrotate.conf and /etc/logrotate.d/ set the mode of the file after rotation and will silently reinstate 0644 at the next rotation.",
			"Restart rsyslog and confirm: 'systemctl restart rsyslog' then 'stat -c \"%n %a\" /var/log/syslog'.",
		},
		Commands: []string{
			"grep -rEn 'FileCreateMode|fileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/",
			"stat -c '%n %a %U:%G' /var/log/*.log",
		},
		Caution: "Tightening the mode breaks anything reading logs as a non-root, non-group account: log shippers, monitoring agents and some web-facing log viewers. Add those agents to the log group rather than widening the mode back — and check logrotate, or the next rotation will undo the change without anybody noticing.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-9"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-4"},
	},

	References: []finding.Reference{
		{Title: "rsyslog.conf(5)", URL: "https://www.rsyslog.com/doc/configuration/index.html"},
	},
}

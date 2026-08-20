package sshd

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0009 tests whether sshd logs enough to reconstruct who connected.
var Check0009 = catalog.Check{
	ID:     "SSHD-0009",
	Module: "SSHD",
	Title:  "sshd logging is detailed enough to reconstruct access",
	Description: `The authentication log is where an SSH compromise is found,
and it is the only place a successful login leaves a durable record. LogLevel
decides how much of that record exists.

At ERROR or below, sshd logs failures of the daemon but not the outcome of
authentication attempts: successful logins produce nothing. An investigation
into "who was on this host last Tuesday" has no source to consult, and the
absence is not visible until the moment it matters.

INFO is the default and logs accepted and failed authentications with the
account, the source address and the method. VERBOSE adds the **fingerprint of
the public key that was used**, which is the difference between knowing that
somebody authenticated as deploy@ and knowing which of the eleven keys in that
account's authorized_keys file did it. On any host where more than one key can
open an account, VERBOSE is what makes key-based logins attributable at all.

DEBUG and DEBUG1-3 fail this check from the other direction. sshd_config(5)
states plainly that logging at DEBUG "violates the privacy of users and is not
recommended": the output includes material from the authentication exchange
that has no place in a log an operations team reads. It also produces enough
volume to roll a log file before an investigator reaches it.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "logging", "forensics", "attribution"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: func(fs *fact.Set) catalog.Outcome {
		insufficient := func(v string) bool {
			switch strings.ToUpper(strings.TrimSpace(v)) {
			case "INFO", "VERBOSE":
				return false
			case "QUIET", "FATAL", "ERROR", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3":
				return true
			}
			return false // unrecognised is a parse problem, not a weakening
		}

		return evaluate(fs, "LogLevel",
			func(cfg fact.SSHDConfig) catalog.Outcome {
				ev := primaryEvidence(cfg, fmt.Sprintf(
					"LogLevel not present in any parsed file; built-in default %q applies", defaultLogLevel))
				desc := fmt.Sprintf("not configured, so sshd applies its built-in default of %q", defaultLogLevel)

				if loosened := loosenedInMatch(cfg, "LogLevel", insufficient); len(loosened) > 0 {
					return conditionalFail(cfg, "LogLevel", desc, ev, loosened, finding.Medium,
						"Connections matching those blocks are logged in less detail than the rest.")
				}
				return catalog.Outcome{
					Result: finding.Pass,
					Detail: fmt.Sprintf(
						"LogLevel is %s, which records accepted and failed authentications with the account, source address and method. Setting VERBOSE additionally records the fingerprint of the key used, which is what makes a key-based login attributable to one key rather than to the account.",
						desc),
					Evidence: []finding.Evidence{ev},
				}
			},

			func(cfg fact.SSHDConfig, d fact.Directive) catalog.Outcome {
				ev := append([]finding.Evidence{directiveEvidence(cfg, d)},
					matchScopedEvidence(cfg, "LogLevel")...)
				value := strings.ToUpper(strings.TrimSpace(d.Value))

				switch value {
				case "INFO", "VERBOSE":
					if loosened := loosenedInMatch(cfg, "LogLevel", insufficient); len(loosened) > 0 {
						return conditionalFail(cfg, "LogLevel",
							fmt.Sprintf("set to %q globally at %s:%d", d.Value, d.File, d.Line),
							ev[0], loosened, finding.Medium,
							"Connections matching those blocks are logged in less detail than the rest.")
					}
					detail := fmt.Sprintf(
						"LogLevel is set to %q at %s:%d; authentication outcomes are recorded with the account, source address and method.",
						d.Value, d.File, d.Line)
					if value == "INFO" {
						detail += " VERBOSE would additionally record the fingerprint of the key used, which is what distinguishes one key from another when an account has several."
					} else {
						detail += " The key fingerprint is recorded, so a login is attributable to the specific key that authenticated it."
					}
					return catalog.Outcome{Result: finding.Pass, Detail: detail, Evidence: ev}

				case "QUIET", "FATAL", "ERROR":
					return catalog.Outcome{
						Result:  finding.Fail,
						Subject: "LogLevel",
						Detail: fmt.Sprintf(
							"LogLevel is set to %q at %s:%d, below the level at which sshd records authentication outcomes. Successful logins produce no log entry, so there is no record of who connected to this host — and the absence only becomes visible during an investigation, when it can no longer be fixed retroactively.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}

				case "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3":
					return catalog.Outcome{
						Result:   finding.Fail,
						Severity: finding.Low,
						Subject:  "LogLevel",
						Detail: fmt.Sprintf(
							"LogLevel is set to %q at %s:%d. sshd_config(5) states that logging at this level violates the privacy of users: the output carries material from the authentication exchange that does not belong in an operational log, and the volume can roll the file before an investigator reads it. Debug levels are for diagnosing a specific fault, not for running a host.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}

				default:
					return catalog.Outcome{
						Result:        finding.Unknown,
						UnknownReason: finding.ReasonParse,
						Subject:       "LogLevel",
						Detail: fmt.Sprintf(
							"LogLevel has unrecognised value %q at %s:%d; sshd accepts QUIET, FATAL, ERROR, INFO, VERBOSE or DEBUG1-3 and would reject this configuration, so the running server may be using a different file.",
							d.Value, d.File, d.Line),
						Evidence: ev,
					}
				}
			})
	},

	Remediation: &finding.Remediation{
		Summary: "Set LogLevel VERBOSE, and confirm the log is actually being collected.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config. INFO also passes this check; VERBOSE additionally records key fingerprints and is what makes key-based logins individually attributable.",
			"Verify the fingerprints are appearing: after a key login, 'journalctl -u sshd | grep -i \"Accepted publickey\"' should show a SHA256: fingerprint.",
			"Confirm the log leaves the host. A local authentication log is deleted by whoever compromises the host; forwarding to a collector is what makes it evidence. LOGGING module checks cover that side.",
			"If the level was at DEBUG, check the existing log files for authentication material before rotating them, and rotate them rather than leaving them in place.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i loglevel",
			"journalctl -u sshd -n 50",
		},
		Caution: "VERBOSE increases log volume noticeably on a busy bastion. Check the retention and disk headroom on the log partition before making the change, or the first symptom will be a full filesystem rather than a better audit trail.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-2"},
		{Framework: "nist-800-53-r5", Control: "AU-3"},
		{Framework: "nist-800-53-r5", Control: "AU-12"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — LogLevel", URL: "https://man.openbsd.org/sshd_config#LogLevel"},
	},
}

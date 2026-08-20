package logging

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests whether journald hands its records to rsyslog.
//
// It reads both facts, and the order matters: rsyslog first, so that on a host
// without rsyslog the runner's gate and this check both reach the same
// conclusion — there is nothing to forward to.
var Check0004 = catalog.Check{
	ID:     "LOGGING-0004",
	Module: "LOGGING",
	Title:  "journald forwards to syslog where rsyslog is present",
	Description: `On a host running both daemons, journald is where records
arrive and rsyslog is what sends them anywhere else. If journald does not hand
them over, rsyslog's forwarding rules (LOGGING-0002) receive nothing from the
journal — and the host looks correctly configured from either file alone.

That is the failure worth catching: two configurations that are each defensible
and that do not connect. An operator who has set up remote logging in rsyslog
and reads LOGGING-0002 passing has every reason to believe the records are
leaving, and the gap is visible only by reading the two files together.

**The proposition tested is that forwarding is explicitly configured**, not
that it happens to be on. journald's default for ForwardToSyslog has changed
across systemd versions — it was yes historically and is no in current
releases — and Plumbline does not read the systemd version. Relying on an
unstated default that has already flipped once is not a configuration, so an
absent setting is a definite FAIL rather than an UNKNOWN: the fact tested, "it
is explicitly set", is decided by the files. This is the same shape as
CRON-0003.

This check is NOT_APPLICABLE where rsyslog is not installed. A journald-only
host has nothing to forward to, and LOGGING-0002 and LOGGING-0003 are the
checks that apply to it.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"logging", "forensics", "integration"},
	Requires:     []fact.ID{fact.JournaldID, fact.RsyslogID},
	SinceCatalog: 8,

	Eval: func(fs *fact.Set) catalog.Outcome {
		j := journaldFact(fs)
		r := rsyslogFact(fs)

		if !r.Installed {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "rsyslog is not configured on this host, so there is no syslog daemon for journald to forward to. LOGGING-0003 covers whether the journal itself is durable.",
			}
		}
		if !j.Installed {
			return journaldAbsent()
		}

		setting, configured := j.Effective("ForwardToSyslog")

		if !configured {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "ForwardToSyslog",
				Detail: fmt.Sprintf(
					"rsyslog is configured on this host but ForwardToSyslog is not set in any of the %d journald file(s) read, so whether records reach rsyslog depends on a built-in default that has changed across systemd releases — yes historically, no in current versions. rsyslog's own forwarding rules therefore may be receiving nothing from the journal while both files look correct in isolation.",
					len(j.Files)),
				Evidence: []finding.Evidence{primaryEvidence(j.Files, j.Digests,
					"ForwardToSyslog is not set in any file read; the effective value is a version-dependent default")},
			}
		}

		ev := append([]finding.Evidence{
			settingEvidence(j, setting, "the effective value; systemd applies the last occurrence"),
		}, overriddenEvidence(j, "ForwardToSyslog")...)

		on, ok := fact.BoolValue(setting.Value)
		if !ok {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonParse,
				Subject:       "ForwardToSyslog",
				Detail: fmt.Sprintf(
					"ForwardToSyslog is set to %q at %s:%d; systemd accepts yes, no, true, false, on, off, 1 or 0 and would reject this, so the running configuration is not what this file says.",
					setting.Value, setting.File, setting.Line),
				Evidence: ev,
			}
		}

		if !on {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "ForwardToSyslog",
				Detail: fmt.Sprintf(
					"ForwardToSyslog is set to %q at %s:%d while rsyslog is configured on this host. Records stay in the journal and rsyslog receives nothing from it, so any forwarding rule rsyslog carries is sending an empty stream.",
					setting.Value, setting.File, setting.Line),
				Evidence: ev,
			}
		}

		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"ForwardToSyslog is set to %q at %s:%d, so journald hands its records to rsyslog and rsyslog's own rules decide where they go from there.",
				setting.Value, setting.File, setting.Line),
			Evidence: ev,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set ForwardToSyslog=yes explicitly, or remove rsyslog if it is not being used.",
		Effort:  "LOW",
		Steps: []string{
			"Decide which daemon owns forwarding first. Running both with journald not forwarding is a common and reasonable arrangement — if rsyslog is installed but unused, removing it is the better fix and makes this check NOT_APPLICABLE.",
			"To connect them, set 'ForwardToSyslog=yes' under [Journal], preferably in a drop-in under /etc/systemd/journald.conf.d/. Set it explicitly even if the current default already does what you want: the default has changed once and may again.",
			"Restart journald: 'systemctl restart systemd-journald'.",
			"Verify end to end rather than by reading the file: 'logger -p auth.info plumbline-test' and confirm the line appears in the rsyslog-written file, not only in 'journalctl'.",
			"Watch for duplication. With forwarding on and the journal persistent, every record is stored twice — that is usually the intent, but it doubles the disk the logs consume.",
		},
		Commands: []string{
			"systemd-analyze cat-config systemd/journald.conf | grep -i forwardtosyslog",
			"logger -p auth.info plumbline-test",
		},
		Caution: "Turning forwarding on doubles log volume on a host that also persists the journal, and on a busy host that can fill /var faster than anybody expects. Check SystemMaxUse and the rsyslog side's rotation before making the change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-6"},
		{Framework: "nist-800-53-r5", Control: "AU-9(2)"},
	},

	References: []finding.Reference{
		{Title: "journald.conf(5) — ForwardToSyslog", URL: "https://www.freedesktop.org/software/systemd/man/journald.conf.html"},
	},
}

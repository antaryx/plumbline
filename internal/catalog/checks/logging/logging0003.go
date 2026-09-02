package logging

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests whether the journal survives a reboot.
var Check0003 = catalog.Check{
	ID:     "LOGGING-0003",
	Module: "LOGGING",
	Title:  "The systemd journal is stored persistently",
	Description: `A volatile journal lives in /run/log/journal, which is a
tmpfs. Every record in it is destroyed at the next boot, and "the machine was
rebooted" is a description of most incidents, whether the reboot was the
attacker covering their tracks, a kernel panic they caused, or an operator
restarting a host that was behaving oddly. Investigating afterwards means
investigating a host that deleted its own evidence.

The setting has three meaningful values and a fourth that is the reason this
check needs more than the configuration file:

| Storage | Effect |
|---|---|
| persistent | /var/log/journal, created if absent; survives reboot |
| volatile | /run/log/journal only; destroyed at reboot |
| none | nothing is stored at all |
| auto (the default) | persistent **if /var/log/journal already exists**, volatile otherwise |

Because auto is the default and its effect is a property of the filesystem
rather than of the configuration, this check stats /var/log/journal. Without
that one observation the answer would be UNKNOWN on the majority of hosts,
which would be honest and useless.

Persistence is not a substitute for forwarding (LOGGING-0002). A persistent
journal is still a local file that root can delete; it survives a reboot, not
an attacker.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"logging", "forensics", "retention"},
	Requires:     []fact.ID{fact.JournaldID},
	SinceCatalog: 8,

	Eval: func(fs *fact.Set) catalog.Outcome {
		j := journaldFact(fs)
		if !j.Installed {
			return journaldAbsent()
		}

		setting, configured := j.Effective("Storage")
		persistent, known := j.StoresPersistently()

		var ev []finding.Evidence
		if configured {
			ev = append(ev, settingEvidence(j, setting, "the effective value; systemd applies the last occurrence"))
			ev = append(ev, overriddenEvidence(j, "Storage")...)
		} else {
			ev = append(ev, primaryEvidence(j.Files, j.Digests,
				"Storage is not set in any file read; journald applies its default of auto"))
		}
		ev = append(ev, finding.NewEvidence(j.PersistentDirPath, 0,
			"journal directory: "+string(j.PersistentDirState), ""))

		if !known {
			// Either the value is one journald would refuse, or it is auto and
			// the directory could not be stat'ed. Both leave what is running
			// undetermined.
			reason := finding.ReasonAmbiguousState
			detail := fmt.Sprintf(
				"Storage resolves to auto and %s could not be examined, so whether the journal survives a reboot depends on a directory this scan could not see.",
				j.PersistentDirPath)
			if configured {
				if _, ok := recognisedStorage(setting.Value); !ok {
					reason = finding.ReasonParse
					detail = fmt.Sprintf(
						"Storage is set to %q at %s:%d; journald accepts only persistent, volatile, auto or none and would reject this, so the running configuration is not what this file says.",
						setting.Value, setting.File, setting.Line)
				}
			}
			return catalog.Outcome{
				Result: finding.Unknown, UnknownReason: reason,
				Subject: "Storage", Detail: detail, Evidence: ev,
			}
		}

		if !persistent {
			how := fmt.Sprintf("Storage is set to %q at %s:%d", setting.Value, setting.File, setting.Line)
			if !configured {
				how = fmt.Sprintf("Storage is not configured, so journald applies its default of auto, and %s does not exist",
					j.PersistentDirPath)
			}
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: "Storage",
				Detail: fmt.Sprintf(
					"%s, so the journal is held in a tmpfs and every record in it is destroyed at the next boot. An investigation after a reboot — which describes most incidents — has nothing local to read.",
					how),
				Evidence: ev,
			}
		}

		how := fmt.Sprintf("Storage is set to %q at %s:%d", setting.Value, setting.File, setting.Line)
		if !configured {
			how = fmt.Sprintf("Storage is not configured, so journald applies its default of auto, and %s exists",
				j.PersistentDirPath)
		}
		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"%s, so the journal is written to disk and survives a reboot. Note that persistence is not tamper-resistance: the file is still local, and LOGGING-0002 is what puts a copy beyond this host's reach.",
				how),
			Evidence: ev,
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set Storage=persistent and give the journal a size limit.",
		Effort:  "LOW",
		Steps: []string{
			"Set 'Storage=persistent' under [Journal] in /etc/systemd/journald.conf, or in a drop-in under /etc/systemd/journald.conf.d/, the drop-in is the better place on a configuration-managed host, and it overrides the main file.",
			"Bound the size in the same change: 'SystemMaxUse=1G' or similar. journald defaults to 10% of the filesystem, which on a large disk is a great deal of space and on a small one is a disk-full outage.",
			"Create the directory and restart: 'mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal && systemctl restart systemd-journald'.",
			"Confirm it took effect: 'journalctl --disk-usage' reports the on-disk size, and 'journalctl --list-boots' should show more than the current boot once the host has been restarted.",
		},
		Commands: []string{
			"systemd-analyze cat-config systemd/journald.conf",
			"journalctl --disk-usage",
		},
		Caution: "Persisting the journal starts consuming disk on a host that was not consuming any. Set SystemMaxUse in the same change, a full /var is an outage, and on many hosts it is an outage that also stops the logging you just enabled.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-4"},
		{Framework: "nist-800-53-r5", Control: "AU-11"},
		{Framework: "nist-800-53-r5", Control: "AU-9"},
	},

	References: []finding.Reference{
		{Title: "journald.conf(5)", URL: "https://www.freedesktop.org/software/systemd/man/journald.conf.html"},
	},
}

// recognisedStorage reports whether a value is one journald accepts.
func recognisedStorage(v string) (string, bool) {
	switch normalise(v) {
	case "persistent", "volatile", "auto", "none":
		return normalise(v), true
	}
	return "", false
}

package services

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// TimeSyncUnits are the network time daemons the major distributions ship,
// under every name they ship them as.
//
// Names differ per distribution for the same software — chrony's unit is
// chronyd.service on Red Hat and chrony.service on Debian — so a check written
// against one name reports "no time synchronisation" on the other, which is a
// wrong verdict produced entirely by packaging.
var TimeSyncUnits = []string{
	"systemd-timesyncd.service",
	"chronyd.service", "chrony.service",
	"ntpd.service", "ntp.service", "ntpsec.service",
	"openntpd.service",
	"timemaster.service",
}

// Check0003 tests that exactly one time synchronisation daemon is enabled.
//
// Both halves matter and they fail differently. None means the clock drifts;
// more than one means two daemons fight over it, which is a distinct and more
// confusing failure than having neither.
var Check0003 = catalog.Check{
	ID:     "SERVICES-0003",
	Module: "SERVICES",
	Title:  "Exactly one time synchronisation daemon is enabled",
	Description: `An accurate clock is a security control, not housekeeping.
Three things break without it, and each breaks quietly.

Log correlation is the first. An incident is reconstructed by ordering events
across hosts, and a host whose clock is minutes out contributes events that
appear in the wrong place in the sequence — or, worse, appear to have happened
before the intrusion that caused them. The investigation does not fail loudly;
it produces a timeline that is wrong.

Authentication is the second. Kerberos rejects tickets outside a five-minute
skew by design, because the timestamp is the replay defence. TLS certificates,
signed tokens, TOTP codes and short-lived cloud credentials all fail closed
against a clock that has drifted — and an operator debugging that failure will
find nothing wrong with the certificate.

Scheduled work is the third. Certificate renewal, log rotation and credential
rotation all run on timers, and a clock that jumps can skip a window entirely.

Two daemons enabled at once is its own failure and a subtler one. They compete
for the same UDP port and for the same clock: the second to start fails to bind
and exits, and which one that is depends on start order rather than on
configuration. The host then synchronises through whichever daemon won, using
whichever server list that one was given — which is very often not the list the
administrator edited. This is a common outcome of installing chrony on a system
already running systemd-timesyncd, because installing it does not disable the
other.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"services", "systemd", "time", "logging", "authentication"},
	Requires:     []fact.ID{fact.ServicesID},
	SinceCatalog: 9,

	Eval: func(fs *fact.Set) catalog.Outcome {
		s := servicesFact(fs)
		if !s.Systemd {
			return notSystemd()
		}

		enabled := s.AnyEnabled(TimeSyncUnits...)

		switch {
		case len(enabled) == 0:
			// Drawn from absence: a directory we could not list might hold the
			// enablement symlink that makes this a PASS. This is the branch
			// that a PASS-only guard would have got wrong.
			return unknownIfIncomplete(s, catalog.Outcome{
				Result:  finding.Fail,
				Subject: "systemd-timesyncd.service",
				Detail: fmt.Sprintf(
					"No time synchronisation daemon is enabled; none of the %d units this check knows about will start at boot. The clock will drift with the hardware, which puts this host's log timestamps out of step with every other host's, and eventually fails Kerberos, TLS and any short-lived credential that carries an expiry.%s",
					len(TimeSyncUnits), describeStatuses(s, TimeSyncUnits)),
				Evidence: []finding.Evidence{
					finding.NewEvidence("/etc/systemd/system", 0, "no .wants symlink names any time synchronisation unit", ""),
				},
			})

		case len(enabled) > 1:
			// Positive: we found them. No listing we missed can unmake that,
			// so this one is never wrapped.
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: enabled[0],
				Detail: fmt.Sprintf(
					"%d time synchronisation daemons are enabled at once (%s). They compete for the same UDP port and the same clock: the second to start fails to bind and exits, so which one disciplines the clock depends on start order rather than on configuration, and the server list actually in use is very often not the one that was edited. Enable one and mask the others.",
					len(enabled), join(enabled)),
				Evidence: enabledEvidence(s, enabled),
			}

		default:
			// PASS also rests on absence — of a *second* daemon — so it is
			// wrapped for the same reason the none-branch is.
			return unknownIfIncomplete(s, catalog.Outcome{
				Result:   finding.Pass,
				Subject:  enabled[0],
				Detail:   fmt.Sprintf("%s is enabled and is the only time synchronisation daemon that will start at boot, so nothing competes with it for the clock.", enabled[0]),
				Evidence: enabledEvidence(s, enabled),
			})
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Enable exactly one time synchronisation daemon and mask the rest.",
		Effort:  "LOW",
		Steps: []string{
			"Choose one. chrony is the right default on almost anything: it converges faster than ntpd, copes with intermittent connectivity and virtualised clocks, and is what both Red Hat and Debian ship as the recommendation. systemd-timesyncd is a reasonable choice for a client that only needs SNTP and is already present.",
			"Establish what is enabled now, including the one you did not install: 'systemctl list-unit-files --state=enabled | grep -E 'chrony|ntp|timesync''.",
			"Enable the one you chose: 'systemctl enable --now chronyd.service' (or 'chrony.service' on Debian-family systems).",
			"Mask every other one: 'systemctl mask systemd-timesyncd.service'. Mask rather than disable — installing an NTP package re-runs its preset, and a merely disabled unit can come back enabled.",
			"Point it at servers you control or trust, in /etc/chrony.conf or /etc/chrony/chrony.conf. A host that takes its time from an arbitrary public pool takes it from whoever answers first.",
			"Verify it is actually disciplining the clock rather than merely running: 'chronyc tracking' shows the reference source and the current offset; 'timedatectl' reports whether the system clock is synchronised at all.",
		},
		Commands: []string{
			"timedatectl",
			"systemctl list-unit-files --state=enabled | grep -E 'chrony|ntp|timesync'",
			"chronyc tracking",
		},
		Caution: "A host whose clock is badly wrong will have it stepped when synchronisation starts, and a large backward step can make log timestamps go backwards and confuse anything holding a lease or a timer. On a host that has drifted for months, expect the correction to be visible in the logs and note when it happened.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-8"},
		{Framework: "nist-800-53-r5", Control: "SC-45"},
	},

	References: []finding.Reference{
		{Title: "systemd-timesyncd.service(8)", URL: "https://man7.org/linux/man-pages/man8/systemd-timesyncd.service.8.html"},
		{Title: "chronyd(8)", URL: "https://man7.org/linux/man-pages/man8/chronyd.8.html"},
	},
}

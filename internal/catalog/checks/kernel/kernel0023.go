package kernel

import (
	"fmt"
	"strconv"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0023 tests whether SYN cookies are written to the sysctl
// configuration, rather than merely running.
var Check0023 = catalog.Check{
	ID:     "KERNEL-0023",
	Module: "KERNEL",
	Title:  "TCP SYN cookies are written to the sysctl configuration",

	Description: `A SYN flood fills a listening socket's backlog with half-open
connections from addresses that never complete the handshake. The queue is
finite, so once it is full the service refuses legitimate clients while the
attacker spends almost nothing. SYN cookies remove the queue from the
equation: on overflow the kernel stops storing connection state and encodes it
in the sequence number it returns, reconstructing the connection only if the
client completes the handshake.

net.ipv4.tcp_syncookies takes three values:

  - 0, never. The backlog is the only defence.
  - 1, on overflow. The upstream default, and the value to write down.
  - 2, always, rather than only under overflow.

**Every distribution the corpus covers runs 1 already, and almost none of them
say so in a file.** That is the finding. A running value with nothing behind it
is one container runtime, one network-tuning role, or one sysctl -w in a
start-up script away from being 0, and nothing on the host records that anyone
ever chose it. The parameter is also a favourite of performance tuning guides,
which is a specific way it gets turned off by someone who is not thinking about
floods.

2 passes. It uses cookies for every connection rather than only under overflow,
which is stricter and costs a few TCP options, window scaling, SACK and
timestamps cannot be carried in a cookie, on every connection rather than only
during an attack. That is a throughput decision, not a security one, so a host
that has made it is passed and told what it costs.

This is a check about files. KERNEL-0016 asks what the running kernel does.`,

	// Low, and deliberately the same as KERNEL-0016 rather than a band above
	// it. The persistence checks that outrank their runtime counterparts do so
	// because the setting is a boundary that will silently fall down —
	// KERNEL-0017 and KERNEL-0019 are of that kind. This one is availability
	// hardening: it grants an attacker nothing and removes a cheap way to deny
	// service. Ranking an unwritten SYN-cookie setting alongside an unwritten
	// ptrace scope would mis-sort a triage queue, which is the harm a severity
	// is there to prevent.
	BaseSeverity: finding.Low,
	Tags:         []string{"kernel", "sysctl", "persistence", "denial-of-service"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 29,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{syncookiesKey}, persistSyncookiesCaveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(syncookiesKey)
		if !found {
			detail := fmt.Sprintf("%s is not set in any sysctl configuration file, so after the next reboot it is whatever the kernel defaults to.", syncookiesKey)
			if r, ok := sc.Run(syncookiesKey); ok && r.State == fact.SysctlObserved {
				if v, isInt := r.Int(); isInt && v >= 1 {
					detail += fmt.Sprintf(" The running kernel has it at %d, so this host is defended now on a default nobody wrote down: a performance-tuning drop-in, a container runtime or a sysctl -w in a start-up script can set it to 0 and nothing here records that it was ever meant to be 1.", v)
				} else if isInt {
					detail += fmt.Sprintf(" The running kernel has it at %d as well, so the backlog is the only thing standing between a listening socket and a SYN flood right now.", v)
				}
			}
			return tierAbsence(catalog.Outcome{
				Result:   finding.Fail,
				Subject:  syncookiesKey,
				Detail:   detail,
				Evidence: searchedEvidence(sc, nil),
			}, sc, syncookiesTiering, persistSyncookiesCaveat)
		}

		n, err := strconv.Atoi(set.Value)
		if err != nil {
			return unparseableConfig(sc, syncookiesKey, set, persistSyncookiesCaveat)
		}

		switch {
		case n == 1:
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: syncookiesKey,
				Detail: fmt.Sprintf("%s is 1 %s, so a listening socket whose backlog overflows falls back to cookies instead of refusing connections, and it stays that way across a reboot.%s%s",
					syncookiesKey, configuredAt(sc, syncookiesKey, set),
					runningMismatch(sc, syncookiesKey, set.Value), persistSyncookiesCaveat),
				Evidence: configuredEvidence(sc, syncookiesKey),
			}

		case n >= 2:
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: syncookiesKey,
				Detail: fmt.Sprintf("%s is %d %s, so cookies are used for every connection rather than only when a backlog overflows, and it stays that way across a reboot. That is stricter than the 1 this check asks for and it is not free: window scaling, SACK and timestamps cannot be carried in a cookie, so every connection loses them rather than only the ones made during a flood.%s%s",
					syncookiesKey, n, configuredAt(sc, syncookiesKey, set),
					runningMismatch(sc, syncookiesKey, set.Value), persistSyncookiesCaveat),
				Evidence: configuredEvidence(sc, syncookiesKey),
			}

		case n == 0:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: syncookiesKey,
				Detail: fmt.Sprintf("%s is 0 %s, which turns the fallback off: a listening socket's backlog is finite, and once it is full of half-open connections the service refuses legitimate clients. This is written down, so it is a decision somebody made rather than a default nobody set — performance-tuning guides recommend it, and the throughput it buys is not worth the socket.%s%s",
					syncookiesKey, configuredAt(sc, syncookiesKey, set),
					runningMismatch(sc, syncookiesKey, "0"), persistSyncookiesCaveat),
				Evidence: configuredEvidence(sc, syncookiesKey),
			}
		}

		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonAmbiguousState,
			Subject:       syncookiesKey,
			Detail: fmt.Sprintf("%s is %d at %s:%d, which is not one of the documented values 0, 1 or 2. What the kernel does with it depends on the build, so what this host does after a reboot cannot be determined from the file.%s",
				syncookiesKey, n, set.File, set.Line, persistSyncookiesCaveat),
			Evidence: configuredEvidence(sc, syncookiesKey),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write net.ipv4.tcp_syncookies = 1 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn tcp_syncookies /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. Alpine ships it in a vendor file; most distributions rely on the kernel default and write nothing.",
			"Create or extend a drop-in containing net.ipv4.tcp_syncookies = 1. Write it down even though the running kernel almost certainly reports 1 already: that is the built-in default, not a decision, and a tuning drop-in that sets it to 0 will win silently.",
			"Leave it at 1 rather than 2 unless something specific calls for it. 1 uses cookies only when a backlog overflows, so a normal connection keeps window scaling, SACK and timestamps; 2 gives those up on every connection for no benefit outside a sustained flood.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl net.ipv4.tcp_syncookies.",
			"Raise the backlog as well if the service is genuinely busy: cookies are the fallback for an overflowing queue, and net.core.somaxconn together with the application's own listen() backlog decide how often the fallback is reached.",
		},
		Commands: []string{
			"sysctl net.ipv4.tcp_syncookies",
			"grep -rn tcp_syncookies /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Value 1 costs nothing on a host that is not under attack, because the fallback only engages when a backlog overflows. Value 2 is the one to be careful with: it drops window scaling, SACK and timestamps on every connection, which is measurable on a high-throughput or high-latency link.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-5"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, ip-sysctl tcp_syncookies", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const syncookiesKey = "net.ipv4.tcp_syncookies"

// persistSyncookiesCaveat names the check that reads the running value.
var persistSyncookiesCaveat = persistCaveatFor("KERNEL-0016")

// syncookiesTiering is the runtime cross-reference for the absence case.
var syncookiesTiering = []requirement{{key: syncookiesKey, accept: func(n int) bool { return n >= 1 }}}

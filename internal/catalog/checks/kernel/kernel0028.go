package kernel

import (
	"fmt"
	"strconv"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0028 tests whether the RFC 1337 TIME-WAIT protection is written to the
// sysctl configuration.
var Check0028 = catalog.Check{
	ID:     "KERNEL-0028",
	Module: "KERNEL",
	Title:  "RFC 1337 TIME-WAIT protection is written to the sysctl configuration",

	Description: `When a TCP connection closes, the side that closed first holds
the socket in TIME-WAIT for twice the maximum segment lifetime. The socket is
doing something during that time: it holds the four-tuple so that a segment
from the old connection, delayed somewhere in the network, cannot arrive after
a new connection has taken the same tuple and be accepted as part of it.

**A reset ends TIME-WAIT early, and that is the hazard RFC 1337 describes.** An
RST for a socket in TIME-WAIT tears it down immediately and frees the tuple for
reuse. A delayed segment from the old connection can then land inside the new
one — the sequence numbers may fall in the new window by chance, or be chosen —
and the receiver accepts data that belongs to a connection that ended.

net.ipv4.tcp_rfc1337 = 1 makes the kernel drop RSTs aimed at TIME-WAIT sockets
instead of acting on them, which is the mitigation the RFC recommends. **The
kernel defaults to 0**, so no host has this unless someone set it.

The realistic reach of this is narrow, and the severity says so. An attacker
needs to be on the path or able to guess a four-tuple and a sequence number,
and what they get is a corrupted or reset connection rather than access to
anything. It belongs in a hardening baseline because it costs nothing, not
because it closes a common door.

This is a check about files. Nothing reads the running value yet.`,

	// Low. The precondition — on-path, or a correctly guessed tuple and
	// sequence number — is most of the work, and the outcome is data
	// corruption on one connection rather than a foothold. Rating it higher
	// would put it alongside findings that hand over traffic wholesale, which
	// is what a severity is there to prevent.
	BaseSeverity: finding.Low,
	Tags:         []string{"kernel", "sysctl", "persistence", "tcp"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 30,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, []string{rfc1337Key}, persistRFC1337Caveat); out != nil {
			return *out
		}

		set, found := sc.EffectiveConfigured(rfc1337Key)
		if !found {
			detail := fmt.Sprintf("%s, so after the next reboot it is the kernel's default of 0: a reset aimed at a socket in TIME-WAIT tears it down early, and a delayed segment from the finished connection can be accepted into a new one that has taken the same four-tuple.", notConfigured(sc, rfc1337Key))
			if r, ok := sc.Run(rfc1337Key); ok && r.State == fact.SysctlObserved {
				if v, isInt := r.Int(); isInt && v == 1 {
					detail += " The running kernel has it at 1, so this host is protected now and will not be after the next reboot unless something sets it again outside these files."
				}
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  rfc1337Key,
				Detail:   detail + persistRFC1337Caveat,
				Evidence: searchedEvidence(sc, nil),
			}
		}

		n, err := strconv.Atoi(set.Value)
		if err != nil {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       rfc1337Key,
				Detail: fmt.Sprintf("%s is %q %s, which is not a number. What the kernel does with a value it cannot parse depends on the build, so what this host does after a reboot cannot be determined from the file.%s",
					rfc1337Key, set.Value, configuredAt(sc, rfc1337Key, set), persistRFC1337Caveat),
				Evidence: configuredEvidence(sc, rfc1337Key),
			}
		}

		if n == 1 {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: rfc1337Key,
				Detail: fmt.Sprintf("%s is 1 %s, so a reset aimed at a socket in TIME-WAIT is dropped rather than acted on, and the socket serves out its wait absorbing anything still in flight from the connection that ended. It stays that way across a reboot.%s%s",
					rfc1337Key, configuredAt(sc, rfc1337Key, set),
					runningMismatch(sc, rfc1337Key, set.Value), persistRFC1337Caveat),
				Evidence: configuredEvidence(sc, rfc1337Key),
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: rfc1337Key,
			Detail: fmt.Sprintf("%s is %d %s, which is the unprotected behaviour written down rather than inherited: a reset ends TIME-WAIT early, freeing the four-tuple while a delayed segment from the finished connection may still arrive and be accepted into whatever takes it next.%s%s",
				rfc1337Key, n, configuredAt(sc, rfc1337Key, set),
				runningMismatch(sc, rfc1337Key, set.Value), persistRFC1337Caveat),
			Evidence: configuredEvidence(sc, rfc1337Key),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write net.ipv4.tcp_rfc1337 = 1 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets it: grep -rn tcp_rfc1337 /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. Expect nothing — the kernel defaults to 0 and no distribution in this project's corpus ships it.",
			"Create or extend a drop-in containing net.ipv4.tcp_rfc1337 = 1.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl net.ipv4.tcp_rfc1337.",
			"Do not pair this with net.ipv4.tcp_tw_reuse or the long-removed tcp_tw_recycle as a set of 'TIME-WAIT tuning'. They pull in opposite directions: this one makes TIME-WAIT more durable on purpose, and those exist to get out of it sooner.",
		},
		Commands: []string{
			"sysctl net.ipv4.tcp_rfc1337",
			"grep -rn tcp_rfc1337 /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
		},
		Caution: "Effectively none. Sockets already in TIME-WAIT stay there for their full wait instead of being cut short by a reset, which is what the state is for. A host exhausting its ephemeral ports under very high connection churn is the only place the extra durability is felt, and the answer there is the port range and keep-alive behaviour rather than accepting resets from anyone.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-5"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "RFC 1337 — TIME-WAIT Assassination Hazards in TCP", URL: "https://www.rfc-editor.org/rfc/rfc1337"},
		{Title: "Linux kernel — ip-sysctl tcp_rfc1337", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
	},
}

const rfc1337Key = "net.ipv4.tcp_rfc1337"

// persistRFC1337Caveat names the absent runtime counterpart.
var persistRFC1337Caveat = persistCaveatUnpaired()

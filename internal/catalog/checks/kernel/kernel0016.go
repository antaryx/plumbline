package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0016 tests that TCP SYN cookies are available.
var Check0016 = catalog.Check{
	ID:     "KERNEL-0016",
	Module: "KERNEL",
	Title:  "TCP SYN cookies are enabled",
	Description: `A SYN flood fills a listening socket's backlog with half-open
connections from addresses that never complete the handshake. The queue is
finite, so once it is full the service refuses legitimate connections while
using almost no resources on the attacker's side.

SYN cookies remove the queue from the equation: when the backlog overflows the
kernel stops storing connection state and encodes it in the sequence number it
returns, reconstructing the connection only if the client completes the
handshake. The cost is that a few TCP options cannot be carried in a cookie, so
the kernel enables them only under overflow rather than always.

Severity is LOW deliberately. This is availability hardening, it grants an
attacker nothing, it removes a cheap way to deny service, and treating it as
equivalent to a privilege-escalation finding would mis-rank a triage queue.`,

	BaseSeverity: finding.Low,
	Tags:         []string{"kernel", "network", "denial-of-service", "availability"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: intCheck(
		"net.ipv4.tcp_syncookies",
		func(n int) bool { return n >= 1 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 1:
				return "net.ipv4.tcp_syncookies is 1; the kernel falls back to SYN cookies when a listening socket's backlog overflows."
			case ok:
				return fmt.Sprintf("net.ipv4.tcp_syncookies is %d; SYN cookies are used unconditionally rather than only under overflow, which is stricter and disables a few TCP options for every connection.", n)
			default:
				return "net.ipv4.tcp_syncookies is 0; a SYN flood can fill a listening socket's backlog and deny service to legitimate clients using very little bandwidth."
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set net.ipv4.tcp_syncookies to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w net.ipv4.tcp_syncookies=1",
			"Persist it: write 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl net.ipv4.tcp_syncookies",
			"Leave the value at 1 rather than 2 unless you have a specific reason: 2 applies cookies to every connection and disables TCP options that a normal workload benefits from.",
		},
		Commands: []string{
			"sysctl -w net.ipv4.tcp_syncookies=1",
			"sysctl net.ipv4.tcp_syncookies",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-5"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation, ip-sysctl tcp_syncookies", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
	},
}

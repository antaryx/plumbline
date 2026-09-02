package kernel

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0027 tests whether this host is configured not to send ICMP redirects.
var Check0027 = catalog.Check{
	ID:     "KERNEL-0027",
	Module: "KERNEL",
	Title:  "Sending ICMP redirects is refused in the sysctl configuration",

	Description: `An ICMP redirect is a router telling a host on its own segment
that there is a better first hop for some destination. Only a router has any
business sending one, and a host that is not routing has nothing to say.

KERNEL-0025 asks whether this host *accepts* redirects, which is the
man-in-the-middle exposure. This asks whether it *sends* them, which is a
smaller and different problem:

  - **It describes the network to anyone who can reach this host.** A redirect
    names a gateway and a destination, so an attacker who can elicit one learns
    a route they were not told about, internal topology, from the outside of
    it.
  - **It is a statement that this host is forwarding at all.** On a machine
    that is not meant to be a router, a redirect leaving it is evidence that
    something turned forwarding on.

**The parameter only has effect while forwarding is enabled, which is exactly
why it is worth writing down.** A host that is not forwarding sends no
redirects whatever this says, so setting it costs nothing today, and container
runtimes, VPN daemons and virtualisation hosts all enable
net.ipv4.ip_forward as a side effect of being installed. Docker turns it on at
start-up. The value of writing 0 down is that the day something enables
forwarding, this host still does not start advertising routes.

Both keys are checked. conf.default is the template every interface created
after boot inherits, which on a host running containers is a new interface
every few seconds.

This is a check about files. Nothing reads the running value yet.`,

	// Medium. It leaks routing topology and signals unintended forwarding; it
	// does not by itself give an attacker a position. That places it with the
	// other routing findings and below the ones that hand over traffic.
	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "sysctl", "persistence", "routing"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 30,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, requirementKeys(sendRedirectsPersistent), persistSendRedirectsCaveat); out != nil {
			return *out
		}

		res := checkRequirements(sc, sendRedirectsPersistent)
		if len(res.failed) > 0 {
			return tierRequirementFailure(catalog.Outcome{
				Result:  finding.Fail,
				Subject: "sysctl configuration",
				Detail: capitaliseFirst(strings.Join(res.failed, "; ")) +
					". Only a router has any business sending a redirect, and a host that emits one describes a route it was not asked about to whoever elicited it." +
					forwardingNote(sc),
				Evidence: searchedEvidence(sc, res.evidence),
			}, sc, sendRedirectsPersistent, res, persistSendRedirectsCaveat)
		}

		return catalog.Outcome{
			Result:  finding.Pass,
			Subject: "sysctl configuration",
			Detail: "Sending ICMP redirects is refused in the sysctl configuration, for the host-wide key and for the template every interface created later inherits. If something enables IP forwarding on this host — a container runtime, a VPN daemon, a virtualisation stack — it still will not start advertising routes to its neighbours." +
				runningContradiction(sc, sendRedirectsPersistent) + persistSendRedirectsCaveat,
			Evidence: searchedEvidence(sc, res.evidence),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write net.ipv4.conf.all.send_redirects = 0 and net.ipv4.conf.default.send_redirects = 0 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check whether this host is meant to route: sysctl net.ipv4.ip_forward. If it is a router, a NAT gateway or a firewall with more than one leg, leave this alone, sending redirects is part of the job and suppressing them makes traffic take a longer path rather than no path.",
			"Check what already sets it, patterns included: grep -rn send_redirects /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d.",
			"Create or extend a drop-in containing net.ipv4.conf.all.send_redirects = 0 and net.ipv4.conf.default.send_redirects = 0.",
			"Apply without rebooting: sysctl --system, then confirm with sysctl -a | grep send_redirects.",
			"Expect the running value to be 1 on a host with Docker or libvirt installed even though nothing configured it. Those enable net.ipv4.ip_forward, which is what makes send_redirects reachable at all; this setting is what stops that side effect from turning into route advertisements.",
		},
		Commands: []string{
			"sysctl net.ipv4.ip_forward",
			"sysctl -a 2>/dev/null | grep send_redirects",
			"grep -rn send_redirects /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
		},
		Caution: "On a genuine router this suppresses a legitimate optimisation: hosts on the segment keep sending through this machine instead of learning the better first hop, so traffic takes an extra hop rather than failing. Do not set it on a device whose purpose is to route.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, ip-sysctl send_redirects", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "RFC 1122. Requirements for Internet Hosts", URL: "https://www.rfc-editor.org/rfc/rfc1122"},
	},
}

// sendRedirectsPersistent are the two keys the configuration has to carry.
var sendRedirectsPersistent = []requirement{
	{
		key:     "net.ipv4.conf.all.send_redirects",
		accept:  refused,
		absence: "nothing stops this host advertising routes to its neighbours if anything enables IP forwarding on it, and the kernel defaults this to 1",
		wrong:   "this host will send ICMP redirects to its neighbours whenever it forwards a packet",
	},
	{
		key:     "net.ipv4.conf.default.send_redirects",
		accept:  refused,
		absence: "every interface created after boot inherits the kernel's default of 1, which on a host running containers is a new interface every few seconds",
		wrong:   "every interface created after boot will send ICMP redirects when it forwards",
	},
}

// persistSendRedirectsCaveat names the absent runtime counterpart.
var persistSendRedirectsCaveat = persistCaveatUnpaired()

// forwardingNote says whether the condition this parameter depends on is
// currently true.
//
// Without it the finding is about a setting that does nothing on most hosts,
// which is a fair objection an operator will raise. With it the finding either
// says "and this host is forwarding right now", which makes it immediate, or
// says nothing, which leaves it as the defence in depth it is.
func forwardingNote(sc fact.Sysctl) string {
	r, ok := sc.Run("net.ipv4.ip_forward")
	if !ok || r.State != fact.SysctlObserved || strings.TrimSpace(r.Value) == "0" {
		return ""
	}
	return fmt.Sprintf(" IP forwarding is on right now (net.ipv4.ip_forward is %s), so this is not hypothetical: this host is a router today, whether or not anyone decided it should be.", strings.TrimSpace(r.Value))
}

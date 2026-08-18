package kernel

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// rpFilterAll and rpFilterDefault are the two parameters that are not
// interfaces. "all" is combined with each interface's own value; "default" is
// the template copied into interfaces created later and governs nothing that
// already exists.
const (
	rpFilterAll    = "net.ipv4.conf.all.rp_filter"
	rpFilterPrefix = "net.ipv4.conf."
	rpFilterSuffix = ".rp_filter"
)

// Check0008 tests that reverse-path filtering is enabled on every interface.
var Check0008 = catalog.Check{
	ID:     "KERNEL-0008",
	Module: "KERNEL",
	Title:  "Reverse-path filtering is enabled on every network interface",
	Description: `Reverse-path filtering makes the kernel drop an incoming packet
whose source address it would not route back out of the interface the packet
arrived on. Without it, a host accepts packets claiming to come from anywhere,
which is what makes source-address spoofing useful: an attacker on one network
segment can impersonate an address on another, defeating any control that
trusts a source address and hiding the true origin of an attack.

The parameter is namespaced per interface and the effective value for an
interface is the *maximum* of net.ipv4.conf.all.rp_filter and that interface's
own setting. A check that read conf.all alone would report a host as unfiltered
while every interface on it was in fact filtering, so this check computes the
effective value per interface.

Value 1 is strict mode: the reverse path must be the same interface. Value 2 is
loose mode: the source must be routable via some interface. Loose mode is a
deliberate and correct choice on a multi-homed host with asymmetric routing, so
it passes, and the finding says which interfaces are in it.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "network", "spoofing"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		probed := sc.RunningMatching(rpFilterPrefix, rpFilterSuffix)
		if len(probed) == 0 {
			// The collector could not enumerate /proc/sys/net/ipv4/conf, or
			// the listing was incomplete. Reporting on an empty set would read
			// as "no unfiltered interfaces found", which is a PASS built out
			// of having looked at nothing.
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Detail:        "The per-interface reverse-path-filter parameters could not be enumerated, so no statement can be made about which interfaces filter spoofed source addresses.",
				Evidence:      []finding.Evidence{finding.NewEvidence("/proc/sys/net/ipv4/conf", 0, "interface list unavailable", "")},
			}
		}

		all, allOK := intValue(sc, rpFilterAll)

		var (
			unfiltered []string
			loose      []string
			considered int
			denied     []string
			evidence   []finding.Evidence
		)

		for _, r := range probed {
			iface := interfaceOf(r.Key)
			switch iface {
			case "all", "default":
				// "all" is folded into every interface below. "default" is a
				// template for interfaces that do not exist yet and governs
				// no traffic, so it is not judged here.
				continue
			case "lo":
				// Loopback traffic never crosses a network boundary and its
				// reverse path is always the loopback interface. Distributions
				// leave this at 0 as a matter of course, and failing it would
				// produce a finding on almost every host that no operator can
				// act on.
				continue
			}

			if r.State != fact.SysctlObserved {
				if r.State == fact.SysctlDenied {
					denied = append(denied, iface)
				}
				continue
			}
			n, ok := r.Int()
			if !ok {
				denied = append(denied, iface)
				continue
			}

			considered++
			effective := n
			if allOK && all > effective {
				effective = all
			}
			switch {
			case effective == 0:
				unfiltered = append(unfiltered, iface)
				evidence = append(evidence, evidenceFor(r))
			case effective == 2:
				loose = append(loose, iface)
			}
		}

		sort.Strings(unfiltered)
		sort.Strings(loose)
		sort.Strings(denied)

		if len(unfiltered) > 0 {
			if allRun, ok := sc.Run(rpFilterAll); ok && allRun.State == fact.SysctlObserved {
				evidence = append(evidence, evidenceFor(allRun))
			}
			detail := fmt.Sprintf(
				"Reverse-path filtering is off on %d interface(s): %s. The kernel accepts packets on these interfaces regardless of whether it could route a reply to their claimed source, so source addresses on them cannot be trusted.",
				len(unfiltered), joinKeys(unfiltered))
			if allOK {
				detail += fmt.Sprintf(" %s is %d, so it does not raise them.", rpFilterAll, all)
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Detail:   detail,
				Evidence: evidence,
			}
		}

		if considered == 0 {
			if len(denied) > 0 {
				return catalog.Outcome{
					Result:        finding.Unknown,
					UnknownReason: finding.ReasonPermission,
					Detail: fmt.Sprintf(
						"The reverse-path-filter setting could not be read for any interface (%s), so whether spoofed source addresses are dropped cannot be determined.",
						joinKeys(denied)),
					Evidence: []finding.Evidence{finding.NewEvidence("/proc/sys/net/ipv4/conf", 0, "per-interface values unreadable", "")},
				}
			}
			// Only loopback exists. There is no interface whose source
			// addresses could be spoofed from elsewhere.
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "This host has no non-loopback network interface, so there is no path on which a spoofed source address could arrive.",
			}
		}

		detail := fmt.Sprintf(
			"Reverse-path filtering is enabled on all %d non-loopback interface(s); packets with unroutable source addresses are dropped.",
			considered)
		if len(loose) > 0 {
			detail += fmt.Sprintf(
				" %s in loose mode (value 2), which accepts a source routable via any interface — correct for asymmetric routing, weaker than strict mode.",
				joinKeys(loose))
		}
		if len(denied) > 0 {
			detail += fmt.Sprintf(
				" The value for %s could not be read and is not included.",
				joinKeys(denied))
		}
		return catalog.Outcome{Result: finding.Pass, Detail: detail}
	},

	Remediation: &finding.Remediation{
		Summary: "Set net.ipv4.conf.all.rp_filter to 1 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Confirm this host does not rely on asymmetric routing: a multi-homed host that receives replies on a different interface than it sends from needs loose mode (2), not strict (1).",
			"Apply immediately: sysctl -w net.ipv4.conf.all.rp_filter=1",
			"Set the template for interfaces created later: sysctl -w net.ipv4.conf.default.rp_filter=1",
			"Persist both in /etc/sysctl.d/60-hardening.conf.",
			"Verify per interface: sysctl -a | grep '\\.rp_filter'",
		},
		Commands: []string{
			"sysctl -w net.ipv4.conf.all.rp_filter=1",
			"sysctl -w net.ipv4.conf.default.rp_filter=1",
		},
		Caution: "Strict mode drops traffic on a host with asymmetric routing, which can remove your own access if you are connected over the interface that stops accepting replies. On a multi-homed or policy-routed host, use loose mode (2) and verify connectivity from a second session before persisting the change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-5"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel documentation — ip-sysctl rp_filter", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "RFC 3704 — Ingress Filtering for Multihomed Networks", URL: "https://www.rfc-editor.org/rfc/rfc3704"},
	},
}

// interfaceOf extracts the interface name from a per-interface sysctl key.
// The name is whatever sits between the prefix and the suffix, taken whole:
// a VLAN device is called "eth0.1" and splitting on dots would lose it.
func interfaceOf(key string) string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(key, rpFilterPrefix), rpFilterSuffix)
	return path.Clean(trimmed)
}

// intValue reads one parameter as an integer, reporting false unless it was
// observed and parsed.
func intValue(sc fact.Sysctl, key string) (int, bool) {
	r, ok := sc.Run(key)
	if !ok {
		return 0, false
	}
	return r.Int()
}

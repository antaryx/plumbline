package kernel

import (
	"fmt"
	"sort"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

const (
	srrAll    = "net.ipv4.conf.all.accept_source_route"
	srrSuffix = ".accept_source_route"
)

// Check0015 tests that source-routed packets are refused.
var Check0015 = catalog.Check{
	ID:     "KERNEL-0015",
	Module: "KERNEL",
	Title:  "Source-routed packets are refused on every network interface",
	Description: `A source-routed packet carries its own return path. The sender
dictates which hops the reply traverses, which lets an attacker steer traffic
through a machine they control, reach addresses that are not routable from
where they are, and receive replies to a source address they have spoofed,
because the reply follows the attached route rather than the routing table.

There is no legitimate modern use. IP source routing was deprecated for exactly
these reasons and RFC 7126 records that the correct handling on a host is to
drop such packets.

**The combining rule is the opposite of the one KERNEL-0008 uses, and the
difference matters.** An interface accepts source routing only when
net.ipv4.conf.all.accept_source_route *and* that interface's own setting are
both non-zero, the kernel takes the logical AND, where for rp_filter it takes
the maximum. So conf.all at 0 disables source routing everywhere regardless of
per-interface values, and a check that reused the rp_filter logic here would
report a safe host as unsafe.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "network", "spoofing", "routing"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		probed := sc.RunningMatching(rpFilterPrefix, srrSuffix)
		if len(probed) == 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonFactMissing,
				Detail:        "The per-interface source-routing parameters could not be enumerated, so no statement can be made about whether this host accepts source-routed packets.",
				Evidence:      []finding.Evidence{finding.NewEvidence("/proc/sys/net/ipv4/conf", 0, "interface list unavailable", "")},
			}
		}

		all, allKnown := intValue(sc, srrAll)
		allRun, _ := sc.Run(srrAll)

		// conf.all at 0 is decisive on its own: the AND can never be true, so
		// no interface accepts source routing whatever its own value says.
		// Concluding this without reading a single interface is correct, and
		// it is why the combining rule had to be looked up rather than copied.
		if allKnown && all == 0 {
			detail := fmt.Sprintf(
				"%s is 0, and an interface accepts source routing only when conf.all and its own setting are both non-zero, so source-routed packets are refused on every interface.",
				srrAll)
			if raised := nonZeroInterfaces(probed); len(raised) > 0 {
				detail += fmt.Sprintf(
					" These interfaces still carry a non-zero value of their own, which has no effect while conf.all is 0 but would take effect if it were raised: %s.",
					joinKeys(raised))
			}
			note, driftEv := driftNote(sc, srrAll, allRun.Value)
			return catalog.Outcome{
				Result:   finding.Pass,
				Detail:   detail + note,
				Evidence: append([]finding.Evidence{evidenceFor(allRun)}, driftEv...),
			}
		}

		var (
			accepting  []string
			unreadable []string
			considered int
			evidence   []finding.Evidence
		)

		for _, r := range probed {
			switch iface := interfaceOf(r.Key, srrSuffix); iface {
			case "all", "default":
				// conf.all is folded in above. conf.default is the template
				// copied into interfaces created later and governs no traffic
				// today, so it is not judged.
				continue
			case "lo":
				// A source-routed packet cannot arrive over loopback.
				continue
			default:
				n, parsed := r.Int()
				if r.State != fact.SysctlObserved || !parsed {
					unreadable = append(unreadable, iface)
					continue
				}
				considered++
				if n == 0 {
					// Safe by itself: the AND is false whatever conf.all is,
					// so this interface is settled even when conf.all is not.
					continue
				}
				if allKnown {
					accepting = append(accepting, iface)
					evidence = append(evidence, evidenceFor(r))
				} else {
					// Non-zero here and conf.all unknown: whether this
					// interface accepts depends on a value we could not read.
					unreadable = append(unreadable, iface)
				}
			}
		}

		sort.Strings(accepting)
		sort.Strings(unreadable)

		// A positive result stands whatever else could not be read: an
		// interface we watched accept source routing accepts source routing.
		if len(accepting) > 0 {
			evidence = append(evidence, evidenceFor(allRun))
			note, driftEv := driftNote(sc, srrAll, allRun.Value)
			evidence = append(evidence, driftEv...)
			return catalog.Outcome{
				Result: finding.Fail,
				Detail: fmt.Sprintf(
					"%d interface(s) accept source-routed packets: %s. %s is %d, and each of these carries a non-zero value of its own, so the kernel honours a route the sender attached to the packet — which lets an attacker choose the return path and receive replies to a spoofed source address.%s",
					len(accepting), joinKeys(accepting), srrAll, all, note),
				Evidence: evidence,
			}
		}

		// Every negative claim needs a complete view; an interface we could not
		// read may be the one that accepts.
		if len(unreadable) > 0 {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonPermission,
				Detail: fmt.Sprintf(
					"No interface was observed accepting source-routed packets, but the setting could not be resolved for %s, so whether this host refuses them cannot be determined.",
					joinKeys(unreadable)),
				Evidence: []finding.Evidence{finding.NewEvidence("/proc/sys/net/ipv4/conf", 0, "per-interface values unresolved", "")},
			}
		}

		if considered == 0 {
			return catalog.Outcome{
				Result: finding.NotApplicable,
				Detail: "This host has no non-loopback network interface, so there is no path on which a source-routed packet could arrive.",
			}
		}

		note, driftEv := driftNote(sc, srrAll, allRun.Value)
		return catalog.Outcome{
			Result: finding.Pass,
			Detail: fmt.Sprintf(
				"All %d non-loopback interface(s) refuse source-routed packets.%s",
				considered, note),
			Evidence: append([]finding.Evidence{evidenceFor(allRun)}, driftEv...),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set net.ipv4.conf.all.accept_source_route to 0 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w net.ipv4.conf.all.accept_source_route=0",
			"Set the template for interfaces created later: sysctl -w net.ipv4.conf.default.accept_source_route=0",
			"Persist both in /etc/sysctl.d/60-hardening.conf.",
			"Verify per interface: sysctl -a | grep accept_source_route",
			"Setting conf.all to 0 is sufficient on its own, because the kernel requires both it and the interface value to be non-zero. Setting the per-interface values too means the host stays safe if conf.all is later raised.",
		},
		Commands: []string{
			"sysctl -w net.ipv4.conf.all.accept_source_route=0",
			"sysctl -w net.ipv4.conf.default.accept_source_route=0",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
	},

	References: []finding.Reference{
		{Title: "RFC 7126. Filtering of IP-Optioned Packets", URL: "https://www.rfc-editor.org/rfc/rfc7126"},
		{Title: "Linux kernel documentation, ip-sysctl accept_source_route", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
	},
}

// nonZeroInterfaces names the real interfaces carrying a non-zero value, for
// the case where conf.all already settles the verdict but the per-interface
// settings would become live if it changed.
func nonZeroInterfaces(probed []fact.SysctlRunning) []string {
	var out []string
	for _, r := range probed {
		switch iface := interfaceOf(r.Key, srrSuffix); iface {
		case "all", "default", "lo":
			continue
		default:
			if n, ok := r.Int(); ok && n != 0 {
				out = append(out, iface)
			}
		}
	}
	sort.Strings(out)
	return out
}

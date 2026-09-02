package kernel

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0024 tests whether reverse-path filtering is written to the sysctl
// configuration, rather than merely running.
var Check0024 = catalog.Check{
	ID:     "KERNEL-0024",
	Module: "KERNEL",
	Title:  "Reverse-path filtering is written to the sysctl configuration",

	Description: `Reverse-path filtering makes the kernel drop an incoming packet
whose source address it would not route back out of the interface the packet
arrived on. Without it a host accepts packets claiming to come from anywhere,
which is what makes source-address spoofing useful: an attacker on one segment
impersonates an address on another, defeating any control that trusts a source
address and hiding where the traffic really came from.

Two keys are checked, because they answer different questions:

  - net.ipv4.conf.default.rp_filter is the template every interface created
    after boot inherits, a container's veth, a VPN tunnel, a hot-plugged NIC.
    Nothing else covers those, because they do not exist when the files are
    applied.
  - net.ipv4.conf.all.rp_filter is the floor. The kernel takes the *maximum*
    of it and the interface's own value, so it can raise filtering everywhere
    but never lower it.

Either 1 or 2 passes. 1 is strict, the reverse path must be the same
interface, and 2 is loose, requiring only that the source be routable
somewhere. Loose mode is the correct and deliberate choice on a multi-homed
host with asymmetric routing, so failing it would punish the operators who
thought about it hardest.

**A key set by a glob counts as set.** Red Hat's 50-redhat.conf writes
net.ipv4.conf.*.rp_filter rather than naming interfaces, and systemd's
50-default.conf does the same and then withholds the "all" key with a bare
-net.ipv4.conf.all.rp_filter line, so that "all" stays 0 and an operator keeps
the ability to turn filtering down on one interface. Both are configured hosts.
A check that only looked up the literal key name would report them as having no
reverse-path filtering at all, which is the kind of false positive that teaches
an operator to stop reading the report.

This is a check about files. KERNEL-0008 computes the effective value for each
interface that exists right now.`,

	// Medium, matching KERNEL-0008. Spoofing defeats controls that trust a
	// source address and obscures an attack's origin; it is not itself a way
	// in, which is what keeps it below the ptrace and BPF findings.
	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "sysctl", "persistence", "spoofing"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 29,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		if out := persistenceGate(sc, rpFilterPersistKeys, persistRPFilterCaveat); out != nil {
			return *out
		}

		var (
			failed   []string
			loose    []string
			withheld []string
			evidence []finding.Evidence
			written  int
		)
		for _, key := range rpFilterPersistKeys {
			set, found := sc.EffectiveConfigured(key)
			if !found {
				// A withheld "all" is survivable and a withheld "default" is
				// not, so the two are separated here and weighed below rather
				// than both being called an absence.
				if _, excluded := sc.ExcludedFrom(key); excluded && key == rpFilterAll {
					withheld = append(withheld, notConfigured(sc, key))
					continue
				}
				failed = append(failed, notConfigured(sc, key))
				continue
			}
			evidence = append(evidence, evidenceForSetting(sc, set))

			n, err := strconv.Atoi(strings.TrimSpace(set.Value))
			switch {
			case err != nil:
				failed = append(failed, fmt.Sprintf("%s is %q %s, which is not a number", key, set.Value, configuredAt(sc, key, set)))
				written++
			case n == 1:
				// Strict. Nothing to say beyond passing.
			case n == 2:
				loose = append(loose, key)
			default:
				failed = append(failed, fmt.Sprintf("%s is %d %s, so packets are accepted whatever source address they claim", key, n, configuredAt(sc, key, set)))
				written++
			}
		}

		// A withheld "all" is only safe while a pattern still covers the
		// interfaces themselves. Without one, "all" at 0 and nothing else is
		// an unfiltered host.
		if len(withheld) > 0 && !rpFilterPatternCovers(sc) {
			failed = append(failed, withheld...)
			withheld = nil
		}

		if len(failed) > 0 {
			out := catalog.Outcome{
				Result:   finding.Fail,
				Subject:  "sysctl configuration",
				Detail:   rpFilterFailureDetail(failed),
				Evidence: searchedEvidence(sc, evidence),
			}
			if written > 0 {
				// A file sets one of these to 0 or to something unreadable.
				// That is a decision somebody made, and the running kernel
				// currently disagreeing with it does not soften it.
				out.Detail += persistRPFilterCaveat
				return out
			}
			return tierAbsence(out, sc, rpFilterTiering, persistRPFilterCaveat)
		}

		detail := "Reverse-path filtering is written to the sysctl configuration: " +
			strings.Join(rpFilterConfiguredNotes(sc), "; ") + "."
		if len(withheld) > 0 {
			detail += fmt.Sprintf(" A pattern sets it on the interfaces themselves, and %s, so it keeps the kernel's own default — which is deliberate, because the kernel takes the maximum of that key and the interface's own, so pinning it would take away the ability to turn filtering down on one interface that needs it.",
				strings.Join(withheld, "; "))
		} else {
			detail += " The floor is set for the interfaces already up and the template for every interface created after boot, so a spoofed source address is dropped after the next reboot either way."
		}
		if len(loose) > 0 {
			verb := "is"
			if len(loose) > 1 {
				verb = "are"
			}
			detail += fmt.Sprintf(" %s %s at 2, which is loose mode: the source has to be routable by some interface rather than by the one the packet arrived on. That is the right choice on a multi-homed host with asymmetric routing and the wrong one on a host with a single default route, where strict mode costs nothing.",
				joinKeys(loose), verb)
		}
		return catalog.Outcome{
			Result:   finding.Pass,
			Subject:  "sysctl configuration",
			Detail:   detail + persistRPFilterCaveat,
			Evidence: searchedEvidence(sc, evidence),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Write net.ipv4.conf.all.rp_filter = 1 and net.ipv4.conf.default.rp_filter = 1 to a file in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Check what already sets them, patterns included: grep -rn rp_filter /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d. A line reading net.ipv4.conf.*.rp_filter sets every interface, and a bare -net.ipv4.conf.all.rp_filter withholds that one key from it on purpose.",
			"Create or extend a drop-in containing net.ipv4.conf.all.rp_filter = 1 and net.ipv4.conf.default.rp_filter = 1. Set both: default is the template for interfaces that do not exist yet, and all is the floor for the ones that do.",
			"Use 2 rather than 1 on a multi-homed host where traffic legitimately arrives on one interface and would leave by another. Loose mode still drops a source address that is routable nowhere, which is most spoofing.",
			"Apply without rebooting: sysctl --system, then confirm per interface with sysctl -a | grep '\\.rp_filter'.",
			"Check the interfaces that already exist afterwards. Neither key changes an interface that is up and has its own value; all raises the floor for it, and default does not apply to it at all.",
		},
		Commands: []string{
			"sysctl -a 2>/dev/null | grep '\\.rp_filter'",
			"grep -rn rp_filter /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d 2>/dev/null",
			"systemd-analyze cat-config sysctl.d",
		},
		Caution: "Strict mode drops legitimate traffic on a host with asymmetric routing, multiple uplinks, policy routing, or a router doing anything other than symmetric forwarding. Check the routing table before setting 1 host-wide; loose mode (2) is the safe answer where routing is not symmetric, and a per-interface override is the answer where only one interface is affected.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-5"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "Linux kernel, ip-sysctl rp_filter", URL: "https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html"},
		{Title: "RFC 3704. Ingress Filtering for Multihomed Networks", URL: "https://www.rfc-editor.org/rfc/rfc3704"},
		{Title: "sysctl.d(5)", URL: "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"},
	},
}

const rpFilterDefault = "net.ipv4.conf.default.rp_filter"

// rpFilterPersistKeys are the two the configuration has to carry: the template
// for interfaces created later, and the floor under the ones already up.
var rpFilterPersistKeys = []string{rpFilterAll, rpFilterDefault}

// persistRPFilterCaveat names the check that reads the running values.
var persistRPFilterCaveat = persistCaveatFor("KERNEL-0008")

// rpFilterPatternCovers reports whether the configuration sets rp_filter on
// the real interfaces, rather than only on the two host-wide keys.
//
// It is what makes a withheld conf.all key survivable. systemd's own
// 50-default.conf sets net.ipv4.conf.*.rp_filter and then withholds
// net.ipv4.conf.all.rp_filter, and the result is a filtered host: every
// interface present when the files are applied gets its own value from the
// pattern, and every interface created afterwards gets conf.default. Reading
// the withheld key alone would call that host unfiltered.
//
// The interfaces are the ones the collector enumerated rather than a list of
// likely names, and each is resolved through the same glob rules as any other
// key. Where none were enumerated — an old bundle, or a scan that could not
// read /proc/sys/net/ipv4/conf — the question is answered from the patterns
// alone, which is weaker but is the only evidence available and is still
// specific to rp_filter.
func rpFilterPatternCovers(sc fact.Sysctl) bool {
	var interfaces int
	for _, r := range sc.RunningMatching(rpFilterPrefix, rpFilterSuffix) {
		if r.Key == rpFilterAll || r.Key == rpFilterDefault {
			continue
		}
		interfaces++
		set, found := sc.EffectiveConfigured(r.Key)
		if !found {
			return false
		}
		if n, err := strconv.Atoi(strings.TrimSpace(set.Value)); err != nil || n < 1 {
			return false
		}
	}
	if interfaces > 0 {
		return true
	}

	for pattern, sets := range sc.Configured {
		if !strings.HasSuffix(pattern, rpFilterSuffix) || !strings.ContainsAny(pattern, "*?[") {
			continue
		}
		last := sets[len(sets)-1]
		if n, err := strconv.Atoi(strings.TrimSpace(last.Value)); err == nil && n >= 1 {
			return true
		}
	}
	return false
}

// rpFilterConfiguredNotes renders where each key that *is* set got its value.
func rpFilterConfiguredNotes(sc fact.Sysctl) []string {
	var out []string
	for _, key := range rpFilterPersistKeys {
		if set, found := sc.EffectiveConfigured(key); found {
			out = append(out, fmt.Sprintf("%s is %s %s", key, strings.TrimSpace(set.Value), configuredAt(sc, key, set)))
		}
	}
	return out
}

// rpFilterFailureDetail renders the failing verdict.
func rpFilterFailureDetail(failed []string) string {
	return fmt.Sprintf("%s. A host that does not filter by reverse path accepts packets claiming any source address, so a control that trusts one can be walked past and the origin of an attack is whatever the attacker wrote in the header.",
		capitaliseFirst(strings.Join(failed, "; ")))
}

// rpFilterTiering is the runtime cross-reference for the absence case.
//
// KERNEL-0008 computes the effective value per interface, taking the maximum
// of conf.all and each interface's own. This is the simpler question the
// downgrade needs answered — are the two host-wide keys themselves at a value
// that filters — and it is deliberately not the per-interface computation: a
// downgrade should rest on the same keys the check requires, not on a wider
// claim about the host.
var rpFilterTiering = []requirement{
	{key: rpFilterAll, accept: func(n int) bool { return n >= 1 }},
	{key: rpFilterDefault, accept: func(n int) bool { return n >= 1 }},
}

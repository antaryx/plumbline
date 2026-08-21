package fact

import (
	"sort"
	"strings"
)

// FirewallID names the host firewall configuration fact.
const FirewallID ID = "network.firewall"

// FirewallKind is which of the four host firewall configurations a record
// describes.
//
// They are not four alternatives at the same level, and the checks depend on
// the difference. ufw and firewalld are *managers*: they own the ruleset and
// write it into the kernel themselves. iptables and nftables saved-rule files
// are *rulesets*, loaded verbatim by a systemd unit. A manager and a saved
// ruleset on the same host is not redundancy — the manager flushes what the
// ruleset installed, and whoever maintains the file is editing something with
// no effect.
type FirewallKind string

const (
	// FirewallNFTables is /etc/nftables.conf or the RHEL variant: a ruleset
	// loaded verbatim by nftables.service.
	FirewallNFTables FirewallKind = "nftables"
	// FirewallIPTables is an iptables-save file loaded by a restore unit.
	FirewallIPTables FirewallKind = "iptables"
	// FirewallUFW is Ubuntu's manager.
	FirewallUFW FirewallKind = "ufw"
	// FirewallFirewalld is the Red Hat manager.
	FirewallFirewalld FirewallKind = "firewalld"
)

// Manager reports whether this kind owns the ruleset rather than being one.
func (k FirewallKind) Manager() bool {
	return k == FirewallUFW || k == FirewallFirewalld
}

// SourceState is what the collector was able to observe about one candidate
// configuration file. The states exist for the reason CronPathState's do:
// "the file is not there" and "we were not allowed to read it" produce
// opposite verdicts, and a boolean would have collapsed them into a guess.
type SourceState string

const (
	// SourcePresent: the file exists and was read.
	SourcePresent SourceState = "present"
	// SourceAbsent: the file does not exist. For a firewall this is the
	// ordinary case on a host using a different backend.
	SourceAbsent SourceState = "absent"
	// SourceDenied: permission denied. Nothing may be concluded from it.
	SourceDenied SourceState = "denied"
	// SourceError: the read failed for a reason worth recording verbatim.
	SourceError SourceState = "error"
)

// InputPolicy is the default disposition of inbound packets that match no rule.
//
// This is the single most important property of a firewall and the one most
// often wrong. A default-accept ruleset with a list of blocks is a deny list:
// every port a future package opens is reachable until somebody notices and
// adds a rule. A default-drop ruleset with a list of allows fails closed.
type InputPolicy string

const (
	// PolicyDeny: unmatched inbound traffic is dropped or rejected.
	PolicyDeny InputPolicy = "deny"
	// PolicyAllow: unmatched inbound traffic is accepted.
	PolicyAllow InputPolicy = "allow"
	// PolicyUndetermined: the file was read but does not state a policy this
	// collector could recognise. It is not "allow" — assuming the insecure
	// value would be as much a guess as assuming the secure one.
	PolicyUndetermined InputPolicy = ""
)

// EnabledState is whether a manager's own on/off switch is set.
//
// Three values rather than a bool because the switch may be absent: firewalld
// has no such key at all, and a ufw.conf without ENABLED= is a file that says
// nothing rather than a file that says no.
type EnabledState string

const (
	EnabledYes     EnabledState = "yes"
	EnabledNo      EnabledState = "no"
	EnabledUnknown EnabledState = ""
)

// FirewallSource is one candidate configuration file and what was read from it.
//
// The file's **contents are not carried**. A firewall ruleset is a map of the
// network — internal address ranges, which hosts may reach which ports, which
// management network exists — and putting it into a bundle designed to travel
// would attach the topology to every ticket the bundle is filed against. Only
// the derived properties the checks read are kept, plus the one policy line a
// finding has to quote. The same reasoning as ADR-0015 and the CRON collector.
type FirewallSource struct {
	Kind   FirewallKind `json:"kind"`
	Path   string       `json:"path"`
	State  SourceState  `json:"state"`
	Digest string       `json:"digest,omitempty"`
	Msg    string       `json:"msg,omitempty"`

	// Statements counts non-blank, non-comment lines. It is how an empty
	// configuration is told from a configured one: Debian's nftables package
	// installs /etc/nftables.conf whether or not anybody has written a rule
	// in it, and a file whose existence alone counted as a firewall would
	// report every such host as protected.
	Statements int `json:"statements,omitempty"`

	// Enabled is the manager's own switch. EnabledUnknown for a ruleset file,
	// which has no such concept.
	Enabled EnabledState `json:"enabled,omitempty"`

	// Policy is the default disposition of inbound traffic, and PolicyLine and
	// PolicyRaw are where it was read from so a finding can quote it.
	Policy     InputPolicy `json:"policy,omitempty"`
	PolicyLine int         `json:"policy_line,omitempty"`
	PolicyRaw  string      `json:"policy_raw,omitempty"`
}

// Active reports whether this source is a firewall configuration in force.
//
// A manager must be switched on; a saved ruleset must have something in it.
// The distinction matters because the two fail differently: `ufw disable`
// leaves every rule in the file and applies none of them, while an empty
// nftables.conf is a file with nothing to apply.
func (s FirewallSource) Active() bool {
	if s.State != SourcePresent {
		return false
	}
	if s.Kind.Manager() {
		return s.Enabled != EnabledNo && s.Statements > 0
	}
	return s.Statements > 0
}

// Firewall is the collected host firewall configuration.
type Firewall struct {
	// Sources are every candidate probed, in the collector's fixed order, so
	// the fact is deterministic without anything downstream having to sort.
	Sources []FirewallSource `json:"sources"`
}

func (Firewall) FactID() ID       { return FirewallID }
func (Firewall) FactVersion() int { return 1 }

// Active returns the sources that are a firewall configuration in force, in
// record order.
func (f Firewall) Active() []FirewallSource {
	var out []FirewallSource
	for _, s := range f.Sources {
		if s.Active() {
			out = append(out, s)
		}
	}
	return out
}

// Managers returns the active sources that own the ruleset.
func (f Firewall) Managers() []FirewallSource {
	var out []FirewallSource
	for _, s := range f.Active() {
		if s.Kind.Manager() {
			out = append(out, s)
		}
	}
	return out
}

// Rulesets returns the active sources that are a saved ruleset.
func (f Firewall) Rulesets() []FirewallSource {
	var out []FirewallSource
	for _, s := range f.Active() {
		if !s.Kind.Manager() {
			out = append(out, s)
		}
	}
	return out
}

// Kinds returns the distinct kinds among the active sources, in record order.
// Two files of the same kind — rules.v4 and rules.v6 — are one configuration,
// not two competing ones.
func (f Firewall) Kinds() []FirewallKind {
	seen := map[FirewallKind]bool{}
	var out []FirewallKind
	for _, s := range f.Active() {
		if !seen[s.Kind] {
			seen[s.Kind] = true
			out = append(out, s.Kind)
		}
	}
	return out
}

// Unreadable returns the candidates whose state could not be determined,
// sorted by path.
//
// A check consults this before drawing any negative conclusion: a file that
// could not be read might be the firewall, and reporting "no firewall is
// configured" over the paths that happened to be readable is the false
// assurance CONTRIBUTING.md rule 3 forbids.
func (f Firewall) Unreadable() []FirewallSource {
	var out []FirewallSource
	for _, s := range f.Sources {
		if s.State == SourceDenied || s.State == SourceError {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// KindNames renders a kind list for a detail string.
func KindNames(kinds []FirewallKind) string {
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

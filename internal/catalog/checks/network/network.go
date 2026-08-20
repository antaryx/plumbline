// Package network holds the NETWORK module's checks.
//
// The module is deliberately small. SSHD covers the service that is actually
// exposed on nearly every host, and KERNEL covers the packet-handling
// parameters — rp_filter, redirect acceptance, source routing, SYN cookies —
// that a firewall does not govern. What is left is the firewall itself, and
// specifically the two properties an offline read can settle: whether one is
// configured, and whether it fails closed.
//
// Every check here reports what is **configured**, never what is loaded. There
// is no `nft list ruleset` and no `iptables -S`, because a scan must work
// against a mounted image and against a bundle collected months ago. A host
// with a perfect nftables.conf and a disabled nftables.service has no
// firewall; that half is visible to the SERVICES module and not to this one,
// and neither module claims the other's.
package network

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// firewallFact reads the module's fact. The runner's required-fact gate
// guarantees it is present and typed before Eval is entered.
func firewallFact(fs *fact.Set) fact.Firewall {
	f, _, _ := fact.Get[fact.Firewall](fs, fact.FirewallID)
	return f
}

// sourceEvidence cites one configuration file.
func sourceEvidence(s fact.FirewallSource) finding.Evidence {
	switch s.State {
	case fact.SourcePresent:
		excerpt := fmt.Sprintf("%s configuration, %d statement(s)", s.Kind, s.Statements)
		if s.Enabled != fact.EnabledUnknown {
			excerpt += "; ENABLED=" + string(s.Enabled)
		}
		if s.PolicyRaw != "" {
			excerpt += "; " + s.PolicyRaw
		}
		return finding.NewEvidence(s.Path, s.PolicyLine, excerpt, s.Digest)
	case fact.SourceAbsent:
		return finding.NewEvidence(s.Path, 0, "does not exist", "")
	default:
		return finding.NewEvidence(s.Path, 0, string(s.State)+": "+s.Msg, "")
	}
}

// evidenceFor cites a list of sources.
func evidenceFor(srcs []fact.FirewallSource) []finding.Evidence {
	ev := make([]finding.Evidence, 0, len(srcs))
	for _, s := range srcs {
		ev = append(ev, sourceEvidence(s))
	}
	return ev
}

// paths renders a source list for a detail string.
func paths(srcs []fact.FirewallSource) string {
	names := make([]string, 0, len(srcs))
	for _, s := range srcs {
		names = append(names, s.Path)
	}
	return strings.Join(names, ", ")
}

// noFirewall is the verdict for a check whose subject is a firewall that is
// not there.
//
// NOT_APPLICABLE and not FAIL: "the default policy denies" is not a false
// statement about a host with no firewall, it is a sentence with no subject.
// NETWORK-0001 is the check that reports the absence, once, and a module that
// failed three times for one missing thing would bury the finding that matters
// under two that repeat it.
func noFirewall(what string) catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: fmt.Sprintf(
			"No host firewall configuration was found on this host, so %s has no subject. NETWORK-0001 reports the absence itself.",
			what),
	}
}

// unknownIfUnreadable converts an outcome that rests on **absence** into
// UNKNOWN when any candidate file could not be read.
//
// As in the SERVICES module, the call site decides whether to apply it rather
// than the helper guessing from the result: which outcome rests on absence
// differs per check, and the compiler cannot tell. A configuration file we
// were refused might be the firewall, might be the second manager, or might
// hold the accept policy — so any conclusion drawn from not having seen one is
// only as good as the reads behind it. The converse is never wrapped: a policy
// line we read is a fact, and a file we could not read cannot unmake it
// (ADR-0014).
func unknownIfUnreadable(f fact.Firewall, o catalog.Outcome) catalog.Outcome {
	bad := f.Unreadable()
	if len(bad) == 0 {
		return o
	}

	reason := finding.ReasonPermission
	for _, s := range bad {
		if s.State == fact.SourceError {
			reason = finding.ReasonAmbiguousState
		}
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       o.Subject,
		Detail: fmt.Sprintf(
			"This result rests on what was not found, and %d of the candidate configuration files could not be read (%s). Any of them could hold the configuration that decides this check, so the conclusion cannot be confirmed.",
			len(bad), paths(bad)),
		Evidence: append(evidenceFor(bad), o.Evidence...),
	}
}

// plural picks the verb form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

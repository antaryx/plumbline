package containers

import (
	"strings"

	"github.com/antaryx/plumbline/internal/fact"
)

// The Docker API is root on the host and authenticates nobody over plain TCP,
// so "which sockets does this daemon listen on" is the highest-value question
// this module asks. It is asked twice, because there are two files that can
// answer it: the systemd unit's -H flags (CONTAINERS-0006) and daemon.json's
// hosts key (CONTAINERS-0007).
//
// Everything the two checks share lives here rather than in either of them.
// The alternative is two readings of dockerd's socket grammar that agree today
// and drift later, and a drift between them would not be a cosmetic
// inconsistency: the same configuration would be Critical when written in one
// file and a pass when written in the other, which is worse than either answer
// on its own.
//
// **dockerd refuses to start when an option is given in both places.** That is
// what makes the pair well behaved rather than double-counting: on any host
// whose daemon is actually running, at most one of the two files sets hosts,
// so at most one of the two checks has a subject and neither can report the
// same socket twice.

// binding is one socket the daemon was asked to listen on, and where the ask
// was written.
//
// It exists so the shared readings below take one type rather than one per
// source. The unit's bindings arrive as fact.DockerHostBinding with a line
// number; daemon.json's arrive as bare strings out of a JSON array, where
// there is no line to cite and Line stays zero.
type binding struct {
	spec   string
	source string
	line   int
}

// unitBindings adapts the systemd unit's -H values.
func unitBindings(hosts []fact.DockerHostBinding) []binding {
	out := make([]binding, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, binding{spec: h.Spec, source: h.Origin, line: h.Line})
	}
	return out
}

// configBindings adapts daemon.json's hosts array.
func configBindings(d fact.DockerDaemon) []binding {
	out := make([]binding, 0, len(d.Hosts))
	for _, h := range d.Hosts {
		out = append(out, binding{spec: h, source: d.Path})
	}
	return out
}

// socketKind is what a socket specification points at.
type socketKind int

const (
	socketLocal socketKind = iota
	socketTCP
	socketOther
)

// classify reads a dockerd socket specification.
//
// A bare host:port with no scheme is TCP: dockerd accepts "-H 0.0.0.0:2375"
// and binds it exactly as it binds the tcp:// form. Reading that as
// unrecognised would turn the shortest way to write the finding into the one
// spelling that escapes it.
func classify(spec string) socketKind {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch {
	case strings.HasPrefix(s, "tcp://"):
		return socketTCP
	case strings.HasPrefix(s, "unix://"), strings.HasPrefix(s, "fd://"), strings.HasPrefix(s, "npipe://"):
		return socketLocal
	case strings.Contains(s, "://"):
		return socketOther
	case strings.Contains(s, ":"):
		return socketTCP
	}
	return socketOther
}

// partition sorts bindings into the network-facing, the local, and the ones
// this build does not recognise.
func partition(bs []binding) (exposed, local, unrecognised []binding) {
	for _, b := range bs {
		switch classify(b.spec) {
		case socketTCP:
			exposed = append(exposed, b)
		case socketLocal:
			local = append(local, b)
		default:
			unrecognised = append(unrecognised, b)
		}
	}
	return exposed, local, unrecognised
}

// addrOf returns the address part of a socket specification, without its
// scheme or port.
//
// Written with strings rather than net.SplitHostPort because a check may not
// import net — the purity rule in CONTRIBUTING.md — and because the input is
// not necessarily a well-formed address in the first place. It is a value an
// operator typed, and the job here is to read what they wrote.
func addrOf(spec string) string {
	s := strings.ToLower(strings.TrimSpace(spec))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// A bracketed IPv6 literal keeps its colons; everything after the closing
	// bracket is the port.
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i >= 0 {
			return s[1:i]
		}
		return strings.TrimPrefix(s, "[")
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

// loopbackOnly reports whether every binding is to the host's own loopback
// interface.
//
// An empty address is not loopback: "tcp://:2375" binds every interface, and
// so does "tcp://0.0.0.0:2375". Treating either as local would downgrade the
// two most common ways of writing the worst case.
func loopbackOnly(bindings []binding) bool {
	for _, b := range bindings {
		a := addrOf(b.spec)
		switch {
		case a == "localhost", a == "::1", a == "0:0:0:0:0:0:0:1":
		case strings.HasPrefix(a, "127."):
		default:
			return false
		}
	}
	return len(bindings) > 0
}

// specList renders socket specifications for a detail string.
func specList(bindings []binding) string {
	seen := make(map[string]bool, len(bindings))
	var parts []string
	for _, b := range bindings {
		if seen[b.spec] {
			continue
		}
		seen[b.spec] = true
		parts = append(parts, b.spec)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// tlsVerified reports whether client-certificate verification is in force, and
// which file said so.
//
// Both files are consulted whichever check is asking, and that is the point of
// putting it here. The socket may be bound in the unit and the certificates
// configured in daemon.json, or the other way round: they are different
// options, so dockerd's refusal to take one option from two places does not
// apply and the split is legal. A check that read only its own file would
// report a mutually authenticated endpoint as an open one.
func tlsVerified(u fact.DockerService, d fact.DockerDaemon) (bool, string) {
	if u.BoolFlag("tlsverify") {
		return true, "the unit's command line"
	}
	// daemon.json is only consulted when it was actually read. An unreadable
	// or absent configuration says nothing, and nothing is not a yes.
	if d.Parsed() {
		if on, set := fact.OptBool(d.TLSVerify); set && on {
			return true, d.Path
		}
	}
	return false, ""
}

// tlsEncryptedOnly reports whether TLS is on and client verification is not.
//
// It earns its own sentence in a finding rather than being folded into "no
// TLS", because an operator who set it believes the socket is protected. A
// report that told them there is no TLS would be both wrong and unpersuasive,
// and the thing they actually need to hear is that encryption without
// verification does not restrict who may connect.
func tlsEncryptedOnly(u fact.DockerService, d fact.DockerDaemon) bool {
	if u.BoolFlag("tls") {
		return true
	}
	if d.Parsed() {
		if on, set := fact.OptBool(d.TLS); set && on {
			return true
		}
	}
	return false
}

// unitCouldSetTLS returns the unit fragments that were not read and could
// therefore be carrying the --tlsverify this scan did not find.
//
// A binding that was found is a finding whatever else went unread — ADR-0014,
// and the reason a FAIL is not downgraded to UNKNOWN here. But the mitigation
// is a different claim from the exposure, and a finding that said "with no
// authentication on it" while a drop-in sat unread would be asserting the one
// half it could not see.
//
// An absent unit has no command line and a masked one has a command line
// systemd will not run, so neither can be hiding a flag that is in force.
func unitCouldSetTLS(u fact.DockerService) []string {
	switch u.State {
	case fact.DockerUnitAbsent, fact.DockerUnitMasked:
		return nil
	case fact.DockerUnitPresent:
		var out []string
		for _, f := range u.Incomplete() {
			out = append(out, f.Path)
		}
		return out
	default:
		// The unit itself was not read, so the whole command line is unseen.
		return []string{u.Path}
	}
}

// certCaveat qualifies a pass reached by way of tlsverify.
//
// The flag being set is a fact about a configuration. Whether the CA is one
// this operator controls, whether the key is 0644, and whether any certificate
// has expired are facts about files these checks do not read, and a pass that
// did not say so would be read as more assurance than it is.
const certCaveat = " Whether the certificates themselves are sound — the CA, the key's permissions, the expiry — is not examined here."

package containers

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0006 tests whether the systemd unit binds the Docker API to a network
// socket without requiring client certificates.
var Check0006 = catalog.Check{
	ID:     "CONTAINERS-0006",
	Module: "CONTAINERS",
	Title:  "The Docker daemon is not started with an unauthenticated TCP socket",

	Description: `The Docker API is root on the host. Anything that can reach
it can start a container with the root filesystem bind-mounted and the SYS_ADMIN
capability, which is not privilege escalation so much as the API working
exactly as designed. The single line

	docker -H tcp://target:2375 run -v /:/host --privileged -it alpine chroot /host

is a root shell, and it needs no exploit and no credential.

Nothing in the daemon authenticates a plain TCP client. There is no password,
no token and no per-user access control: dockerd's own documentation is
explicit that its API is intended to be reached over a unix socket whose file
permissions are the access control, and that exposing it over TCP without TLS
client verification hands the host to the network. Port 2375 is scanned
continuously for exactly this reason, and an exposed daemon is typically mining
cryptocurrency within hours rather than days.

The stock unit every distribution ships binds -H fd://, which is the socket
systemd hands over from docker.socket, and that is safe. The exposure is
something an operator added, almost always through a drop-in:

	/etc/systemd/system/docker.service.d/override.conf
	    [Service]
	    ExecStart=
	    ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375

That is what "how do I connect Docker from another machine" answers with, and
what remote-build, CI-runner and IDE-integration guides ask for. This check
reads the effective ExecStart — the vendor unit with every drop-in folded onto
it, in systemd's own precedence order — and reports a tcp:// binding that is
not protected by client-certificate verification.

**--tls is not enough and --tlsverify is.** The first encrypts the connection
and asks nothing of the client, so anyone who can reach the port still gets a
root shell over a nicely encrypted channel. Only --tlsverify makes the daemon
require a certificate signed by the CA it was given, which is what turns the
port from an open door into an authenticated one. A daemon.json that sets
tlsverify counts here too: it and the -H flag are different options, so dockerd
accepts them from different places.

A binding to loopback is rated below one to a routable address, and it is still
a finding. tcp://127.0.0.1:2375 is unreachable from the network and reachable
by every local user on the host, by every container started with
--network=host, and by anything that can be talked into making an HTTP request
on the host's behalf — which is the standard second half of a server-side
request forgery.`,

	// Critical, and the only Critical in the module. The other five describe a
	// weakened boundary; this one describes the absence of a boundary. There
	// is no exploitation step between finding the port and owning the host,
	// and the finding is remotely reachable by definition.
	BaseSeverity: finding.Critical,
	Tags:         []string{"containers", "docker", "remote-access", "authentication", "attack-surface"},
	Requires:     []fact.ID{fact.DockerServiceID, fact.DockerDaemonID},
	SinceCatalog: 19,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees both required facts are present and typed.
		u, _, _ := fact.Get[fact.DockerService](fs, fact.DockerServiceID)
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := serviceApplicable(d, u); out != nil {
			return *out
		}

		var exposed, local, unrecognised []fact.DockerHostBinding
		for _, b := range u.Hosts() {
			switch classify(b.Spec) {
			case socketTCP:
				exposed = append(exposed, b)
			case socketLocal:
				local = append(local, b)
			default:
				unrecognised = append(unrecognised, b)
			}
		}

		// tlsverify is honoured from either file. The -H flag lives in the
		// unit and tlsverify may live in daemon.json; they are different
		// options, so dockerd does not refuse the split, and a check that read
		// only the unit would report a mutually authenticated endpoint as an
		// open one.
		verified, verifiedBy := tlsVerified(u, d)

		if len(exposed) > 0 {
			if verified {
				return catalog.Outcome{
					Result:  finding.Pass,
					Subject: u.Path,
					Detail: fmt.Sprintf("The daemon is started with %s, which puts the API on the network, and with client-certificate verification enabled in %s. Access therefore requires a certificate signed by the configured CA rather than only the ability to reach the port.%s%s",
						specList(exposed), verifiedBy, unitCaveat, certCaveat),
					Evidence: bindingEvidence(u, exposed),
				}
			}
			return failure(u, exposed)
		}

		// Nothing binds TCP. Before that becomes a pass, everything that could
		// have hidden a binding has to be accounted for — an unread drop-in
		// and an unexpanded variable are both places a -H tcp:// lives, and
		// reporting a pass over either would be reporting on a command line
		// this scan only partly read.
		if out := incomplete(u, unrecognised); out != nil {
			return *out
		}

		detail := "The daemon is started with no TCP socket, so its API is reachable only through the local socket and the file permissions on it."
		if len(local) > 0 {
			detail = fmt.Sprintf("The daemon is started with %s, which is local to the host, and with no TCP socket. Its API is reachable only through that socket and the file permissions on it.", specList(local))
		}
		return catalog.Outcome{
			Result:   finding.Pass,
			Subject:  u.Path,
			Detail:   detail + unitCaveat,
			Evidence: []finding.Evidence{execEvidence(u)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Stop the daemon listening on TCP, or require client certificates on the socket that must stay.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out what connects to it before removing it: a CI runner, a remote docker context, an IDE, or an orchestrator may depend on the port, and each of them needs a route to the daemon afterwards.",
			"See exactly what systemd is running, drop-ins and all: systemctl cat docker.service, and systemctl show -p ExecStart docker.service for the assembled line.",
			"If nothing needs remote access, remove the -H tcp:// argument from the ExecStart in the drop-in that added it — systemctl edit docker will open it — leaving -H fd:// on its own.",
			"If remote access is genuinely needed, do not simply add --tls: it encrypts without authenticating and leaves the port open to anyone who can reach it. Generate a CA and a server certificate, start the daemon with --tlsverify --tlscacert --tlscert --tlskey, and issue each client its own signed certificate.",
			"Prefer a route that needs no open port at all where one exists: docker context create --docker host=ssh://user@host carries the API over SSH and authenticates with the keys already deployed.",
			"Reload and restart: systemctl daemon-reload, then systemctl restart docker.",
			"Verify from another machine that the old port is closed, not merely firewalled off from where you happened to test.",
			"Treat any host that was exposed as suspect rather than fixed: an unauthenticated daemon is compromised in hours, so audit docker ps -a, the image list and the host's crontabs before considering the incident closed.",
		},
		Commands: []string{
			"systemctl cat docker.service",
			"systemctl show -p ExecStart docker.service",
			"ss -lntp | grep -E ':(2375|2376)'",
		},
		Caution: "Removing the binding disconnects every remote client immediately, and restarting the daemon stops every running container unless live-restore is enabled. A firewall in front of the port is a mitigation and not a fix: the API is still unauthenticated to anything inside the perimeter, including every container on the host.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "IA-2"},
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "SC-8"},
	},

	References: []finding.Reference{
		{Title: "Docker — protect the Docker daemon socket", URL: "https://docs.docker.com/engine/security/protect-access/"},
		{Title: "Docker — dockerd command line reference", URL: "https://docs.docker.com/reference/cli/dockerd/"},
	},
}

// certCaveat qualifies a pass reached by way of --tlsverify.
//
// The flag being present is a fact about the command line. Whether the CA is
// one this operator controls, whether the key is 0644, and whether any
// certificate has expired are facts about files this check does not read, and
// a pass that did not say so would be read as more assurance than it is.
const certCaveat = " Whether the certificates themselves are sound — the CA, the key's permissions, the expiry — is not examined here."

// socketKind is what a -H value points at.
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

// addrOf returns the address part of a socket specification, without its
// scheme or port.
//
// Written with strings rather than net.SplitHostPort because a check may not
// import net — the purity rule in CONTRIBUTING.md — and because the input is
// not necessarily a well-formed address in the first place. It is a line from
// a unit file, and the job here is to read what an operator wrote.
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
func loopbackOnly(bindings []fact.DockerHostBinding) bool {
	for _, b := range bindings {
		a := addrOf(b.Spec)
		switch {
		case a == "localhost", a == "::1", a == "0:0:0:0:0:0:0:1":
		case strings.HasPrefix(a, "127."):
		default:
			return false
		}
	}
	return len(bindings) > 0
}

// tlsVerified reports whether client-certificate verification is in force, and
// which file said so.
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

// failure builds the FAIL for an unprotected TCP binding.
func failure(u fact.DockerService, exposed []fact.DockerHostBinding) catalog.Outcome {
	out := catalog.Outcome{
		Result:   finding.Fail,
		Subject:  u.Path,
		Evidence: bindingEvidence(u, exposed),
	}

	// --tls without --tlsverify is its own finding and deserves its own
	// sentence. An operator who set it believes the socket is protected, and
	// telling them "no TLS" would be both wrong and unpersuasive.
	encrypted := u.BoolFlag("tls")

	switch {
	case loopbackOnly(exposed):
		// Not reachable from the network, reachable by every local user and by
		// every container on the host network. High rather than Critical, and
		// still a root-equivalent socket with no authentication on it.
		out.Severity = finding.High
		out.Detail = fmt.Sprintf("The daemon is started with %s, which is a root-equivalent API with no authentication on it. The binding is to loopback, so it is not reachable from the network, but every local user on this host can use it to start a privileged container and become root — as can any container run with --network=host, and anything that can be induced to make an HTTP request from this host.",
			specList(exposed))
	default:
		out.Detail = fmt.Sprintf("The daemon is started with %s, which publishes a root-equivalent API to the network with no authentication on it. Anyone who can reach the port can start a privileged container with the host filesystem mounted, which is a root shell on this machine.",
			specList(exposed))
	}

	if encrypted {
		out.Detail += " --tls is set and --tlsverify is not, so the connection is encrypted and the client is never asked to prove who it is; encryption without verification does not restrict who may connect."
	}
	out.Detail += unitCaveat
	return out
}

// incomplete returns the UNKNOWN for a command line that was only partly read,
// or nil when it was read in full.
//
// It runs only after the TCP bindings have been counted, and that order is
// ADR-0014: a binding that was found is a finding whatever else went unread,
// because an incomplete examination invalidates a negative result and never a
// positive one.
func incomplete(u fact.DockerService, unrecognised []fact.DockerHostBinding) *catalog.Outcome {
	var reasons []string
	for _, f := range u.Incomplete() {
		reasons = append(reasons, fmt.Sprintf("%s was not read (%s)", f.Path, f.State))
	}
	reasons = append(reasons, u.Ambiguities()...)
	for _, b := range unrecognised {
		reasons = append(reasons, fmt.Sprintf("%s line %d binds %s, which is not a socket specification this build recognises", b.Origin, b.Line, b.Spec))
	}
	if len(reasons) == 0 {
		return nil
	}

	reason := finding.ReasonAmbiguousState
	for _, f := range u.Incomplete() {
		if f.State == fact.DockerUnitDenied {
			reason = finding.ReasonPermission
			break
		}
	}

	return &catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       u.Path,
		Detail: fmt.Sprintf("No TCP socket appears in the part of the daemon's command line this scan could read, but the command line was not read in full, so that is not the same as there being none: %s.%s",
			strings.Join(reasons, "; "), unitCaveat),
		Evidence: []finding.Evidence{execEvidence(u)},
	}
}

// specList renders socket specifications for a detail string.
func specList(bindings []fact.DockerHostBinding) string {
	seen := make(map[string]bool, len(bindings))
	var parts []string
	for _, b := range bindings {
		if seen[b.Spec] {
			continue
		}
		seen[b.Spec] = true
		parts = append(parts, "-H "+b.Spec)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// bindingEvidence cites the ExecStart line each binding came from, once per
// line rather than once per binding.
func bindingEvidence(u fact.DockerService, bindings []fact.DockerHostBinding) []finding.Evidence {
	seen := make(map[string]bool, len(bindings))
	var out []finding.Evidence
	for _, b := range bindings {
		key := fmt.Sprintf("%s:%d", b.Origin, b.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, unitEvidenceAt(u, b.Origin, b.Line, execLine(u, b.Origin, b.Line)))
	}
	if len(out) == 0 {
		out = append(out, execEvidence(u))
	}
	return out
}

// execEvidence cites the effective command line as a whole, for a verdict that
// is about its absence of something rather than about a particular line.
func execEvidence(u fact.DockerService) finding.Evidence {
	if len(u.ExecStart) == 0 {
		return unitEvidence(u, u.Path, "the [Service] section sets no ExecStart")
	}
	e := u.ExecStart[len(u.ExecStart)-1]
	return unitEvidenceAt(u, e.Origin, e.Line, "ExecStart="+e.Prefixes+strings.Join(e.Argv, " "))
}

// execLine renders one effective ExecStart as it would read in the file.
func execLine(u fact.DockerService, origin string, line int) string {
	for _, e := range u.ExecStart {
		if e.Origin == origin && e.Line == line {
			return "ExecStart=" + e.Prefixes + strings.Join(e.Argv, " ")
		}
	}
	return "ExecStart"
}

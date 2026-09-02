package containers

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0007 tests whether daemon.json binds the Docker API to a network socket
// without requiring client certificates.
var Check0007 = catalog.Check{
	ID:     "CONTAINERS-0007",
	Module: "CONTAINERS",
	Title:  "The Docker daemon configuration does not bind an unauthenticated TCP socket",

	Description: `This is CONTAINERS-0006's other half. That check reads the -H
flags on dockerd's command line in the systemd unit; this one reads the hosts
key in /etc/docker/daemon.json. They are two spellings of one option, they
produce exactly the same exposure, and an audit that read only one of them
would be a scanner an operator could pass by moving a line between two files.

	{
	  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]
	}

is the same open door as -H tcp://0.0.0.0:2375, and everything CONTAINERS-0006
says about it applies unchanged: the API is root on the host, nothing
authenticates a plain TCP client, and reaching the port is the whole of the
attack. Port 2375 is scanned continuously and an exposed daemon is typically
mining cryptocurrency within hours.

**The two never both apply on a running host.** dockerd refuses to start when
an option is given as a flag and in the configuration file at once, and hosts
is the option it refuses over most often, adding it to daemon.json on a stock
installation is the well-known way to make Docker stop starting, because the
unit already passes -H fd://. So on any host whose daemon is running, at most
one of these two files decides the sockets, and the pair of checks covers both
without double-counting.

That is also why an absent hosts key is a pass here rather than a gap. It does
not mean the daemon listens on nothing; it means this file is not where the
listening is configured, and the unit is. CONTAINERS-0006 reads the unit. The
two are a pair, and neither is complete on its own.

**--tls is not enough and --tlsverify is.** Setting "tls": true encrypts the
connection and asks the client for nothing, so anyone who can reach the port
still gets a root shell over a well-encrypted channel. Only "tlsverify": true
makes the daemon require a certificate signed by the CA it was given.
Verification set on dockerd's command line counts here, for the reason the
sockets count in the other direction: tlsverify and hosts are different
options, so dockerd accepts them from different places.

A binding to loopback is rated below one to a routable address, and it is still
a finding, for the reasons CONTAINERS-0006 gives.`,

	// Critical, and identical to CONTAINERS-0006 deliberately. The two describe
	// one exposure written in two files, and rating them differently would tell
	// an operator that where they typed it changes what it does.
	BaseSeverity: finding.Critical,
	Tags:         []string{"containers", "docker", "remote-access", "authentication", "attack-surface"},
	Requires:     []fact.ID{fact.DockerDaemonID, fact.DockerServiceID},
	SinceCatalog: 20,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees both required facts are present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)
		u, _, _ := fact.Get[fact.DockerService](fs, fact.DockerServiceID)

		// The module's ordinary gate: no dockerd is NOT_APPLICABLE, and a
		// daemon.json that exists and could not be read is UNKNOWN. It is the
		// right gate here for the same reason it is right for the other five —
		// a host running Docker is judged whether or not it has a config file.
		if out := applicable(d); out != nil {
			return *out
		}

		exposed, local, unrecognised := partition(configBindings(d))
		verified, verifiedBy := tlsVerified(u, d)

		if len(exposed) > 0 {
			if verified {
				return catalog.Outcome{
					Result:  finding.Pass,
					Subject: d.Path,
					Detail: fmt.Sprintf("The hosts key binds %s, which puts the API on the network, and client-certificate verification is enabled in %s. Access therefore requires a certificate signed by the configured CA rather than only the ability to reach the port.%s%s",
						specList(exposed), verifiedBy, hostsCaveat, certCaveat),
					Evidence: []finding.Evidence{evidence(d, hostsExcerpt(d))},
				}
			}
			return hostsFailure(u, d, exposed)
		}

		// dockerd validates every hosts entry at startup and refuses to run on
		// one it cannot parse. A spelling this build does not recognise is
		// therefore either a newer scheme than this build knows or a daemon
		// that is not running, and neither is something to call a pass.
		if len(unrecognised) > 0 {
			var specs []string
			for _, b := range unrecognised {
				specs = append(specs, b.spec)
			}
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       d.Path,
				Detail: fmt.Sprintf("The hosts key binds %s, which is not a socket specification this build recognises, so whether the API is reachable from the network cannot be determined.%s",
					strings.Join(specs, " and "), hostsCaveat),
				Evidence: []finding.Evidence{evidence(d, hostsExcerpt(d))},
			}
		}

		detail := "The hosts key binds no TCP socket"
		switch {
		case len(local) > 0:
			detail = fmt.Sprintf("The hosts key binds %s, which is local to the host, and no TCP socket", specList(local))
		// The two commonest shapes by far, and the ones worth wording
		// carefully. Silence here is not "the daemon listens on nothing" — it
		// is "this file does not decide that", and the check that reads the
		// file which does is named so a reader can follow it.
		case d.State == fact.DockerConfigAbsent:
			detail = "No socket is configured in this file, so the daemon listens on whatever dockerd's command line in the systemd unit asks for — which CONTAINERS-0006 reads"
		case !d.HasKey("hosts"):
			detail = "The hosts key is not set, so this file binds no socket at all and the daemon listens on whatever dockerd's command line in the systemd unit asks for — which CONTAINERS-0006 reads"
		}
		return catalog.Outcome{
			Result:   finding.Pass,
			Subject:  d.Path,
			Detail:   detail + "." + defaultsNote(d) + hostsCaveat,
			Evidence: []finding.Evidence{evidence(d, hostsExcerpt(d))},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Remove the tcp:// entry from the hosts array, or require client certificates on the socket that must stay.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out what connects to it before removing it: a CI runner, a remote docker context, an IDE, or an orchestrator may depend on the port, and each of them needs a route to the daemon afterwards.",
			"Edit /etc/docker/daemon.json and delete the tcp:// entry from hosts, leaving the unix socket. Removing the key entirely is also correct and hands the decision back to the systemd unit.",
			"If remote access is genuinely needed, do not simply set \"tls\": true: it encrypts without authenticating and leaves the port open to anyone who can reach it. Generate a CA and a server certificate, set \"tlsverify\": true with tlscacert, tlscert and tlskey, and issue each client its own signed certificate.",
			"Prefer a route that needs no open port at all where one exists: docker context create --docker host=ssh://user@host carries the API over SSH and authenticates with the keys already deployed.",
			"Restart the daemon: systemctl restart docker. If it refuses to start with a message about hosts being specified both as a flag and in the configuration file, the systemd unit is passing -H as well, decide which of the two files owns the sockets and remove it from the other.",
			"Verify from another machine that the old port is closed, not merely firewalled off from where you happened to test.",
			"Treat any host that was exposed as suspect rather than fixed: an unauthenticated daemon is compromised in hours, so audit docker ps -a, the image list and the host's crontabs before considering the incident closed.",
		},
		Commands: []string{
			"docker info --format '{{.Name}}' >/dev/null && ss -lntp | grep -E ':(2375|2376)'",
			"systemctl show -p ExecStart docker.service",
			"systemctl restart docker",
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
		{Title: "Docker, protect the Docker daemon socket", URL: "https://docs.docker.com/engine/security/protect-access/"},
		{Title: "Docker, daemon configuration file reference", URL: "https://docs.docker.com/reference/cli/dockerd/"},
	},
}

// hostsCaveat is appended to every verdict this check draws, and it is the
// mirror of unitCaveat.
//
// CONTAINERS-0006 reads the unit and says a socket in daemon.json is invisible
// to it; this one reads daemon.json and says a socket in the unit is
// CONTAINERS-0006's subject. Neither says anything about docker.socket, whose
// ListenStream is what the stock -H fd:// actually listens on and which
// nothing in this build reads.
const hostsCaveat = " This reads the hosts key in /etc/docker/daemon.json; a socket bound by -H on dockerd's command line is CONTAINERS-0006's subject, and one bound by ListenStream in docker.socket is read by neither."

// hostsFailure builds the FAIL for an unprotected TCP binding in daemon.json.
//
// It is hostsFailure and not a second call into failure() because the two
// differ in every part a reader sees — the subject is a JSON key rather than a
// command line, and the evidence is a document rather than a line in a unit.
// What they must not differ in is the reading of the sockets themselves, and
// that is in sockets.go, called by both.
func hostsFailure(u fact.DockerService, d fact.DockerDaemon, exposed []binding) catalog.Outcome {
	out := catalog.Outcome{
		Result:   finding.Fail,
		Subject:  d.Path,
		Evidence: []finding.Evidence{evidence(d, hostsExcerpt(d))},
	}

	switch {
	case loopbackOnly(exposed):
		out.Severity = finding.High
		out.Detail = fmt.Sprintf("The hosts key binds %s, which is a root-equivalent API with no authentication on it. The binding is to loopback, so it is not reachable from the network, but every local user on this host can use it to start a privileged container and become root — as can any container run with --network=host, and anything that can be induced to make an HTTP request from this host.",
			specList(exposed))
	default:
		out.Detail = fmt.Sprintf("The hosts key binds %s, which publishes a root-equivalent API to the network with no authentication on it. Anyone who can reach the port can start a privileged container with the host filesystem mounted, which is a root shell on this machine.",
			specList(exposed))
	}

	if tlsEncryptedOnly(u, d) {
		out.Detail += " tls is enabled and tlsverify is not, so the connection is encrypted and the client is never asked to prove who it is; encryption without verification does not restrict who may connect."
	}
	if unread := unreadFragments(u); len(unread) > 0 {
		out.Detail += fmt.Sprintf(" %s could not be read, so if client-certificate verification is configured anywhere it is there.", strings.Join(unread, " and "))
	}
	out.Detail += hostsCaveat
	return out
}

// hostsExcerpt renders the hosts key for evidence, telling apart the three
// ways of not binding anything.
//
// They are three different positions for an operator to be in. One host wrote
// the key and asked for nothing, one never wrote it and is running on whatever
// the unit passes, and one has no configuration file at all — and the remedy
// for a finding elsewhere in this module differs between them, so a report
// that rendered all three as "hosts: none" would be hiding the distinction it
// exists to draw.
func hostsExcerpt(d fact.DockerDaemon) string {
	switch {
	case d.State == fact.DockerConfigAbsent:
		return "no daemon.json; the sockets come from the unit's -H flags"
	case !d.HasKey("hosts"):
		return "hosts not set in this file; the sockets come from the unit's -H flags"
	case len(d.Hosts) == 0:
		return "hosts: [] (explicitly empty)"
	}
	return "hosts: " + strings.Join(d.Hosts, ", ")
}

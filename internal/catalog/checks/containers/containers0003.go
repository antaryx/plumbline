package containers

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests whether unrestricted traffic between containers on the
// default bridge network is disabled.
var Check0003 = catalog.Check{
	ID:     "CONTAINERS-0003",
	Module: "CONTAINERS",
	Title:  "The Docker daemon restricts traffic between containers on the default bridge",

	Description: `Containers attached to the default bridge network can, by
default, reach every port of every other container on it. Nothing has to be
published and no rule has to be added: the daemon installs an ACCEPT rule
between them and leaves it there.

That makes a single compromised container a position from which to reach the
others. A database that publishes no port to the host is still on the bridge,
and a web container running attacker code is on the same bridge, so the
database's port is one connection away. Setting icc to false replaces the
blanket ACCEPT with DROP, after which containers reach each other only through
links or published ports, connections somebody had to ask for.

The default is true, so a host with no daemon.json fails this check,
correctly, because the default is what such a host is running.

**This governs the default bridge and nothing else.** Containers on a
user-defined network are unaffected: those have their own isolation from other
networks, and within one, containers can always reach each other whatever icc
says. Docker Compose creates a user-defined network for every project, so on a
host whose workloads all run under Compose this setting changes very little.
It still matters for containers started with a plain docker run, which is most
ad-hoc and many CI ones, and it costs nothing to set.`,

	// Low, where CONTAINERS-0001 and -0002 are Medium, and the reason is reach
	// rather than kind. Those two apply to every container the daemon starts;
	// this one governs a single network that a large share of real workloads do
	// not use. Rating them alike would tell an operator the three are equally
	// worth their afternoon, and the first two are not.
	BaseSeverity: finding.Low,
	Tags:         []string{"containers", "docker", "network-segmentation", "lateral-movement"},
	Requires:     []fact.ID{fact.DockerDaemonID},
	SinceCatalog: 17,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := applicable(d); out != nil {
			return *out
		}

		// nil and true are both "containers can reach each other", because the
		// daemon's default is true. This is the CONTAINERS-0002 shape and the
		// opposite of CONTAINERS-0001: there the value carries the meaning and
		// an empty string is as good as an absent key, here the option has to
		// have been requested. The *bool is what makes the difference
		// expressible — a plain bool would decode an absent icc as false and
		// report an open bridge as a closed one, which is the single most
		// misleading answer this check could give.
		enabled, set := fact.OptBool(d.ICC)

		if set && !enabled {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  d.Path,
				Detail:   "icc is disabled, so containers on the default bridge cannot reach each other except through published ports or links." + flagsCaveat,
				Evidence: []finding.Evidence{evidence(d, "icc: false")},
			}
		}

		detail := "icc is not disabled, so every container on the default bridge can reach every port of every other one, published or not."
		detail += defaultsNote(d)
		detail += flagsCaveat

		// Three ways of arriving here and three different positions for the
		// operator to be in. See CONTAINERS-0002 for why they are told apart.
		excerpt := "icc not set in this file"
		switch {
		case d.State == fact.DockerConfigAbsent:
			excerpt = "no daemon.json; icc defaults to true"
		case set:
			excerpt = "icc: true (explicitly enabled)"
		}

		return catalog.Outcome{
			Result:   finding.Fail,
			Subject:  d.Path,
			Detail:   detail,
			Evidence: []finding.Evidence{evidence(d, excerpt)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set icc to false in the Docker daemon configuration.",
		Effort:  "LOW",
		Steps: []string{
			"Check whether it will change anything for your workloads first: containers on a user-defined network, including everything Docker Compose starts, are unaffected by this setting.",
			"Find containers on the default bridge that talk to each other: docker network inspect bridge lists them, and anything relying on that path will stop working.",
			"Create or edit /etc/docker/daemon.json and set \"icc\": false.",
			"Restart the daemon: systemctl restart docker.",
			"Give the containers that do need to talk a user-defined network instead, docker network create, then --network on each, which is the supported way to scope container-to-container traffic and is unaffected by icc.",
			"Verify: docker network inspect bridge should report com.docker.network.bridge.enable_icc as false.",
		},
		Commands: []string{
			"docker network inspect bridge --format '{{index .Options \"com.docker.network.bridge.enable_icc\"}}'",
			"systemctl restart docker",
		},
		Caution: "Containers on the default bridge that reach each other directly will lose that path immediately. Restarting the daemon also stops every running container unless live-restore is enabled. Move dependent workloads onto a user-defined network before making the change, not after.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-7"},
		{Framework: "nist-800-53-r5", Control: "AC-4"},
	},

	References: []finding.Reference{
		{Title: "Docker, container communication on the default bridge", URL: "https://docs.docker.com/engine/network/drivers/bridge/"},
	},
}

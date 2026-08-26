package containers

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests whether the daemon has been put into experimental mode.
var Check0005 = catalog.Check{
	ID:     "CONTAINERS-0005",
	Module: "CONTAINERS",
	Title:  "The Docker daemon does not run with experimental features enabled",

	Description: `Experimental mode unlocks daemon features that Docker ships
without the guarantees the rest of the engine carries. They are documented as
subject to change or removal without notice, they are excluded from the
stability commitments the supported API makes, and they have seen far less
production exposure than the code paths beside them.

The exposure is attack surface rather than a specific defect. Enabling the
flag turns on API endpoints and daemon subsystems that would otherwise not be
reachable at all, in code that is by construction the least exercised in the
build. Anything with access to the socket can call them, so the daemon's API
grows without the operator's threat model growing with it.

There is a second, quieter cost. An experimental feature can be withdrawn in a
minor release, so a host that came to depend on one is a host whose next Docker
upgrade breaks it — and a daemon that cannot be upgraded is the problem
CONTAINERS-0004 describes, arrived at from the other direction.

Unlike the rest of this module, the daemon's default here is the safe value:
experimental is off unless somebody turned it on. A host with no daemon.json
therefore passes, and a failure means a deliberate act rather than an
oversight. That is also why this is rated below the other checks — the operator
who set it may have had a reason, and the finding is a question rather than an
accusation.`,

	// Low, and the lowest-consequence check in the module. Nothing here is a
	// privilege boundary and nothing is on by default: a FAIL says the daemon
	// is carrying more API than it needs, which is worth knowing and is not
	// worth an afternoon ahead of CONTAINERS-0001.
	BaseSeverity: finding.Low,
	Tags:         []string{"containers", "docker", "attack-surface", "supportability"},
	Requires:     []fact.ID{fact.DockerDaemonID},
	SinceCatalog: 18,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := applicable(d); out != nil {
			return *out
		}

		// This is the one check in the module where silence is a pass, and the
		// reason is that the daemon's default is the value the check wants.
		// CONTAINERS-0002, -0003 and -0004 all have to insist the option was
		// requested, because for those an unwritten key leaves the permissive
		// default in force; here an unwritten key leaves the safe one in
		// force, and demanding "experimental": false be written down would
		// fail every correctly configured host in the fleet for not having
		// said something it did not need to say.
		//
		// So the test is on the value, and the *bool is used only to tell the
		// two shapes of pass apart in the evidence.
		enabled, set := fact.OptBool(d.Experimental)

		if set && enabled {
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: d.Path,
				Detail: "experimental is enabled, so the daemon exposes API endpoints and subsystems that Docker ships without stability or support guarantees." +
					flagsCaveat,
				Evidence: []finding.Evidence{evidence(d, "experimental: true")},
			}
		}

		// Two ways of passing, and they are not the same position to be in.
		// One host wrote the option down and chose off; the other never
		// enabled it. Both are correct, and an operator reading a report wants
		// to know which of the two their host is.
		excerpt := "experimental not set in this file; the default is off"
		switch {
		case d.State == fact.DockerConfigAbsent:
			excerpt = "no daemon.json; experimental defaults to false"
		case set:
			excerpt = "experimental: false (explicitly disabled)"
		}

		return catalog.Outcome{
			Result:   finding.Pass,
			Subject:  d.Path,
			Detail:   "experimental is not enabled, so only the supported API surface is reachable." + defaultsNote(d) + flagsCaveat,
			Evidence: []finding.Evidence{evidence(d, excerpt)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Turn off experimental mode unless a specific feature requires it.",
		Effort:  "LOW",
		Steps: []string{
			"Find out what the flag was turned on for before turning it off: experimental mode is rarely enabled by accident, and something on this host may depend on a feature it unlocks.",
			"If nothing depends on it, edit /etc/docker/daemon.json and set \"experimental\": false, or remove the key — the default is off either way.",
			"If a workload does depend on an experimental feature, treat that as the finding: plan the move to a supported equivalent, because the feature can be withdrawn in any release.",
			"Restart the daemon: systemctl restart docker.",
			"Verify: docker version should no longer report the server as experimental.",
		},
		Commands: []string{
			"docker version --format '{{.Server.Experimental}}'",
			"docker info --format '{{.ExperimentalBuild}}'",
		},
		Caution: "Anything using an experimental daemon feature stops working the moment the flag is cleared. Establish what depends on it first. Restarting the daemon also stops every running container unless live-restore is enabled.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SA-22"},
	},

	References: []finding.Reference{
		{Title: "Docker — daemon configuration file reference", URL: "https://docs.docker.com/reference/cli/dockerd/"},
	},
}

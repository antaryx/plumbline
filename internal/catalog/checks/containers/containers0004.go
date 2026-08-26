package containers

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests whether containers survive a restart of the Docker daemon.
var Check0004 = catalog.Check{
	ID:     "CONTAINERS-0004",
	Module: "CONTAINERS",
	Title:  "The Docker daemon keeps containers running across its own restart",

	Description: `By default, stopping dockerd stops every container on the
host. Upgrading the daemon, changing daemon.json, or a crash in dockerd itself
all become a full outage of everything the machine was running.

live-restore decouples the two: containers keep running while the daemon is
down and are reattached when it comes back.

This is an availability control, and it is in a security catalogue because of
what its absence does to patching. A daemon whose restart takes down every
workload on the host is a daemon that does not get restarted, so the Docker
security update sits unapplied until a maintenance window that keeps slipping.
The exposure is not the downtime; it is the months of running a known-vulnerable
daemon because the alternative was an outage nobody would authorise.

It defaults to off, so a host with no daemon.json fails this check —
correctly, because the default is what such a host is running.

Two limits worth knowing before enabling it. It does not cover a change to the
daemon's own configuration that containers inherit, so some restarts still
require recreating them. And it is incompatible with live Swarm mode, which
manages container lifecycle itself.`,

	// Medium. Unlike the other checks in this module it does not describe a
	// privilege boundary, so it is not obviously comparable to them — but the
	// consequence it leads to, an unpatchable daemon, is a real exposure rather
	// than an inconvenience, and rating it Low would put it below findings that
	// matter less.
	BaseSeverity: finding.Medium,
	Tags:         []string{"containers", "docker", "availability", "patching"},
	Requires:     []fact.ID{fact.DockerDaemonID},
	SinceCatalog: 18,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := applicable(d); out != nil {
			return *out
		}

		// nil and false are both a failure, because the daemon's default is
		// off: an option nobody requested is an option not in force. Same
		// shape as CONTAINERS-0002 and -0003, and the opposite of
		// CONTAINERS-0005, where the default is the safe value and silence is
		// therefore a pass.
		enabled, set := fact.OptBool(d.LiveRestore)

		if set && enabled {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  d.Path,
				Detail:   "live-restore is enabled, so containers keep running while the daemon restarts and the daemon can be patched without an outage." + flagsCaveat,
				Evidence: []finding.Evidence{evidence(d, "live-restore: true")},
			}
		}

		detail := "live-restore is not enabled, so restarting or upgrading the daemon stops every container on this host."
		detail += defaultsNote(d)
		detail += flagsCaveat

		excerpt := "live-restore not set in this file"
		switch {
		case d.State == fact.DockerConfigAbsent:
			excerpt = "no daemon.json; live-restore defaults to false"
		case set:
			excerpt = "live-restore: false (explicitly disabled)"
		}

		return catalog.Outcome{
			Result:   finding.Fail,
			Subject:  d.Path,
			Detail:   detail,
			Evidence: []finding.Evidence{evidence(d, excerpt)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Enable live-restore in the Docker daemon configuration.",
		Effort:  "LOW",
		Steps: []string{
			"Check first whether this host runs Swarm mode: live-restore is incompatible with it, and a Swarm node should be drained and updated rather than kept running through a daemon restart.",
			"Create or edit /etc/docker/daemon.json and set \"live-restore\": true.",
			"Restart the daemon once to apply it. That restart is still an outage — the setting protects subsequent ones, not the one that enables it.",
			"Verify: docker info should report Live Restore Enabled: true.",
			"Test it before relying on it: start a container, systemctl restart docker, and confirm the container is still running and still reachable.",
		},
		Commands: []string{
			"docker info --format '{{.LiveRestoreEnabled}}'",
			"systemctl restart docker",
		},
		Caution: "The restart that enables this setting will itself stop every running container; schedule it. Do not enable it on a Swarm node, where it is unsupported and the orchestrator expects to manage container lifecycle across daemon restarts itself.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CP-10"},
		{Framework: "nist-800-53-r5", Control: "SI-2"},
	},

	References: []finding.Reference{
		{Title: "Docker — keep containers alive during daemon downtime", URL: "https://docs.docker.com/engine/daemon/live-restore/"},
	},
}

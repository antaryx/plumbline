package containers

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests whether the Docker daemon applies no_new_privileges to every
// container by default.
var Check0002 = catalog.Check{
	ID:     "CONTAINERS-0002",
	Module: "CONTAINERS",
	Title:  "The Docker daemon applies no-new-privileges to containers by default",

	Description: `no_new_privileges is a process flag the kernel never clears
once set: a process carrying it, and every child it forks, cannot gain
privileges through execve. Setuid and setgid bits stop taking effect and file
capabilities stop being granted.

Inside a container that closes a specific and well-used path. An attacker with
code execution as an unprivileged container user looks for a setuid binary in
the image — and images routinely carry ping, mount, su and sudo without anybody
having thought about it — then uses it to become root in the container, which is
the position from which a namespace escape is worth attempting. With the flag
set, the setuid bit does nothing and the attacker stays where they landed.

The daemon-wide setting is what makes this reliable. Per-container
--security-opt=no-new-privileges works and depends on whoever wrote the run
command remembering it, which over a fleet means it is sometimes set.

It defaults to off, so a host with no daemon.json fails this check — correctly,
because the default is what such a host is running. It is also cheap: unlike
user-namespace remapping, turning it on breaks only workloads that were
deliberately escalating privileges inside a container.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"containers", "docker", "privilege-boundary", "setuid"},
	Requires:     []fact.ID{fact.DockerDaemonID},
	SinceCatalog: 16,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := applicable(d); out != nil {
			return *out
		}

		// The test is on the option being requested, not merely on the value:
		// nil and false are both "the daemon does not apply the flag", because
		// the default is off. This is why the field is a *bool — a plain one
		// could not tell an operator who wrote false from one who wrote
		// nothing, and the remediation differs between them.
		enabled, set := fact.OptBool(d.NoNewPrivileges)

		if set && enabled {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  d.Path,
				Detail:   "no-new-privileges is enabled, so a setuid binary inside a container cannot be used to gain privileges." + flagsCaveat,
				Evidence: []finding.Evidence{evidence(d, "no-new-privileges: true")},
			}
		}

		detail := "no-new-privileges is not enabled, so a setuid binary inside a container image can be used to become root within the container."
		detail += defaultsNote(d)
		detail += flagsCaveat

		excerpt := "no-new-privileges not set in this file"
		switch {
		case d.State == fact.DockerConfigAbsent:
			excerpt = "no daemon.json; no-new-privileges defaults to false"
		case set:
			// Explicitly false. Worth distinguishing from absent: somebody
			// wrote this down, and a report telling them to "set it" without
			// noticing they already set it to the other value reads as though
			// nobody looked.
			excerpt = "no-new-privileges: false (explicitly disabled)"
		}

		return catalog.Outcome{
			Result:   finding.Fail,
			Subject:  d.Path,
			Detail:   detail,
			Evidence: []finding.Evidence{evidence(d, excerpt)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Enable no-new-privileges in the Docker daemon configuration.",
		Effort:  "LOW",
		Steps: []string{
			"Create or edit /etc/docker/daemon.json and set \"no-new-privileges\": true.",
			"Identify workloads that deliberately escalate inside a container before restarting: anything invoking sudo, su or a setuid helper from an entrypoint will stop working.",
			"Restart the daemon: systemctl restart docker. Running containers keep their existing setting until they are recreated.",
			"Verify on a new container: docker run --rm alpine sh -c 'grep NoNewPrivs /proc/self/status' should report 1.",
			"A workload that genuinely needs to escalate can be exempted per container with --security-opt=no-new-privileges=false, which keeps the safe default for everything else.",
		},
		Commands: []string{
			"docker info --format '{{.SecurityOptions}}'",
			"docker run --rm alpine sh -c 'grep NoNewPrivs /proc/self/status'",
		},
		Caution: "Restarting the daemon stops every running container unless live-restore is enabled. Schedule it, and check first for entrypoints that rely on sudo or a setuid helper — those will fail after the change rather than at restart.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "CM-7"},
	},

	References: []finding.Reference{
		{Title: "no_new_privs — Linux kernel documentation", URL: "https://docs.kernel.org/userspace-api/no_new_privs.html"},
	},
}

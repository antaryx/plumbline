package containers

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests whether the Docker daemon remaps container users into an
// unprivileged range on the host.
var Check0001 = catalog.Check{
	ID:     "CONTAINERS-0001",
	Module: "CONTAINERS",
	Title:  "The Docker daemon remaps container users to unprivileged host uids",

	Description: `Without user-namespace remapping, uid 0 inside a container is
uid 0 on the host. The container's isolation is doing all of the work: a kernel
bug, a permissive bind mount, or a misconfigured capability set turns root in
the container into root on the machine, with no further escalation required.

userns-remap gives the daemon a subordinate uid range and maps container uid 0
onto an unprivileged host uid instead. The isolation still matters, but a
process that gets past it lands as nobody rather than as root, which is the
difference between an escape and a compromise.

It is off by default, so a host with no daemon.json fails this check —
correctly, because the default is what such a host is running.

The trade is real and is why this is not universally enabled: remapping breaks
containers that need to share uids with the host, and it is awkward with
--privileged and with some volume layouts. Where it cannot be enabled, the
compensating controls are the ones that stop a process reaching the boundary in
the first place.`,

	// Medium, not High. This is a missing mitigation rather than a
	// vulnerability: it does not grant anyone anything on its own, it removes a
	// layer that would have contained something else going wrong.
	BaseSeverity: finding.Medium,
	Tags:         []string{"containers", "docker", "privilege-boundary", "namespaces"},
	Requires:     []fact.ID{fact.DockerDaemonID},
	SinceCatalog: 16,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees the required fact is present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)

		if out := applicable(d); out != nil {
			return *out
		}

		// An explicitly empty string is what disables remapping, and it is the
		// same state as the key being absent — dockerd treats "" as off. So the
		// test is on the value rather than on whether the key was written,
		// which is the opposite of CONTAINERS-0002 and is right for the same
		// reason: here the daemon's behaviour turns on the value, there it
		// turns on the option being requested at all.
		if d.UsernsRemap != "" {
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: d.Path,
				Detail: fmt.Sprintf(
					"userns-remap is set to %q, so container uid 0 is mapped to an unprivileged uid on the host.%s",
					d.UsernsRemap, flagsCaveat),
				Evidence: []finding.Evidence{evidence(d, "userns-remap: "+d.UsernsRemap)},
			}
		}

		detail := "userns-remap is not set, so container uid 0 is uid 0 on the host and a process that escapes the container is already root."
		detail += defaultsNote(d)
		detail += flagsCaveat

		// The excerpt distinguishes the two ways of arriving here, because they
		// send an operator to different places: one edits a line, the other
		// creates a file.
		excerpt := "userns-remap not set in this file"
		if d.State == fact.DockerConfigAbsent {
			excerpt = "no daemon.json; userns-remap defaults to disabled"
		} else if d.HasKey("userns-remap") {
			excerpt = `userns-remap: "" (explicitly disabled)`
		}

		return catalog.Outcome{
			Result:   finding.Fail,
			Subject:  d.Path,
			Detail:   detail,
			Evidence: []finding.Evidence{evidence(d, excerpt)},
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Enable userns-remap in the Docker daemon configuration.",
		Effort:  "HIGH",
		Steps: []string{
			"Understand what it will break before enabling it. Containers that share uids with the host, use --privileged, or bind-mount host paths written by root will need changes.",
			"Create or edit /etc/docker/daemon.json and set \"userns-remap\": \"default\", which makes dockerd create and use a dockremap subordinate range.",
			"Check that /etc/subuid and /etc/subgid contain an entry for the remap user; dockerd creates one for 'default' but a named user needs it in place first.",
			"Restart the daemon: systemctl restart docker. Existing containers and images stay, but the daemon's storage moves to a uid-scoped directory and containers must be recreated.",
			"Verify: docker info | grep -i userns should report the remapping, and a container's root should map to a non-zero host uid.",
		},
		Commands: []string{
			"docker info --format '{{.SecurityOptions}}'",
			"systemctl restart docker",
		},
		Caution: "Enabling remapping moves the daemon's data root to a uid-scoped directory: running containers must be recreated and volumes written by a previous root may become unreadable. Do this on a host you can afford to disrupt, and take a backup of /var/lib/docker first.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "SC-39"},
	},

	References: []finding.Reference{
		{Title: "dockerd — isolate containers with a user namespace", URL: "https://docs.docker.com/engine/security/userns-remap/"},
	},
}

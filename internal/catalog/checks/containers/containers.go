// Package containers holds the CONTAINERS module's checks.
//
// The module reads fact.DockerDaemon, which records what
// /etc/docker/daemon.json says and nothing about what the daemon is running.
// The gap is real: dockerd takes the same options as command-line flags and the
// stock unit passes some, so an option set only there is invisible. dockerd
// refuses to start when one appears in both places, so the two cannot disagree
// silently — but a check here states what the file says, not what the daemon is
// doing, and the wording of every detail string is chosen to keep that honest.
//
// CONTAINERS-0006 reads the other half. fact.DockerService records
// docker.service and its drop-ins, which is where the daemon's command line
// lives and therefore where the sockets it listens on are decided. Between the
// two facts the module covers both places a daemon option can be set, and each
// check still names the file it read: a verdict drawn from one of them is never
// phrased as a verdict about the daemon.
//
// There are two gates and they disagree on purpose. A missing daemon.json is
// judged and a missing docker.service is not, because the daemon has
// compiled-in defaults and systemd has none. See applicable and
// serviceApplicable.
package containers

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// applicable decides whether a CONTAINERS check can reach a verdict at all,
// returning a non-nil outcome when it cannot.
//
// **A daemon.json that does not exist is not a Docker that does not exist**,
// and the difference decides whether this module is worth shipping. A host with
// dockerd and no configuration file runs on every compiled-in default, and the
// defaults are what these checks object to: user namespaces are not remapped
// and no_new_privileges is not applied. That is the most common Docker
// installation there is. Treating the missing file as NOT_APPLICABLE would
// decline to judge it, which is the same shape of mistake as reporting PASS for
// something never examined — the module would be quiet on exactly the hosts it
// exists for.
//
// So the gate is Installed, not State. A host with no dockerd has removed the
// subject of the sentence and is NOT_APPLICABLE. A host with dockerd is judged,
// whether its configuration comes from a file or from the daemon's own
// defaults.
//
// The states that remain are the ones where something is at the path and this
// scan could not read it. Those are UNKNOWN: the file may well set the option,
// and reporting FAIL would be a finding about a document nobody opened.
func applicable(d fact.DockerDaemon) *catalog.Outcome {
	if !d.Configurable() {
		return &catalog.Outcome{
			Result: finding.NotApplicable,
			Detail: "No dockerd binary was found on this host, so there is no Docker daemon configuration to report on.",
		}
	}

	switch d.State {
	case fact.DockerConfigPresent, fact.DockerConfigAbsent:
		// Judgeable. Absent means the daemon's own defaults are in force, which
		// is a configuration and not the lack of one.
		return nil

	case fact.DockerConfigDenied:
		return unknown(d, finding.ReasonPermission,
			"the daemon configuration exists and could not be read, so the options it sets are unknown")

	case fact.DockerConfigMalformed:
		// dockerd refuses to start on a file it cannot parse, so this host is
		// running the last configuration that parsed or is not running at all,
		// and this scan cannot tell which.
		return unknown(d, finding.ReasonParse,
			"the daemon configuration is not valid JSON, so dockerd would refuse to load it and the running configuration is not what this file says")

	case fact.DockerConfigTruncated:
		return unknown(d, finding.ReasonTruncated,
			"the daemon configuration exceeded the read cap, and a partial JSON document cannot be parsed")

	case fact.DockerConfigNotRegular:
		// Something occupies the path and it is not a file. Neither reading
		// this as "no configuration, defaults apply" nor as "not installed" is
		// supportable: dockerd is present and what it loaded is unknown.
		return unknown(d, finding.ReasonAmbiguousState,
			"the daemon configuration path is not a regular file, so what dockerd loaded from it cannot be determined")

	default:
		return unknown(d, finding.ReasonAmbiguousState,
			"the daemon configuration could not be read")
	}
}

// unknown builds the UNKNOWN outcome for an unreadable configuration.
func unknown(d fact.DockerDaemon, reason finding.UnknownReason, why string) *catalog.Outcome {
	detail := fmt.Sprintf("Docker is installed at %s but %s.", d.DaemonPath, why)
	if d.Msg != "" {
		detail += " " + capitalise(d.Msg) + "."
	}
	return &catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       d.Path,
		Detail:        detail,
		Evidence:      []finding.Evidence{evidence(d, string(d.State))},
	}
}

// evidence cites the configuration file.
//
// Unlike the MEMORY module, the digest goes in Evidence.SHA256 rather than into
// the excerpt: daemon.json is read through the seam's ordinary ReadFile, so its
// bytes are in the bundle's evidence store and an auditor following the digest
// finds the document. A binary is read through ReadOpaque and is not, which is
// why the two modules cite evidence differently.
//
// When there is no file the digest is empty, which is the honest value: there
// is nothing stored to verify against, because there was nothing to read.
func evidence(d fact.DockerDaemon, excerpt string) finding.Evidence {
	// NewEvidence neutralises the untrusted strings a configured value carries
	// (THREAT-MODEL.md T-03).
	return finding.NewEvidence(d.Path, 0, excerpt, d.Digest)
}

// defaultsNote explains, for a host with no configuration file, where the
// setting an operator is being told about actually comes from.
//
// It matters because the remedy differs. An operator whose daemon.json sets the
// option wrongly edits a line; an operator with no daemon.json has to create
// the file, and a report that said "the option is not set" without saying there
// is no file to set it in sends them looking for something that is not there.
func defaultsNote(d fact.DockerDaemon) string {
	if d.State != fact.DockerConfigAbsent {
		return ""
	}
	return fmt.Sprintf(" There is no %s on this host, so the daemon is running on its compiled-in defaults.", d.Path)
}

// flagsCaveat is appended to every verdict drawn from the file.
//
// dockerd accepts the same options as command-line flags and the stock unit
// passes some, so a configuration this check calls absent may be set in the
// unit file instead. dockerd refuses to start when an option is given in both
// places, so the two cannot silently disagree — but this scan reads only the
// file, and a finding that did not say so would be claiming more than it
// checked.
const flagsCaveat = " This reads /etc/docker/daemon.json only; an option passed to dockerd on its command line in the systemd unit is not visible here."

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------------------
// the systemd unit
// ---------------------------------------------------------------------------

// serviceApplicable is applicable's counterpart for the checks that read
// fact.DockerService, and it answers the question the other way round.
//
// The daemon gate insists that a *missing* daemon.json is judged, because a
// daemon with no configuration file is running the defaults and the defaults
// are the finding. Nothing of the sort is true of a unit file. systemd has no
// compiled-in docker.service to fall back on: a unit that is not there starts
// nothing, and there is no configuration to have an opinion about. So absence
// here really is NOT_APPLICABLE, and the two gates differ for a reason rather
// than by oversight.
//
// What that costs is stated in the outcome rather than hidden. A host with
// dockerd and no unit is running the daemon some other way — by hand, under
// another init, inside another supervisor — and this check cannot see that
// command line. Saying so is the difference between "there is nothing to
// report" and "there is nothing I can see", and only the second is honest.
func serviceApplicable(d fact.DockerDaemon, u fact.DockerService) *catalog.Outcome {
	switch u.State {
	case fact.UnitPresent:
		return nil

	case fact.UnitAbsent:
		detail := "There is no docker.service unit in any systemd unit directory on this host, so systemd starts no Docker daemon and there is no ExecStart command line to read."
		if d.Installed {
			detail += fmt.Sprintf(" A dockerd binary is installed at %s, so if a daemon is running here it was started some other way and its command line is not visible to this check.", d.DaemonPath)
		}
		return &catalog.Outcome{Result: finding.NotApplicable, Detail: detail}

	case fact.UnitMasked:
		return &catalog.Outcome{
			Result:  finding.NotApplicable,
			Subject: u.Path,
			Detail:  fmt.Sprintf("%s is masked — it is a symbolic link to /dev/null — so systemd refuses to start it and the vendor unit underneath is not in force. Any dockerd running on this host was started some other way, and its command line is not visible to this check.", u.Path),
		}

	case fact.UnitDenied:
		return unitUnknown(u, finding.ReasonPermission,
			"the unit file exists and could not be read, so the flags dockerd is started with are unknown")

	case fact.UnitTruncated:
		return unitUnknown(u, finding.ReasonTruncated,
			"the unit file exceeded the read cap, so directives past the cut were never read")

	case fact.UnitNotRegular:
		return unitUnknown(u, finding.ReasonAmbiguousState,
			"the unit path is not a regular file or a link to one, so what systemd loads from it cannot be determined")

	default:
		return unitUnknown(u, finding.ReasonAmbiguousState,
			"the unit file could not be read")
	}
}

// unitUnknown builds the UNKNOWN outcome for a unit that could not be read.
func unitUnknown(u fact.DockerService, reason finding.UnknownReason, why string) *catalog.Outcome {
	detail := capitalise(why) + "."
	if u.Msg != "" {
		detail += " " + capitalise(u.Msg) + "."
	}
	return &catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       u.Path,
		Detail:        detail,
		Evidence:      []finding.Evidence{unitEvidence(u, u.Path, string(u.State))},
	}
}

// unitEvidence cites one fragment of the unit.
//
// The digest is carried and the bytes are not, which is the MEMORY module's
// arrangement rather than the daemon collector's: unit fragments are read
// through ReadOpaque, so there is no blob in the bundle to compare against.
// What an auditor gets is a digest they can reproduce with sha256sum on the
// host, which is checkable against the running system rather than against a
// copy this scan made. fact.DockerService explains why an override.conf is not
// something to carry around.
func unitEvidence(u fact.DockerService, origin, excerpt string) finding.Evidence {
	return unitEvidenceAt(u, origin, 0, excerpt)
}

func unitEvidenceAt(u fact.DockerService, origin string, line int, excerpt string) finding.Evidence {
	digest := ""
	for _, f := range u.Fragments {
		if f.Path == origin {
			digest = f.Digest
			break
		}
	}
	// NewEvidence neutralises the untrusted strings a unit file carries
	// (THREAT-MODEL.md T-03). An ExecStart is operator-controlled text and
	// reaches a terminal report by way of this call.
	return finding.NewEvidence(origin, line, excerpt, digest)
}

// unreadFragments returns the unit fragments that were not read and could
// therefore be carrying a flag this scan did not find.
//
// Every check that reads the command line needs it, and each needs it for a
// different flag: CONTAINERS-0006 and -0007 for the --tlsverify that would
// make an exposed socket safe, CONTAINERS-0008 for the --log-driver or
// --log-opt that would make an unbounded log bounded. What they share is the
// shape of the mistake avoided — asserting the absence of something out of a
// file nobody opened — so the list of files nobody opened lives in one place.
//
// It is not the same question as Complete(). A finding that was *found* stands
// whatever else went unread (ADR-0014), so this never downgrades a positive
// result; it qualifies a negative one, and the caller decides which it has.
//
// An absent unit has no command line and a masked one has a command line
// systemd will not run, so neither can be hiding a flag that is in force.
func unreadFragments(u fact.DockerService) []string {
	switch u.State {
	case fact.UnitAbsent, fact.UnitMasked:
		return nil
	case fact.UnitPresent:
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

// unitCaveat is appended to every verdict drawn from the unit, and it is the
// exact mirror of flagsCaveat.
//
// The daemon checks read daemon.json and say that a flag in the unit is
// invisible to them; this one reads the unit and has to say that a socket
// configured in daemon.json is invisible to it. Neither file is the whole
// answer, and a finding that implied otherwise would be claiming more than it
// checked.
const unitCaveat = " This reads docker.service and its drop-ins only; a socket configured by the hosts key in /etc/docker/daemon.json, or by ListenStream in docker.socket, is not visible here."

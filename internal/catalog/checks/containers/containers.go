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
// One gate is shared, because getting it wrong is the module's central risk.
// See applicable.
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

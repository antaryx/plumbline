package containers

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0008 tests whether container output goes somewhere bounded and
// retrievable.
var Check0008 = catalog.Check{
	ID:     "CONTAINERS-0008",
	Module: "CONTAINERS",
	Title:  "The Docker daemon writes container logs to a bounded, retrievable driver",

	Description: `Docker's default logging driver is json-file, and json-file
has no size limit unless one is configured. Every byte a container writes to
stdout or stderr is appended to

	/var/lib/docker/containers/<id>/<id>-json.log

forever, JSON-escaped one line at a time, until the container is removed or the
filesystem fills. A single application logging a stack trace in a restart loop
will do it in an afternoon, and nothing rotates the file in the meantime:
logrotate does not know about it, journald does not own it, and the daemon
itself will not trim it.

**A full /var/lib/docker is not a logging incident, it is an outage.** The
daemon cannot write container state, containers cannot start, and on most hosts
/var is the same filesystem the package manager and the journal use — so the
recovery tools go down with it. It is also a denial of service somebody else can
reach: anything that can make a containerised service log can make it log a lot,
which turns a chatty error path into a way to stop the host.

The other half is retention. Whatever the logs are for — an investigation, an
incident timeline, a compliance obligation — they have to still exist when
somebody looks. json-file's are deleted with the container, so a compromised
container that is restarted takes its own evidence with it, and "docker logs"
on the new one shows nothing. A driver that ships the output off the host keeps
it beyond the host's own lifetime, which is the property an audit trail needs.

Four shapes pass:

  - **local**, which rotates by default at 20 MB across five files. It is
    Docker's own recommendation for a host that keeps its logs locally.
  - **journald** or **syslog**, which hand each line to the daemon that already
    owns rotation and retention on this host.
  - a shipping driver — **fluentd**, **gelf**, **awslogs**, **splunk**,
    **gcplogs** — which sends the output somewhere else, so neither this disk
    nor the loss of this host is what bounds it.
  - **json-file with a max-size log option**, which is the default driver made
    to rotate. Whether 10m or 10g is a sensible bound is a judgement this build
    does not make; that there is a bound at all is what it checks.

**"none" fails, and it fails for the opposite reason.** It bounds the logs
perfectly by not keeping any: docker logs returns nothing, and a container's
output is discarded as it is produced. That is a deliberate act rather than an
oversight, and it is usually a disk-pressure problem solved by deleting the
evidence. Where the output genuinely goes somewhere else already, a shipping
driver says so and none does not.

This is rated Low because nothing here is a privilege boundary. It is a
denial-of-service exposure and an audit-availability one, and both matter on
the day rather than continuously.`,

	// Low. The consequence is a full filesystem or a missing log, not a
	// crossed security boundary — and both failures are recoverable in a way
	// CONTAINERS-0006's is not. It is the same band as CONTAINERS-0005 and for
	// a related reason: the finding is a question about how the host is run
	// rather than an open door.
	BaseSeverity: finding.Low,
	Tags:         []string{"containers", "docker", "logging", "availability", "audit"},
	// Both facts, because either file can name the driver. See
	// effectiveLogDriver.
	Requires:     []fact.ID{fact.DockerDaemonID, fact.DockerServiceID},
	SinceCatalog: 21,

	Eval: func(fs *fact.Set) catalog.Outcome {
		// The runner guarantees both required facts are present and typed.
		d, _, _ := fact.Get[fact.DockerDaemon](fs, fact.DockerDaemonID)
		u, _, _ := fact.Get[fact.DockerService](fs, fact.DockerServiceID)

		// The module's ordinary gate: no dockerd is NOT_APPLICABLE, and a
		// daemon.json that exists and could not be read is UNKNOWN.
		if out := applicable(d); out != nil {
			return *out
		}

		name, source, line, set := effectiveLogDriver(d, u)

		// Whether anything the unit might still say can change the driver.
		//
		// It cannot when daemon.json named it: dockerd refuses to start when
		// an option is given as a flag and in the configuration file at once,
		// so on a host whose daemon is running, a unit this scan only partly
		// read is not also naming a driver. In every other case it can —
		// nothing named one, or the unit named it and pflag takes the last
		// occurrence, so a --log-driver in a fragment nobody opened wins.
		if set && source != d.Path {
			lead := fmt.Sprintf("%s names the %q logging driver on dockerd's command line", source, name)
			if out := unitMayHide(u, d, lead, "a later --log-driver flag", "which driver is in force"); out != nil {
				return *out
			}
		}
		if !set {
			// Nothing names a driver, so the daemon's compiled-in default is
			// in force and the default is the finding. Before that can be
			// said, the command line has to have been read in full:
			// --log-driver is a dockerd flag like any other, and a drop-in
			// this scan could not open is exactly where it would be.
			if out := unitMayHide(u, d, daemonSilence(d, "does not set a logging driver"),
				"a --log-driver flag", "which driver is in force"); out != nil {
				return *out
			}
			name, source = defaultDriver, ""
		}

		switch {
		case name == noneDriver:
			return catalog.Outcome{
				Result:  finding.Fail,
				Subject: d.Path,
				Detail: fmt.Sprintf("The default logging driver is %q, so container output is discarded as it is produced: docker logs returns nothing, and there is no record of what a container did to consult after the fact.%s%s%s",
					noneDriver, configuredIn(d, source, line), defaultsNote(d), loggingCaveat),
				Evidence: logEvidence(d, u, source, line),
			}

		case name == defaultDriver:
			by := sizeBounded(d, u)

			// The bound gets the same test the driver got, and it needs it in
			// one more case. log-driver and log-opt are *different* options,
			// so dockerd's refusal to take one option from two places does not
			// apply between them: a driver named in daemon.json can be bounded
			// by a --log-opt in the unit, and a fragment nobody opened is
			// exactly where such a line lives. So the answer is settled only
			// when daemon.json itself carries the bound.
			if by != d.Path {
				lead := daemonSilence(d, "sets no max-size log option")
				if by != "" {
					lead = fmt.Sprintf("the max-size log option comes from %s", by)
				}
				if out := unitMayHide(u, d, lead, "a --log-opt max-size", "whether the log rotates"); out != nil {
					return *out
				}
			}

			if by != "" {
				return catalog.Outcome{
					Result:  finding.Pass,
					Subject: d.Path,
					Detail: fmt.Sprintf("The default logging driver is json-file and a max-size log option is set in %s, so each container's log rotates at a fixed size rather than growing until the filesystem fills. Whether that size is a sensible one is not examined here.%s%s",
						by, configuredIn(d, source, line), loggingCaveat),
					Evidence: logEvidence(d, u, source, line),
				}
			}

			detail := "The default logging driver is json-file with no max-size log option, so every container's output is appended to a file in /var/lib/docker that nothing rotates and nothing trims until the container is removed."
			if !set {
				detail = "No logging driver is configured, so the daemon uses its default of json-file with no size limit: every container's output is appended to a file in /var/lib/docker that nothing rotates and nothing trims until the container is removed."
			}
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  d.Path,
				Detail:   detail + " A container that logs heavily fills the filesystem the daemon itself writes to, and the logs are deleted with the container rather than retained." + configuredIn(d, source, line) + defaultsNote(d) + loggingCaveat,
				Evidence: logEvidence(d, u, source, line),
			}

		case rotatingDrivers[name] != "":
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: d.Path,
				Detail: fmt.Sprintf("The default logging driver is %q, which %s, so container output is bounded without anything further being configured.%s%s",
					name, rotatingDrivers[name], configuredIn(d, source, line), loggingCaveat),
				Evidence: logEvidence(d, u, source, line),
			}

		case shippingDrivers[name]:
			return catalog.Outcome{
				Result:  finding.Pass,
				Subject: d.Path,
				Detail: fmt.Sprintf("The default logging driver is %q, which ships each container's output off this host, so neither the disk here nor the loss of this host is what bounds it. Whether the collector at the other end is reachable, authenticated or retaining anything is not examined here.%s%s",
					name, configuredIn(d, source, line), loggingCaveat),
				Evidence: logEvidence(d, u, source, line),
			}
		}

		// A driver this build does not know. Docker supports third-party
		// logging plugins, and a plugin named here is almost certainly a log
		// shipper somebody installed on purpose — calling that a failure would
		// report the operator's own answer to this check as the finding. The
		// honest answer is that this build cannot say what it does.
		return catalog.Outcome{
			Result:        finding.Unknown,
			UnknownReason: finding.ReasonAmbiguousState,
			Subject:       d.Path,
			Detail: fmt.Sprintf("The default logging driver is %q, which is not a driver this build recognises — most likely a logging plugin installed on this host — so whether container output is bounded and retained cannot be determined from configuration alone.%s%s",
				name, configuredIn(d, source, line), loggingCaveat),
			Evidence: logEvidence(d, u, source, line),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Set a logging driver that bounds and retains container output, and restart the daemon.",
		Effort:  "LOW",
		Steps: []string{
			"Decide first where the logs should live. If this host is part of an estate with central logging, use the driver that ships to it — fluentd, gelf, awslogs, splunk or gcplogs — because that is the only option that survives the host.",
			"If the logs stay on the host and journald is already collecting everything else, set \"log-driver\": \"journald\" in /etc/docker/daemon.json. Container output then obeys the journal's own SystemMaxUse limits, and docker logs keeps working.",
			"If neither applies, use \"log-driver\": \"local\", which rotates at 20 MB across five files with nothing else to configure.",
			"To keep json-file — because a tool reads the file directly, say — bound it explicitly: \"log-driver\": \"json-file\" with \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}.",
			"Check the file parses before restarting anything: dockerd --validate --config-file /etc/docker/daemon.json. A malformed daemon.json stops the daemon from starting at all.",
			"Restart the daemon: systemctl restart docker.",
			"The setting is a default for containers started afterwards. Existing containers keep the driver they were created with, so recreate them — or accept that the old ones are still unbounded.",
			"Deal with what has already accumulated: du -sh /var/lib/docker/containers/* will show which container's log is the problem, and it is truncated safely only by recreating the container, not by deleting the file underneath a running daemon.",
		},
		Commands: []string{
			"docker info --format '{{.LoggingDriver}}'",
			"du -sh /var/lib/docker/containers/*/*-json.log 2>/dev/null | sort -h | tail",
			"dockerd --validate --config-file /etc/docker/daemon.json",
		},
		Caution: "Changing the driver changes where docker logs reads from, so anything that scrapes the json files directly — a log agent bind-mounted onto /var/lib/docker/containers is the usual one — stops seeing new output. Restarting the daemon also stops every running container unless live-restore is enabled.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AU-4"},
		{Framework: "nist-800-53-r5", Control: "AU-11"},
		{Framework: "nist-800-53-r5", Control: "AU-12"},
		{Framework: "nist-800-53-r5", Control: "SC-5"},
	},

	References: []finding.Reference{
		{Title: "Docker — configure logging drivers", URL: "https://docs.docker.com/engine/logging/configure/"},
		{Title: "Docker — local file logging driver", URL: "https://docs.docker.com/engine/logging/drivers/local/"},
		{Title: "Docker — daemon configuration file reference", URL: "https://docs.docker.com/reference/cli/dockerd/"},
	},
}

// defaultDriver is what dockerd uses when nothing names one, and noneDriver is
// the one that keeps nothing. Both are spelled out because both are failures
// and a reader should be able to see that the check knows the difference.
const (
	defaultDriver = "json-file"
	noneDriver    = "none"
)

// rotatingDrivers keep the output on this host and bound it, each in its own
// way. The clause is the reason, so the finding can say why rather than assert
// that the name is on a list.
var rotatingDrivers = map[string]string{
	"local":    "rotates by default at 20 MB across five files",
	"journald": "hands each line to the systemd journal, where journald's own size limits and rotation apply",
	"syslog":   "hands each line to the host's syslog daemon, where its rotation and retention apply",
}

// shippingDrivers send the output somewhere else, which bounds it here and
// keeps it beyond this host.
var shippingDrivers = map[string]bool{
	"awslogs": true,
	"fluentd": true,
	"gcplogs": true,
	"gelf":    true,
	"splunk":  true,
}

// loggingCaveat is appended to every verdict, and it names a limit the other
// caveats in this module do not have to.
//
// The two socket checks each read one file and say so. This one reads both, so
// what it has to disclaim is different: the driver it found is the daemon's
// *default*, and any container started with docker run --log-driver, or with a
// logging block in a compose file, overrides it for itself. A per-container
// override is not in either file and is not in any fact this build collects.
const loggingCaveat = " This reads the log-driver key in /etc/docker/daemon.json and the --log-driver and --log-opt flags on dockerd's command line; it is the daemon's default, and a container started with its own --log-driver overrides it for itself."

// effectiveLogDriver reports which driver is in force, where it was named, and
// whether anything named one at all.
//
// Both files are read, and daemon.json wins when both set it. That precedence
// is close to arbitrary and it does not matter, because the case cannot arise
// on a running host: dockerd refuses to start when an option is given as a
// flag and in the configuration file at once. A host with the option in both
// places has a daemon that is not running, which is a fault neither this check
// nor CONTAINERS-0006 and -0007 currently detect — the roadmap carries it as
// one gap covering every option rather than as a special case here.
//
// The unit is consulted at all for the reason CONTAINERS-0007 consults it:
// reading only daemon.json would report the compiled-in default on every host
// whose operator configured the driver through a drop-in, which is a FAIL
// against a host that did the thing being asked for.
//
// An explicitly empty value — "log-driver": "" or --log-driver= — is treated
// as unset, because that is what dockerd does with it.
func effectiveLogDriver(d fact.DockerDaemon, u fact.DockerService) (name, source string, line int, set bool) {
	if v := normaliseDriver(d.LogDriver); v != "" {
		return v, d.Path, 0, true
	}
	if v, ok := u.StringFlag("log-driver"); ok {
		if v := normaliseDriver(v); v != "" {
			origin, at := flagOrigin(u, "log-driver")
			return v, origin, at, true
		}
	}
	return "", "", 0, false
}

func normaliseDriver(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// sizeBounded reports where a max-size log option was found, or "" for
// nowhere.
//
// Only the presence of the key is read and never its value, which is what
// fact.DockerDaemon.LogOpts carries — a log option's *values* are where a
// splunk token lives, and a bundle travels. The consequence is that this
// distinguishes a rotating log from an unbounded one and does not judge
// whether the bound is a sensible size. That is the right line: a 10 GB
// max-size is a configuration somebody chose, an absent one is a default
// nobody did.
func sizeBounded(d fact.DockerDaemon, u fact.DockerService) string {
	if d.HasLogOpt("max-size") {
		return d.Path
	}
	for _, opt := range u.StringFlags("log-opt") {
		if strings.HasPrefix(normaliseDriver(opt), "max-size=") {
			return "the unit's command line"
		}
	}
	return ""
}

// flagOrigin returns the fragment and line the last occurrence of a long flag
// came from, so a finding drawn from the command line points at the file an
// operator would edit rather than at the unit in general.
func flagOrigin(u fact.DockerService, name string) (origin string, line int) {
	long, eq := "--"+name, "--"+name+"="
	for _, e := range u.ExecStart {
		for _, tok := range e.Argv {
			if tok == long || strings.HasPrefix(tok, eq) {
				origin, line = e.Origin, e.Line
			}
		}
	}
	return origin, line
}

// unitMayHide returns the UNKNOWN for a command line that was only partly
// read, or nil when there was nothing unread to worry about.
//
// It is called wherever what went unread could still overturn the verdict, and
// working out where that is takes one fact about dockerd. **An option given as
// a flag and in the configuration file at once stops the daemon starting**, so
// anything daemon.json settles, the unit cannot contradict on a running host —
// and a verdict drawn from daemon.json alone stands however little of the unit
// was read. Everything else is exposed: nothing named a driver, or the unit
// named it and pflag takes the last occurrence, or the size bound came from
// the unit — and log-driver and log-opt are different options, so dockerd
// permits *that* split and a drop-in can bound a driver the file named.
//
// The direction is ADR-0014's. An incomplete examination invalidates a
// negative result and never a positive one, and in this check the negative
// result is usually wearing a FAIL's clothes: "no driver is configured" and
// "no bound is set" are both absences, and neither may be asserted out of a
// file nobody opened. What stands regardless is a verdict resting on something
// actually found in daemon.json.
//
// An absent unit reaches here with nothing to report, which is correct: a
// docker.service that does not exist has no flags to hide, so the daemon's
// default really is the answer.
func unitMayHide(u fact.DockerService, d fact.DockerDaemon, lead, what, question string) *catalog.Outcome {
	var reasons []string
	for _, p := range unreadFragments(u) {
		reasons = append(reasons, p+" was not read")
	}
	reasons = append(reasons, u.Ambiguities()...)
	if len(reasons) == 0 {
		return nil
	}

	reason := finding.ReasonAmbiguousState
	if u.State == fact.UnitDenied {
		reason = finding.ReasonPermission
	}
	for _, f := range u.Incomplete() {
		if f.State == fact.UnitDenied {
			reason = finding.ReasonPermission
			break
		}
	}

	return &catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       d.Path,
		Detail: fmt.Sprintf("%s, and the command line was not read in full, so %s cannot be determined — %s in the part that went unread would change the answer: %s.%s",
			lead, question, what, strings.Join(reasons, "; "), loggingCaveat),
		Evidence: []finding.Evidence{evidence(d, logDriverExcerpt(d))},
	}
}

// daemonSilence opens a sentence about something daemon.json did not say,
// telling apart a file that is silent from a file that is not there. The
// remedy differs — edit a line, or create a file — and CONTAINERS-0007 draws
// the same distinction for the same reason.
func daemonSilence(d fact.DockerDaemon, what string) string {
	if d.State == fact.DockerConfigAbsent {
		return fmt.Sprintf("There is no %s on this host", d.Path)
	}
	return d.Path + " " + what
}

// configuredIn names the file the driver was read from, for the verdicts where
// it was not daemon.json.
//
// The remedy is in that file rather than in the one this check is filed
// against, and an operator told "the logging driver is json-file" who then
// finds no log-driver key in daemon.json has been sent to the wrong place.
func configuredIn(d fact.DockerDaemon, source string, line int) string {
	switch {
	case source == "" || source == d.Path:
		return ""
	case line > 0:
		return fmt.Sprintf(" It is set by a --log-driver flag on dockerd's command line, at %s line %d, rather than in %s.", source, line, d.Path)
	default:
		return fmt.Sprintf(" It is set in %s rather than in %s.", source, d.Path)
	}
}

// logEvidence cites daemon.json first and, when the driver came from the unit
// instead, the command line that set it.
//
// daemon.json is first even when it said nothing, because it is this check's
// subject and because an auditor following the finding needs the digest of the
// document that was read. The unit line is second and carries its own digest,
// which is the only thing there is to follow: unit fragments are read through
// ReadOpaque and their bytes are not in the bundle.
func logEvidence(d fact.DockerDaemon, u fact.DockerService, source string, line int) []finding.Evidence {
	out := []finding.Evidence{evidence(d, logDriverExcerpt(d))}
	if source != "" && source != d.Path {
		out = append(out, unitEvidenceAt(u, source, line, execLine(u, source, line)))
	}
	return out
}

// logDriverExcerpt renders what daemon.json says about logging, telling the
// three silences apart the way CONTAINERS-0007 tells apart the three ways of
// binding nothing.
//
// The log-opts key names are shown and their values are not, which is the
// whole of what the fact carries. Showing the names is worth doing: an
// operator reading "log-driver: json-file, log-opts: labels, tag" can see at a
// glance that they configured the driver and still did not bound it.
func logDriverExcerpt(d fact.DockerDaemon) string {
	var base string
	switch {
	case d.State == fact.DockerConfigAbsent:
		return "no daemon.json; log-driver defaults to json-file"
	case !d.HasKey("log-driver"):
		base = "log-driver not set in this file; the default is json-file"
	case d.LogDriver == "":
		base = `log-driver: "" (explicitly empty, so the default applies)`
	default:
		base = "log-driver: " + d.LogDriver
	}
	if len(d.LogOpts) > 0 {
		// Names only. See fact.DockerDaemon.LogOpts.
		base += "; log-opts keys: " + strings.Join(d.LogOpts, ", ")
	}
	return base
}

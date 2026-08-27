package fact

import (
	"fmt"
	"strings"
)

// DockerDaemonID names the Docker daemon configuration fact.
const DockerDaemonID ID = "containers.docker_daemon"

// DockerConfigState is what the collector was able to observe about
// /etc/docker/daemon.json.
//
// The states are separate because a check must not treat them alike, and the
// first two are the pair that matters most here. See DockerDaemon.Installed for
// why "there is no configuration file" is a statement about the file and not
// about Docker.
type DockerConfigState string

const (
	// DockerConfigPresent means the file was read and parsed. The typed fields
	// are meaningful only in this state.
	DockerConfigPresent DockerConfigState = "present"
	// DockerConfigAbsent means there is no daemon.json.
	//
	// **This is not "Docker is unconfigured".** A daemon with no configuration
	// file runs with every compiled-in default, and several of those defaults
	// are what a hardening check exists to object to — inter-container
	// communication is on, user-namespace remapping is off. Absence is a
	// configuration, and on most hosts running Docker it is the configuration.
	DockerConfigAbsent DockerConfigState = "absent"
	// DockerConfigDenied means the file exists and could not be read.
	DockerConfigDenied DockerConfigState = "denied"
	// DockerConfigNotRegular means something is at the path and it is not a
	// regular file.
	DockerConfigNotRegular DockerConfigState = "not_regular"
	// DockerConfigMalformed means the bytes were read and are not valid JSON,
	// or are JSON that is not an object.
	//
	// dockerd refuses to start on such a file, so the daemon on this host is
	// either running the last configuration that parsed or is not running at
	// all, and this scan cannot tell which. Nothing may be concluded about the
	// running configuration from a file the daemon would reject.
	DockerConfigMalformed DockerConfigState = "malformed"
	// DockerConfigTruncated means the read hit the cap. A prefix of a JSON
	// document does not parse and nothing may be concluded from it.
	DockerConfigTruncated DockerConfigState = "truncated"
	// DockerConfigError means the read failed for a reason worth recording
	// verbatim.
	DockerConfigError DockerConfigState = "error"
)

// OptBool reads a JSON boolean that may have been absent, returning the value
// and whether the document set it at all.
//
// The distinction is the whole reason these fields are pointers. Docker's
// defaults are not all false — inter-container communication defaults to on —
// so a key the operator never wrote and a key they explicitly set to false
// describe opposite intentions and, for icc, opposite security postures. A
// plain bool would have merged them into the safer-looking one.
func OptBool(p *bool) (value, set bool) {
	if p == nil {
		return false, false
	}
	return *p, true
}

// DockerDaemon is the Docker daemon's configuration file, as written.
//
// It records what /etc/docker/daemon.json says and nothing about what the
// daemon is actually running, and the gap between those is real rather than
// theoretical. dockerd takes the same options as command-line flags, and the
// unit file that starts it usually carries some: the stock line is
//
//	ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
//
// An option set only on that line is invisible here. dockerd refuses to start
// when an option appears in both places, so the two cannot silently disagree —
// but a flag the file never mentions is in force and unrecorded, and a check
// concluding "icc is not configured, so the default applies" would be wrong on
// any host whose operator hardened it through the unit file instead.
//
// Reading the unit is the SERVICES module's territory and joining the two is a
// later work package. Until then a check reading this fact may state what the
// file says; it may not state what the daemon is doing.
//
// Rootless Docker keeps its configuration at ~/.config/docker/daemon.json,
// which is per-user and is not read here.
type DockerDaemon struct {
	State DockerConfigState `json:"state"`
	// Path is where the configuration was looked for, whether or not it was
	// found.
	Path string `json:"path"`
	// Digest is the sha256 of the bytes read, so a finding can cite the exact
	// document it drew a conclusion from. Set whenever the file was read,
	// parsed or not.
	Digest string `json:"digest,omitempty"`
	// Msg carries the reason for any state other than DockerConfigPresent.
	Msg string `json:"msg,omitempty"`

	// Installed reports whether a dockerd binary was found on the host.
	//
	// It is the field that makes DockerConfigAbsent readable. Absent plus
	// installed is a daemon running on its defaults, which is a configuration
	// worth judging; absent plus not installed is a host that does not run
	// containers, which is NOT_APPLICABLE. A check that read the state alone
	// would have to choose one of those meanings and would be wrong on the
	// other half of the fleet.
	Installed bool `json:"installed"`
	// DaemonPath is where the binary was found, for evidence. Empty when none
	// was.
	DaemonPath string `json:"daemon_path,omitempty"`

	// Keys lists the top-level keys the document set, sorted. **Names only,
	// never values.**
	//
	// It exists so a check can tell "the operator did not set this" from "this
	// build does not model that option", without the fact carrying the whole
	// document. Values are excluded deliberately: daemon.json holds registry
	// mirrors, proxy URLs and storage paths, and a bundle is written to
	// travel (docs/PRIVACY.md). The typed fields below are what the checks
	// need, and a collector reads what the checks need and no more.
	//
	// An unrecognised key is *not* recorded as an error, though dockerd
	// refuses to start on one. The valid key set differs by Docker release, so
	// calling a newer option a fault would report a broken daemon on a host
	// that is merely more current than this build — the same reasoning the
	// SSHD collector applies to unknown keywords.
	Keys []string `json:"keys,omitempty"`

	// UsernsRemap is the user-namespace remapping setting. Empty means the key
	// was absent, which is also its default: containers run in the host's user
	// namespace and a process that escapes one is uid 0 on the host.
	UsernsRemap string `json:"userns_remap,omitempty"`

	// ICC is inter-container communication on the default bridge.
	//
	// **Its default is true**, which is why this is a pointer. An absent key
	// means every container on the default bridge can reach every other one,
	// and reading absence as false would report an open network as closed.
	ICC *bool `json:"icc,omitempty"`

	// LogDriver is the default logging driver. Empty means the key was absent;
	// Docker's own default is "json-file".
	LogDriver string `json:"log_driver,omitempty"`

	// LogOpts lists the keys the log-opts object set, sorted. **Names only,
	// never values**, for the reason Keys gives and rather more urgently.
	//
	// log-opts is where a logging driver's credentials live. "splunk-token"
	// is an authentication token, "awslogs-credentials-endpoint" is a path to
	// one, and "gelf-address" and "fluentd-address" are internal hostnames.
	// A bundle travels (docs/PRIVACY.md, ADR-0015), so the values do not go
	// in it.
	//
	// The names alone answer the one question a check has to ask: json-file
	// writes without a size limit unless max-size is set, so whether that key
	// is present is the difference between a log directory that rotates and
	// one that fills the disk. What the limit actually is — 10m or 10g — is a
	// judgement about whether the bound is sensible rather than whether there
	// is one, and this build does not make it.
	LogOpts []string `json:"log_opts,omitempty"`

	// Experimental enables unstable daemon features. Default false.
	Experimental *bool `json:"experimental,omitempty"`

	// LiveRestore keeps containers running while the daemon is down. Default
	// false. It is a hardening-relevant availability setting rather than a
	// security boundary, and it is here because it costs nothing to record
	// alongside the rest.
	LiveRestore *bool `json:"live_restore,omitempty"`

	// NoNewPrivileges applies the no_new_privs bit to every container by
	// default, which stops a setuid binary inside one from raising privileges.
	// Default false.
	NoNewPrivileges *bool `json:"no_new_privileges,omitempty"`

	// TLS and TLSVerify are the daemon's transport security for its API
	// socket. Default false, so both are pointers for the reason the rest are.
	//
	// They are here because of where they are *not*. A host that exposes the
	// API over the network does it with -H tcp:// on the dockerd command line,
	// which lives in the systemd unit and not in this file — but it may well
	// turn TLS on here, since the two are different options and dockerd only
	// refuses a *single* option given in both places. CONTAINERS-0006 reads
	// the unit for the binding and these two for whether it is protected, and
	// without them it would report a mutually authenticated endpoint as an
	// open one.
	//
	// The distinction between them is not cosmetic. tls encrypts; tlsverify
	// encrypts *and* requires a client certificate signed by the configured
	// CA. Only the second is authentication, and an API that is encrypted and
	// unauthenticated is reachable by anyone who can reach the port.
	TLS       *bool `json:"tls,omitempty"`
	TLSVerify *bool `json:"tls_verify,omitempty"`

	// Hosts are the sockets the daemon listens on, as written.
	//
	// The Docker API is root-equivalent and unauthenticated by default, so a
	// tcp:// entry without TLS is the single highest-value finding this module
	// will make. Recorded as written rather than normalised: "tcp://0.0.0.0:2375"
	// and "tcp://127.0.0.1:2375" are the same option and opposite exposures,
	// and the difference is in text a check has to be able to read.
	Hosts []string `json:"hosts,omitempty"`
}

func (DockerDaemon) FactID() ID       { return DockerDaemonID }
func (DockerDaemon) FactVersion() int { return 1 }

// Parsed reports whether the typed fields may be read. A check gates on this
// before concluding anything: every field below is a zero value when the
// document could not be read, and a zero value here is indistinguishable from
// a key the operator did not set.
func (d DockerDaemon) Parsed() bool { return d.State == DockerConfigPresent }

// Configurable reports whether this host has a Docker daemon to judge at all.
//
// True when a dockerd binary was found, whatever became of the configuration
// file. A host with no Docker resolves the module to NOT_APPLICABLE; a host
// with Docker and no daemon.json is running on defaults and must still be
// judged.
func (d DockerDaemon) Configurable() bool { return d.Installed }

// HasKey reports whether the document set a top-level key, by its daemon.json
// name ("userns-remap", not "UsernsRemap").
func (d DockerDaemon) HasKey(name string) bool {
	for _, k := range d.Keys {
		if k == name {
			return true
		}
	}
	return false
}

// HasLogOpt reports whether the log-opts object set a key, by its Docker name
// ("max-size"). Names only: see LogOpts for why the value is not here.
func (d DockerDaemon) HasLogOpt(name string) bool {
	for _, k := range d.LogOpts {
		if k == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// containers.docker_service
// ---------------------------------------------------------------------------

// DockerServiceID names the Docker systemd unit fact.
const DockerServiceID ID = "containers.docker_service"

// DockerServiceUnit is the unit this fact is about. It is fixed rather than
// discovered: the question being answered is "how is the Docker daemon on this
// host started", and on every distribution that ships Docker the answer is
// this unit.
const DockerServiceUnit = "docker.service"

// DockerExec is one effective ExecStart directive, split into arguments.
//
// Argv is the command line as systemd would split it — whitespace separated,
// honouring single and double quotes — with the executable at index 0 and
// systemd's own prefix characters stripped into Prefixes. It is *not*
// expanded: a $VARIABLE stays a $VARIABLE, because what it expands to lives in
// an Environment= assignment or an EnvironmentFile that this collector
// deliberately does not read. See DockerService.Ambiguities.
//
// **One kind of value is removed rather than recorded.** The value of a
// --log-opt is replaced with [REDACTED], keeping the option's key: log options
// are where a logging driver's credentials are configured, and this is the one
// command line a bundle carries. The same options written in daemon.json have
// only ever had their key names recorded, and a bundle must not disclose more
// because of which file an operator chose. Nothing else is altered, so every
// other argument is the argument systemd passed. See the collector's
// scrubArgs.
type DockerExec struct {
	// Origin is the fragment this directive survived from.
	Origin string `json:"origin"`
	// Line is the 1-based line in that fragment, so evidence points somewhere.
	Line int `json:"line"`
	// Prefixes are the systemd modifier characters that preceded the
	// executable ("@", "-", ":", "+", "!", "!!"), as written. Recorded because
	// "-" makes a failure non-fatal and "+" runs without the unit's sandbox,
	// and both change what the line means.
	Prefixes string   `json:"prefixes,omitempty"`
	Argv     []string `json:"argv"`
}

// DockerHostBinding is one -H/--host value from the effective ExecStart.
type DockerHostBinding struct {
	// Spec is the socket specification as written: "fd://", "unix:///var/run/
	// docker.sock", "tcp://0.0.0.0:2375". Never normalised — "tcp://0.0.0.0"
	// and "tcp://127.0.0.1" are the same option and opposite exposures.
	Spec   string `json:"spec"`
	Origin string `json:"origin"`
	Line   int    `json:"line"`
}

// DockerService is how systemd starts the Docker daemon, as written.
//
// It is the other half of the pair DockerDaemon warned about. That fact
// records /etc/docker/daemon.json and says at length that an option passed to
// dockerd on its command line is invisible to it; this one reads the command
// line. Between them the two cover both places a daemon option can be set,
// which matters most for the sockets the API listens on: the stock unit passes
// -H fd:// and the documented way to expose the API over the network is to add
// a drop-in that passes -H tcp://, neither of which appears in daemon.json at
// all. dockerd refuses to start when an option is given in both places, so the
// two facts cannot describe conflicting live configurations.
//
// **The bytes of these files are not in the bundle.** They are read through
// ReadOpaque, so what travels is the digest and the ExecStart arguments and
// nothing else. That is not the trade DockerDaemon makes, and the reason is
// what else lives in a unit: an override.conf is where a fleet puts
// Environment="HTTPS_PROXY=https://user:password@proxy", which is the single
// most common way a credential ends up in /etc on a Docker host. Storing the
// whole fragment as an evidence blob would put those in an artifact designed
// to travel, which is the concern ADR-0015 exists for. Only ExecStart is kept,
// because only ExecStart is read.
//
// ExecStart itself is then scrubbed of the one class of value that can be a
// credential — see DockerExec — so the exception the unit gets is narrower
// than "one whole line": it is the flags, and the values of the flags whose
// values a check needs.
//
// **What is not modelled**, and would change the answer if it were set:
//
//   - EnvironmentFile= and Environment=, so a $DOCKER_OPTS in the command line
//     is recorded unexpanded and reported as an ambiguity rather than guessed
//     at. See Ambiguities.
//   - systemd's % specifiers, which are not expanded either. None of them
//     appear in any distribution's docker.service.
//   - Top-level drop-in directories (/etc/systemd/system/service.d/), which
//     apply to every service on the host rather than to this unit.
//   - socket activation. The stock unit binds fd://, which means the listening
//     socket comes from docker.socket rather than from dockerd. A tcp:// entry
//     in docker.socket's ListenStream= exposes the API exactly as -H tcp://
//     would and is not read here.
type DockerService struct {
	State UnitState `json:"state"`
	// Unit is the unit name looked for, always DockerServiceUnit.
	Unit string `json:"unit"`
	// Path is the unit file that won, or where one was looked for last when
	// none did.
	Path string `json:"path,omitempty"`
	// Digest is the sha256 of the unit file's bytes. Empty when it was not
	// read.
	Digest string `json:"digest,omitempty"`
	// Msg carries the reason for any state other than UnitPresent.
	Msg string `json:"msg,omitempty"`

	// Fragments is every file that contributed or was meant to, in systemd's
	// own application order: the unit first, then its drop-ins.
	Fragments []UnitFragment `json:"fragments,omitempty"`

	// ExecStart is the effective list, after drop-ins and after the resets
	// they use to clear it.
	//
	// systemd folds ExecStart across fragments: a non-empty assignment appends
	// and an empty one ("ExecStart=") clears the list, which is why every
	// documented Docker override starts with a bare ExecStart= line. What is
	// recorded here is the result of that fold and not the lines that produced
	// it, because the result is what runs.
	ExecStart []DockerExec `json:"exec_start,omitempty"`
}

func (DockerService) FactID() ID       { return DockerServiceID }
func (DockerService) FactVersion() int { return 1 }

// Judgeable reports whether ExecStart may be read as the daemon's command
// line. False for every state in which some part of the unit was not seen.
func (s DockerService) Judgeable() bool { return s.State == UnitPresent }

// Complete reports whether every fragment that would have contributed was
// actually read.
//
// It is separate from State because the failure it describes is partial: the
// unit itself can read perfectly while a drop-in beside it is unreadable, and
// a drop-in is precisely where an operator puts the flag that changes the
// answer. A check that looked only at State would report on a command line it
// had only part of.
func (s DockerService) Complete() bool { return len(s.Incomplete()) == 0 }

// Incomplete returns the fragments that were not read, excluding shadowed ones
// — systemd would not have applied those, so failing to read one changes
// nothing.
func (s DockerService) Incomplete() []UnitFragment {
	return IncompleteFragments(s.Fragments)
}

// Hosts returns every -H/--host value in the effective ExecStart, in order.
//
// The extraction lives here rather than in the collector on purpose. A fact
// records what was observed; which of those bytes constitute a socket binding
// is a reading of dockerd's flag grammar, and readings improve. Keeping it on
// this side of the bundle means a bundle recorded today is re-read by a later
// build's understanding of the grammar, which is the promise DATA-MODEL.md
// §6.1 makes and which a collector-side extraction would quietly break.
//
// pflag, which dockerd uses, accepts a shorthand's value in three forms —
// "-H tcp://x", "-Htcp://x" and "-H=tcp://x" — and the long form in two. All
// five are recognised. A clustered shorthand that hides an H ("-DH tcp://x")
// is not, and is reported by Ambiguities instead of being read wrongly.
func (s DockerService) Hosts() []DockerHostBinding {
	var out []DockerHostBinding
	for _, e := range s.ExecStart {
		for i := 1; i < len(e.Argv); i++ {
			spec, consumed, ok := hostFlagAt(e.Argv, i)
			if !ok {
				continue
			}
			i += consumed
			out = append(out, DockerHostBinding{Spec: spec, Origin: e.Origin, Line: e.Line})
		}
	}
	return out
}

// hostFlagAt reads a -H/--host at argv[i], returning its value and how many
// extra tokens it consumed.
func hostFlagAt(argv []string, i int) (spec string, consumed int, ok bool) {
	tok := argv[i]

	next := func() (string, int, bool) {
		if i+1 < len(argv) {
			return argv[i+1], 1, true
		}
		// A trailing "-H" with nothing after it. dockerd would refuse to
		// start; there is no value to report and inventing one would be worse
		// than reporting none.
		return "", 0, false
	}

	switch {
	case tok == "--host":
		return next()
	case strings.HasPrefix(tok, "--host="):
		return strings.TrimPrefix(tok, "--host="), 0, true
	case tok == "-H":
		return next()
	case strings.HasPrefix(tok, "-H"):
		// "-Htcp://x" and "-H=tcp://x".
		return strings.TrimPrefix(tok[2:], "="), 0, true
	}
	return "", 0, false
}

// BoolFlag reports whether a dockerd boolean long flag is in force in the
// effective ExecStart. name is given without dashes ("tlsverify").
//
// pflag booleans are true when named alone and take a value only in the
// --flag=value form, so "--tlsverify=false" is a real way to write off and is
// read as one. A flag named more than once takes its last value, as pflag
// does.
func (s DockerService) BoolFlag(name string) bool {
	on, _ := s.boolFlag(name)
	return on
}

func (s DockerService) boolFlag(name string) (on, set bool) {
	long, eq := "--"+name, "--"+name+"="
	for _, e := range s.ExecStart {
		for _, tok := range e.Argv {
			switch {
			case tok == long:
				on, set = true, true
			case strings.HasPrefix(tok, eq):
				v := strings.TrimPrefix(tok, eq)
				on = !(v == "false" || v == "0" || v == "f" || v == "no" || v == "off")
				set = true
			}
		}
	}
	return on, set
}

// StringFlag reports the value of a dockerd long flag that takes one, and
// whether the command line set it at all. name is given without dashes
// ("log-driver").
//
// Both spellings pflag accepts are read — "--log-driver journald" and
// "--log-driver=journald" — and a flag named more than once takes its last
// value, as pflag does. There is no shorthand form here: unlike -H, the flags
// this is used for have no single-letter alias, so the clustered-shorthand
// ambiguity Hosts has to worry about does not arise.
//
// The "set" return is the point of the signature. An empty string is a value
// an operator can write ("--log-driver=") and is not the same as a flag that
// was never passed, and for a check whose whole subject is what the daemon
// falls back to, merging the two would be the error worth avoiding.
func (s DockerService) StringFlag(name string) (value string, set bool) {
	vals := s.StringFlags(name)
	if len(vals) == 0 {
		return "", false
	}
	return vals[len(vals)-1], true
}

// StringFlags returns every value given for a long flag, in command-line
// order.
//
// It exists for the flags dockerd accepts more than once — --log-opt is the
// one that matters here, since each option is its own occurrence — where
// taking the last would discard the rest.
func (s DockerService) StringFlags(name string) []string {
	long, eq := "--"+name, "--"+name+"="
	var out []string
	for _, e := range s.ExecStart {
		for i := 1; i < len(e.Argv); i++ {
			switch tok := e.Argv[i]; {
			case tok == long:
				// A trailing flag with nothing after it is a command line
				// dockerd would refuse to start on. There is no value to
				// report and inventing one would be worse than reporting none.
				if i+1 < len(e.Argv) {
					out = append(out, e.Argv[i+1])
					i++
				}
			case strings.HasPrefix(tok, eq):
				out = append(out, strings.TrimPrefix(tok, eq))
			}
		}
	}
	return out
}

// Ambiguities returns the reasons this build cannot claim to have read the
// whole command line, one human-readable sentence each.
//
// There are two, and both are the same mistake avoided. An unexpanded
// $DOCKER_OPTS may hold "-H tcp://0.0.0.0:2375" and this collector does not
// read the environment file that would say; a clustered shorthand may hide an
// -H that a naive scan of the token would miss. In either case the honest
// answer to "does this unit bind a TCP socket" is that it cannot be
// determined, and a check reading an empty list from Hosts must consult this
// before calling that a pass.
func (s DockerService) Ambiguities() []string {
	var out []string
	for _, e := range s.ExecStart {
		for i := 1; i < len(e.Argv); i++ {
			tok := e.Argv[i]
			switch {
			case strings.Contains(tok, "$"):
				out = append(out, fmt.Sprintf("%s line %d passes %s, whose value comes from an environment file this scan does not read", e.Origin, e.Line, tok))
			case clusterHidesHost(tok):
				out = append(out, fmt.Sprintf("%s line %d passes %s, a clustered shorthand whose -H value this build will not guess at", e.Origin, e.Line, tok))
			}
		}
	}
	return out
}

// clusterHidesHost reports a single-dash token that contains an H somewhere
// other than the front, where pflag would read it as a shorthand -H whose
// value depends on what the letters before it consume.
func clusterHidesHost(tok string) bool {
	if len(tok) < 2 || tok[0] != '-' || tok[1] == '-' {
		return false
	}
	return strings.Contains(tok[2:], "H")
}

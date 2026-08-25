package fact

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

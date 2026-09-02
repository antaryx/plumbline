// Package containers collects container-runtime configuration. It begins with
// the Docker daemon, which is the runtime most hosts have and the one whose
// defaults are least like a hardened configuration.
//
// This is the first collector in the tree to parse JSON. Everything before it
// read a line-oriented text file, where a malformed byte affects one directive
// and the rest of the file still means something. A JSON document has no such
// property: one stray comma and the whole file is unreadable, and dockerd
// refuses to start rather than ignoring it. That makes the malformed case more
// consequential here than anywhere else in the codebase, and it is recorded as
// its own state so a check resolves to UNKNOWN rather than to the defaults.
//
// **The file is not the running configuration.** dockerd accepts the same
// options as command-line flags, and the stock unit file passes some:
//
//	ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
//
// An option set only there is invisible to this collector. dockerd refuses to
// start when an option is given in both places, so the two cannot disagree
// silently, but a flag the file never mentions is in force and unrecorded.
// fact.DockerDaemon says so at length; a check reading it may state what the
// file says and not what the daemon is doing.
//
// dockerservice.go is the other half of that sentence. It reads docker.service
// and its drop-ins, which is where the command line actually lives, and the
// two collectors together cover both places a daemon option can be set. They
// stay separate deliberately — see ServiceID — and every check still says
// which of the two it read, because a verdict drawn from one file must not be
// phrased as a verdict about the daemon.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier. The collector is "containers"; the fact it
// writes is "containers.docker_daemon".
const ID = "containers"

// DaemonConfigPath is where dockerd reads its configuration unless told
// otherwise with --config-file.
//
// Rootless Docker uses ~/.config/docker/daemon.json instead, which is per-user
// and is not read here: a scan does not know which accounts run a rootless
// daemon, and walking every home directory to find out is a filesystem walk
// this collector has no business doing.
const DaemonConfigPath = "/etc/docker/daemon.json"

// maxConfigRead bounds the configuration file. daemon.json holds a few dozen
// keys on the most elaborate host; anything approaching this is not a
// configuration file and should not be held in memory in a root process.
const maxConfigRead = 1 << 20 // 1 MiB

// daemonBinaries are where dockerd is installed, in probe order.
//
// Finding one is what distinguishes "this host does not run containers" from
// "this host runs Docker on its compiled-in defaults", and those resolve to
// NOT_APPLICABLE and to a real verdict respectively. Without the distinction a
// check reading an absent daemon.json would have to pick one meaning and would
// be wrong on the other half of the fleet.
var daemonBinaries = []string{
	"/usr/bin/dockerd",
	"/usr/local/bin/dockerd",
	"/usr/sbin/dockerd",
}

// Collector implements collect.Collector for the Docker daemon configuration.
type Collector struct{}

// New returns the containers collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

// Produces names the fact this collector is responsible for, so a failure it
// never got to report is filed against containers.docker_daemon, which is what
// CONTAINERS checks will require and look up.
func (Collector) Produces() []fact.ID { return []fact.ID{fact.DockerDaemonID} }

// DependsOn is nil. Reading a configuration file needs nothing else observed
// first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// /etc/docker/daemon.json is 0644 on a stock installation, so an unprivileged
// scan usually reads it. Declaring CapRoot would make such a scan skip the
// collector wholesale and report only that it was skipped; running it means the
// collector reads the file and records what actually happened — ErrPermission
// against this path — which is the specific, actionable observation.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: three stats and one bounded file read. No walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is five seconds. One small file by name cannot legitimately take
// longer; if it does, /etc is on a filesystem that is not answering, and an
// audit that hangs on one configuration file is worse than one that records why
// it stopped.
func (Collector) Timeout() time.Duration { return 5 * time.Second }

// Collect observes the Docker daemon configuration and records it in fs.
//
// It returns nil in every circumstance. A configuration that could not be read
// is recorded as a state on the fact rather than as a fact error, because the
// most common reason for not reading it — there is no such file — is not a
// failure at all. It is what a host running Docker on its defaults looks like,
// and it is a configuration a check has to be able to judge.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	d := fact.DockerDaemon{Path: DaemonConfigPath}
	d.Installed, d.DaemonPath = findDaemon(s)

	if ctx.Err() != nil {
		// An abandoned scan stops reading. The runner has already stopped
		// waiting, so the read below is work done on the audited host for a
		// result nobody will look at.
		d.State = fact.DockerConfigError
		d.Msg = "the scan was abandoned before the configuration was read"
		fs.Put(d)
		// Not swallowed: the cancellation is recorded in the fact above, and a
		// check reading DockerConfigError reports UNKNOWN with that message.
		// Returning ctx.Err() would send the runner down its timeout branch,
		// which discards the collector's facts, so the message would be lost
		// and replaced with a generic one. Every other collector does the same.
		return nil //nolint:nilerr // the cancellation is recorded as a fact state, not dropped
	}

	readConfig(s, &d)
	fs.Put(d)
	return nil
}

// findDaemon reports whether a dockerd binary is installed and where.
//
// A stat that is refused is treated as "not found here" and the probe moves on.
// That is deliberate: the alternative is a fact error over a path that is
// merely one of three guesses, and a host where /usr/local/bin cannot be
// stat'ed still answers the question if dockerd is in /usr/bin. The cost of
// being wrong is a NOT_APPLICABLE on a host that does run Docker, which is a
// visible gap rather than a false assurance.
func findDaemon(s system.System) (installed bool, path string) {
	for _, p := range daemonBinaries {
		fi, err := s.Stat(p)
		if err != nil {
			continue
		}
		// A symlink to dockerd counts: what matters is that something is
		// installed at the path a unit file would exec.
		if fi.IsRegular || fi.IsSymlink {
			return true, p
		}
	}
	return false, ""
}

// readConfig reads and parses daemon.json into d.
func readConfig(s system.System, d *fact.DockerDaemon) {
	res, err := s.ReadFile(DaemonConfigPath, maxConfigRead)
	switch {
	case errors.Is(err, system.ErrNotExist):
		// The ordinary case on a host running Docker, and not an error. Every
		// compiled-in default is in force, which is a configuration and not an
		// absence of one — see fact.DockerConfigAbsent.
		d.State = fact.DockerConfigAbsent
		return
	case errors.Is(err, system.ErrPermission):
		d.State = fact.DockerConfigDenied
		d.Msg = "cannot read the daemon configuration"
		return
	case errors.Is(err, system.ErrNotRegular):
		d.State = fact.DockerConfigNotRegular
		d.Msg = "the configuration path is not a regular file"
		return
	case err != nil:
		d.State = fact.DockerConfigError
		d.Msg = err.Error()
		return
	}

	if res.Truncated {
		// A prefix of a JSON document does not parse, and reporting on one
		// would be reporting on a file we only partly saw.
		d.State = fact.DockerConfigTruncated
		d.Msg = "the configuration exceeded the read cap"
		return
	}

	// The digest comes from the seam, which computed it over the bytes actually
	// read. It is recorded before the parse so that a document that turned out
	// to be malformed still cites the bytes the conclusion was drawn from.
	d.Digest = res.SHA256

	// Two passes over the same bytes. The first is the typed read the checks
	// use; the second recovers the key names, which is how a check tells "the
	// operator did not set this" from "this build does not model that option".
	//
	// Decoding into a map is also what rejects a document that is valid JSON
	// and not an object: dockerd wants an object, and `[]` or `"hardened"`
	// would unmarshal into a struct as an error but is worth catching by the
	// same route as a syntax fault, because the consequence is identical.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(res.Data, &raw); err != nil {
		d.State = fact.DockerConfigMalformed
		d.Msg = "not a JSON object: " + err.Error()
		return
	}

	var doc daemonDoc
	if err := json.Unmarshal(res.Data, &doc); err != nil {
		// Valid JSON, wrong shape for a key this build models — a string where
		// a boolean belongs, say. dockerd would refuse it too.
		d.State = fact.DockerConfigMalformed
		d.Msg = "a configured value has the wrong type: " + err.Error()
		return
	}

	d.State = fact.DockerConfigPresent
	d.Keys = make([]string, 0, len(raw))
	for k := range raw {
		d.Keys = append(d.Keys, k)
	}
	// Sorted so that two collections of an unchanged host produce byte-identical
	// facts; ranging over a map is randomised.
	sort.Strings(d.Keys)

	d.UsernsRemap = doc.UsernsRemap
	d.ICC = doc.ICC
	d.LogDriver = doc.LogDriver
	if len(doc.LogOpts) > 0 {
		d.LogOpts = make([]string, 0, len(doc.LogOpts))
		for k := range doc.LogOpts {
			d.LogOpts = append(d.LogOpts, k)
		}
		sort.Strings(d.LogOpts)
	}
	d.Experimental = doc.Experimental
	d.LiveRestore = doc.LiveRestore
	d.NoNewPrivileges = doc.NoNewPrivileges
	d.TLS = doc.TLS
	d.TLSVerify = doc.TLSVerify
	d.Hosts = doc.Hosts
}

// daemonDoc is the subset of daemon.json this build models.
//
// Pointers for the booleans, because Docker's defaults are not all false and an
// absent key therefore cannot be represented by one. icc defaults to true: a
// plain bool would turn "the operator never wrote this" into "inter-container
// communication is off", which is the opposite of what the daemon does.
//
// Unknown keys are ignored by encoding/json, which is the behaviour wanted
// here: they are recorded by name in DockerDaemon.Keys and judged by nothing.
// logOpts is decoded for its key names and never for its values. json.RawMessage
// rather than string because a value of the wrong type — a bare number where
// Docker wants "10m" — must not turn the whole document into DockerConfigMalformed
// over a key whose values this build has no use for. See fact.DockerDaemon.LogOpts
// for why the values do not travel.
type logOpts map[string]json.RawMessage

type daemonDoc struct {
	UsernsRemap     string   `json:"userns-remap"`
	ICC             *bool    `json:"icc"`
	LogDriver       string   `json:"log-driver"`
	LogOpts         logOpts  `json:"log-opts"`
	Experimental    *bool    `json:"experimental"`
	LiveRestore     *bool    `json:"live-restore"`
	NoNewPrivileges *bool    `json:"no-new-privileges"`
	TLS             *bool    `json:"tls"`
	TLSVerify       *bool    `json:"tlsverify"`
	Hosts           []string `json:"hosts"`
}

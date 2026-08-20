package fact

import (
	"sort"
	"strconv"
	"strings"
)

// SysctlID names the kernel runtime-parameter fact.
const SysctlID ID = "kernel.sysctl"

// SysctlState is why a parameter does or does not have a running value.
//
// The three failure states are kept apart because they lead a check to three
// different verdicts. A parameter this kernel does not implement is
// NOT_APPLICABLE — there is nothing to harden. A parameter we were not allowed
// to read is UNKNOWN(insufficient_privileges) — it may well be set wrong and we
// cannot see it. Collapsing them, which is what a bare "missing" would do,
// turns an unprivileged scan into a clean bill of health.
type SysctlState string

const (
	// SysctlObserved means the value was read. Value is meaningful.
	SysctlObserved SysctlState = "observed"
	// SysctlAbsent means /proc/sys has no such key: the kernel was built
	// without the feature, the module is not loaded, or the LSM is disabled.
	SysctlAbsent SysctlState = "absent"
	// SysctlDenied means the key exists and we were refused. Some keys are
	// unreadable even as root under namespacing or kernel lockdown, and some
	// are write-only by design.
	SysctlDenied SysctlState = "denied"
	// SysctlError means the read failed for a reason that is neither of the
	// above. Msg carries what happened.
	SysctlError SysctlState = "error"
)

// SysctlRunning is one parameter as the running kernel reports it.
type SysctlRunning struct {
	Key   string      `json:"key"`
	State SysctlState `json:"state"`
	// Value is the raw text read from /proc/sys, whitespace trimmed. Only
	// meaningful when State is SysctlObserved. It stays a string because the
	// kernel exposes integers, lists of integers and free text through the
	// same interface, and a collector that parsed eagerly would have to decide
	// what to do about the ones it could not — which is a judgement, and
	// judgements belong in checks.
	Value string `json:"value,omitempty"`
	// Path is where it was read from, for evidence.
	Path string `json:"path"`
	// Msg explains a non-observed state.
	Msg string `json:"message,omitempty"`
}

// Int parses the running value as a single integer.
//
// Returns false when the parameter was not observed or does not hold one
// integer. A check must treat false as UNKNOWN(unparseable_source), never as a
// zero: `kernel.randomize_va_space` reading as 0 means ASLR is off, and
// inventing that from an unparseable value would be a fabricated FAIL exactly
// as inventing a 2 would be a fabricated PASS.
func (r SysctlRunning) Int() (int, bool) {
	if r.State != SysctlObserved {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(r.Value))
	if err != nil {
		return 0, false
	}
	return n, true
}

// SysctlSetting is one `key = value` line from one configuration file. Every
// occurrence is retained, not just the winning one, because a check that
// reports drift has to be able to show the operator which file to edit.
type SysctlSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// Sysctl is the kernel's runtime parameters, as they are running and as they
// are configured.
//
// The two are separate maps on purpose. `/proc/sys` is what is running;
// `/etc/sysctl.conf` and the `sysctl.d` directories are what will be running
// after a reboot. A host with a hardened file and an unhardened kernel is a
// real and common finding, and a fact that merged the two would hide it.
type Sysctl struct {
	// Running holds one entry per parameter the collector probed, including
	// the ones it could not read. A probed key is always present here; absence
	// from this map means the collector never asked, which no check may read
	// as a value.
	Running map[string]SysctlRunning `json:"running"`

	// Configured holds every setting found in the configuration files, keyed
	// by parameter, in application order: later entries override earlier ones.
	Configured map[string][]SysctlSetting `json:"configured,omitempty"`

	// Files lists the configuration files read, in application order.
	Files []string `json:"files,omitempty"`
	// Digests maps each file in Files to the sha256 of the bytes read from it,
	// so a finding can cite evidence an auditor can verify against the
	// bundle's evidence store (ADR-0009).
	Digests map[string]string `json:"digests,omitempty"`
	// UnreadableFiles lists configuration files that exist and could not be
	// read, with why. A check comparing running against configured must not
	// conclude "not configured" while one of these is outstanding: the setting
	// it is looking for may be in the file it could not open.
	//
	// The reason is carried rather than summarised so the check can map it to
	// the right UNKNOWN code. "We were not allowed to read your configuration"
	// and "your configuration is too large to read" send an operator to
	// different places.
	UnreadableFiles []SysctlUnreadableFile `json:"unreadable_files,omitempty"`
}

// SysctlUnreadableFile is a configuration file that exists and could not be
// read.
type SysctlUnreadableFile struct {
	File string    `json:"file"`
	Kind ErrorKind `json:"kind"`
	Msg  string    `json:"message,omitempty"`
}

func (Sysctl) FactID() ID       { return SysctlID }
func (Sysctl) FactVersion() int { return 1 }

// Run returns the running state of one parameter. The second return is false
// when the collector never probed the key, which is different from probing it
// and being refused — see SysctlState.
func (s Sysctl) Run(key string) (SysctlRunning, bool) {
	r, ok := s.Running[key]
	return r, ok
}

// RunningMatching returns every probed parameter whose key has the given
// prefix and suffix, sorted by key. It exists for the parameters the kernel
// namespaces per network interface, where the set of keys is a property of the
// host rather than something a check can name in advance.
func (s Sysctl) RunningMatching(prefix, suffix string) []SysctlRunning {
	var out []SysctlRunning
	for key, r := range s.Running {
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// EffectiveConfigured returns the setting that would win at the next boot: the
// last occurrence in application order.
//
// The second return is false when no file sets the parameter.
func (s Sysctl) EffectiveConfigured(key string) (SysctlSetting, bool) {
	all := s.Configured[key]
	if len(all) == 0 {
		return SysctlSetting{}, false
	}
	return all[len(all)-1], true
}

// ConfiguredConflict reports whether more than one configuration file sets this
// parameter to different values.
//
// It matters because the order in which drop-in files are applied is not the
// same on every host: systemd-sysctl merges the sysctl.d directories by
// filename and applies /etc/sysctl.conf last, while procps `sysctl --system`
// walks the directories in its own documented order. They agree in the common
// case and can disagree when one parameter is set twice with different values.
//
// A check that meets a conflict must return UNKNOWN rather than pick a winner.
// Guessing produces a confident claim about what this host will do after a
// reboot, which is exactly the kind of statement an operator acts on.
func (s Sysctl) ConfiguredConflict(key string) bool {
	all := s.Configured[key]
	if len(all) < 2 {
		return false
	}
	first := strings.TrimSpace(all[0].Value)
	for _, set := range all[1:] {
		if strings.TrimSpace(set.Value) != first {
			return true
		}
	}
	return false
}

// ConfiguredKeys returns every parameter any configuration file sets, sorted.
// Sorted because a finding's detail text is part of the deterministic output.
func (s Sysctl) ConfiguredKeys() []string {
	out := make([]string, 0, len(s.Configured))
	for key := range s.Configured {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// RunningKeys returns every probed parameter, sorted.
func (s Sysctl) RunningKeys() []string {
	out := make([]string, 0, len(s.Running))
	for key := range s.Running {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// UnreadableFileNames returns the unreadable configuration files, sorted.
func (s Sysctl) UnreadableFileNames() []string {
	out := make([]string, 0, len(s.UnreadableFiles))
	for _, f := range s.UnreadableFiles {
		out = append(out, f.File)
	}
	sort.Strings(out)
	return out
}

// WorstUnreadableKind returns the error kind a check should report when the
// configuration is incomplete. Permission outranks the rest because it is both
// the most common cause and the one with an obvious remedy; a caller with no
// unreadable files gets the zero value and false.
func (s Sysctl) WorstUnreadableKind() (ErrorKind, bool) {
	if len(s.UnreadableFiles) == 0 {
		return "", false
	}
	worst := s.UnreadableFiles[0].Kind
	for _, f := range s.UnreadableFiles {
		if f.Kind == ErrPermission {
			return ErrPermission, true
		}
	}
	return worst, true
}

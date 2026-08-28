package fact

import (
	"path"
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
	// Resolved maps a configuration file that is a symbolic link to the path
	// its contents were actually read from.
	//
	// The Debian family ships /etc/sysctl.d/99-sysctl.conf as a link to
	// /etc/sysctl.conf, which is how the traditional file comes to be applied
	// last among the drop-ins. Both paths are read and both appear in Files,
	// because procps `sysctl --system` reads both — the duplicate is harmless,
	// since two identical values are not a conflict — but a finding citing the
	// link alone would send an operator to open a symlink.
	//
	// Present only for the files that are links, so its absence is the common
	// case rather than missing information.
	Resolved map[string]string `json:"resolved,omitempty"`
	// Excluded lists the keys a configuration file explicitly withheld from
	// glob matching: a line naming the key prefixed with "-" and *not*
	// followed by "=". sysctl.d(5) gives that syntax exactly one meaning —
	// "this key is excluded from being set by any matching glob pattern" — and
	// it is not the same as the "-" that prefixes an assignment, which only
	// says failures to apply it may be ignored.
	//
	// It has to be recorded because the distributions use it. systemd's own
	// 50-default.conf sets net.ipv4.conf.*.rp_filter and then withholds
	// net.ipv4.conf.all.rp_filter, so that the per-interface values stand on
	// their own and "all" stays at 0 — which is deliberate, because "all" is a
	// floor the kernel takes the maximum against, and pinning it would take
	// away an operator's ability to turn filtering down on one interface.
	// Without this field a glob would appear to set a key the file went out of
	// its way not to set.
	//
	// The Value of each entry is empty: an exclusion has no value, which is
	// what distinguishes it from an assignment.
	Excluded []SysctlSetting `json:"excluded,omitempty"`

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
	all := s.SettingsFor(key)
	if len(all) == 0 {
		return SysctlSetting{}, false
	}
	return all[len(all)-1], true
}

// SettingsFor returns every setting that assigns key, in application order,
// resolving the three rules sysctl.d(5) gives for glob patterns.
//
// A file may assign a key by naming it, or by naming a glob that matches it.
// Reading only the literal name misses the second, and the distributions use
// it: Red Hat's 50-redhat.conf sets net.ipv4.conf.*.rp_filter rather than
// listing the interfaces, so a check that looked up
// net.ipv4.conf.all.rp_filter by name found nothing and reported a host with
// reverse path filtering configured as a host without it.
//
// The rules, in the order they resolve:
//
//  1. An explicit assignment wins outright. "Keys for which an explicit
//     pattern exists will be excluded from any glob matching" — so a literal
//     line beats a glob no matter which file or line either is on, and this is
//     the one case where application order does not decide.
//  2. Otherwise an exclusion — "-key" with no "=" — means no glob may set it,
//     and the key is unset however many patterns match.
//  3. Otherwise every matching glob applies, in application order.
//
// Matching is done on the path form, so a pattern's "*" spans one component
// and not the separators around it, which is what glob(7) does and therefore
// what systemd does. A key naming a VLAN interface is the one shape this
// cannot resolve exactly — "eth0.1" contains the separator character, so the
// dotted form of net.ipv4.conf.eth0.1.rp_filter is ambiguous about where the
// components divide. No check asks about a named interface; the two keys they
// ask about, "all" and "default", have no dots in them.
func (s Sysctl) SettingsFor(key string) []SysctlSetting {
	if literal := s.Configured[key]; len(literal) > 0 {
		return literal
	}
	for _, ex := range s.Excluded {
		if ex.Key == key {
			return nil
		}
	}

	var out []SysctlSetting
	for pattern, sets := range s.Configured {
		if !isGlob(pattern) || !globMatches(pattern, key) {
			continue
		}
		out = append(out, sets...)
	}
	if len(out) < 2 {
		return out
	}
	// Two patterns can match the same key, and Configured is a map, so the
	// order they came out in is not the order they are applied in. Files is in
	// application order, which is what restores it.
	pos := make(map[string]int, len(s.Files))
	for i, f := range s.Files {
		if _, seen := pos[f]; !seen {
			pos[f] = i
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if pi, pj := pos[out[i].File], pos[out[j].File]; pi != pj {
			return pi < pj
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// GlobbedBy reports the pattern that assigns key when nothing names it
// explicitly, so a finding can quote the line that is actually doing the work
// rather than claiming the key was named.
func (s Sysctl) GlobbedBy(key string) (SysctlSetting, bool) {
	if len(s.Configured[key]) > 0 {
		return SysctlSetting{}, false
	}
	set, found := s.EffectiveConfigured(key)
	if !found || !isGlob(set.Key) {
		return SysctlSetting{}, false
	}
	return set, true
}

// ExcludedFrom reports the line that withheld key from glob matching.
//
// The distinction matters to a reader of a finding. "Nothing sets this" and
// "a file sets every interface and then deliberately withheld this one" are
// different states of the world, and only the second is a decision somebody
// made.
func (s Sysctl) ExcludedFrom(key string) (SysctlSetting, bool) {
	if len(s.Configured[key]) > 0 {
		return SysctlSetting{}, false
	}
	for _, ex := range s.Excluded {
		if ex.Key == key {
			return ex, true
		}
	}
	return SysctlSetting{}, false
}

// isGlob reports whether a configured key is a pattern rather than a name.
func isGlob(key string) bool {
	return strings.ContainsAny(key, "*?[")
}

// globMatches reports whether a sysctl glob pattern covers a key.
//
// Both are converted to the path form first. path.Match gives "*" the meaning
// glob(7) gives it — everything except the separator — which is the whole
// reason net.ipv4.conf.*.rp_filter covers "all" and "default" and not
// "ipv4.conf.all".
func globMatches(pattern, key string) bool {
	ok, err := path.Match(
		strings.ReplaceAll(pattern, ".", "/"),
		strings.ReplaceAll(key, ".", "/"),
	)
	return err == nil && ok
}

// ConfiguredConflict reports whether this parameter's value after the next
// reboot depends on which tool applied the configuration.
//
// **Not every repeat is a conflict, and treating them alike produced UNKNOWN on
// hosts whose answer is perfectly determinable.** The two tools that apply
// these files disagree about one thing only:
//
//   - systemd-sysctl merges every drop-in directory and sorts by *filename
//     across all of them*, with a higher-precedence directory shadowing a
//     same-named file in a lower one.
//   - procps `sysctl --system` walks the directories in its own order and
//     sorts filenames *within* each one, applying /etc/sysctl.conf last.
//
// Both therefore agree completely about two settings in the same directory:
// later filename wins, and within one file the later line wins. They can only
// disagree when the settings are in *different* directories, where one tool
// orders by directory and the other by filename.
//
// So the reading is: reduce each directory to the value it ends on — which is
// the last entry for that directory in application order, and which both tools
// compute the same way — and report a conflict only when two directories end
// on different values.
//
// This also disposes of the usr-merge duplicate without a special case. On a
// host where /lib is a symlink to /usr/lib the same files are reached by two
// paths, each directory ends on the same value, and the two agree.
//
// A check that meets a real conflict must return UNKNOWN rather than pick a
// winner. Guessing produces a confident claim about what this host will do
// after a reboot, which is exactly the kind of statement an operator acts on.
func (s Sysctl) ConfiguredConflict(key string) bool {
	winners := s.directoryWinners(key)
	if len(winners) < 2 {
		return false
	}
	first := winners[0].Value
	for _, w := range winners[1:] {
		if strings.TrimSpace(w.Value) != strings.TrimSpace(first) {
			return true
		}
	}
	return false
}

// directoryWinners returns the setting each directory ends on, in the order the
// directories were first applied.
//
// "Ends on" is the last entry for that directory in Configured[key], which is
// application order: the collector emits directories in search order, files
// sorted within a directory, and lines in file order. Both tools compute that
// same value for a single directory, which is what makes it safe to reduce.
func (s Sysctl) directoryWinners(key string) []SysctlSetting {
	all := s.SettingsFor(key)
	if len(all) == 0 {
		return nil
	}

	order := make([]string, 0, len(all))
	last := make(map[string]SysctlSetting, len(all))
	for _, set := range all {
		dir := configDir(set.File)
		if _, seen := last[dir]; !seen {
			order = append(order, dir)
		}
		last[dir] = set
	}

	out := make([]SysctlSetting, 0, len(order))
	for _, dir := range order {
		out = append(out, last[dir])
	}
	return out
}

// configDir is the directory a setting was read from.
//
// /etc/sysctl.conf is its own directory for this purpose rather than being
// lumped in with /etc/sysctl.d. It is not a drop-in: procps applies it last,
// after every directory, and systemd treats it as one more file to merge — so
// a value there and a value in /etc/sysctl.d are exactly the cross-directory
// case this distinction exists to catch.
func configDir(file string) string {
	if i := strings.LastIndexByte(file, '/'); i > 0 {
		if file[:i] == "/etc" {
			return file
		}
		return file[:i]
	}
	return file
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

// ResolvedFrom returns the path a configuration file's contents were read
// from, and whether the file was a symbolic link at all.
func (s Sysctl) ResolvedFrom(file string) (string, bool) {
	target, ok := s.Resolved[file]
	return target, ok
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

// Package kernel collects the kernel's runtime parameters: what is running,
// from /proc/sys, and what is configured, from the sysctl configuration files.
//
// The two are different observations and the module keeps them apart. A host
// whose /etc/sysctl.d says ASLR is on and whose kernel says it is off is a
// real and common finding — someone edited the file and never rebooted, or
// something overrode it at boot — and reporting either number alone hides it.
//
// /proc is on the shared walker's fstype skip list, so this collector reads it
// directly. That is not a special case: the walker exists to answer questions
// about the filesystem, and /proc is not a filesystem in that sense. Reading a
// named list of parameters is bounded; walking /proc is not.
package kernel

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier. The collector is "kernel"; the fact it
// writes is "kernel.sysctl".
const ID = "kernel"

// ProcSysRoot is where the running kernel exposes its parameters.
const ProcSysRoot = "/proc/sys"

// maxSysctlRead bounds one parameter read. A /proc/sys file holds a number or
// a short line; anything approaching this is not a sysctl and we should not be
// holding it in memory in a root process.
const maxSysctlRead = 64 << 10 // 64 KiB

// maxConfigRead bounds one configuration file.
const maxConfigRead = 1 << 20 // 1 MiB

// probedKeys are the parameters this module reads.
//
// The list is explicit rather than discovered. Walking /proc/sys would collect
// several thousand parameters, most of which no check asserts anything about,
// and would put every one of them in the bundle on disk — including the ones
// that name this host's interfaces and routes. A collector reads what the
// checks need and no more.
//
// Keys are dotted sysctl names; the path is derived by replacing dots with
// slashes. That derivation is exact for every key here. It is not exact in
// general — a VLAN interface named "eth0.1" produces a key with a dot inside a
// path element — which is why the per-interface parameters below are
// enumerated from the directory rather than named here.
var probedKeys = []string{
	"fs.protected_fifos",
	"fs.protected_hardlinks",
	"fs.protected_regular",
	"fs.protected_symlinks",
	"fs.suid_dumpable",
	"kernel.core_pattern",
	"kernel.dmesg_restrict",
	"kernel.kptr_restrict",
	"kernel.perf_event_paranoid",
	"kernel.randomize_va_space",
	"kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope",
	"net.ipv4.tcp_syncookies",
}

// interfaceConfDir is the directory whose subdirectories are network
// interfaces, plus the two pseudo-interfaces "all" and "default".
//
// Several parameters are namespaced per interface, and for those the value
// under conf/all is not the effective value on its own — it is combined with
// each interface's own setting, by a rule that differs per parameter. A check
// that read conf/all alone would report a confidently wrong verdict on a large
// fraction of real hosts, so the per-interface values are collected and the
// combining is left to the check that knows which rule applies.
//
// The set of interfaces is a property of the host, so it is enumerated rather
// than named.
const interfaceConfDir = "/proc/sys/net/ipv4/conf"

// perInterfaceLeaves are the parameters collected for every interface.
var perInterfaceLeaves = []string{
	"accept_source_route",
	"rp_filter",
}

// configFiles are the sysctl configuration sources, in application order:
// later files override earlier ones.
//
// The order is the one procps `sysctl --system` documents, with
// /etc/sysctl.conf last. systemd-sysctl reaches the same place by a different
// route — it merges the drop-in directories by filename and Debian-family
// distributions symlink /etc/sysctl.d/99-sysctl.conf at /etc/sysctl.conf so it
// sorts last. The two agree on the common case and can disagree when one
// parameter is set twice, in different directories, to different values.
// fact.Sysctl.ConfiguredConflict is how a check notices that it must not guess.
var configDirs = []string{
	"/usr/lib/sysctl.d",
	"/lib/sysctl.d",
	"/usr/local/lib/sysctl.d",
	"/run/sysctl.d",
	"/etc/sysctl.d",
}

// mainConfigFile is applied after every drop-in.
const mainConfigFile = "/etc/sysctl.conf"

// Collector implements collect.Collector for kernel runtime parameters.
type Collector struct{}

// New returns the kernel collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

// Produces names the fact this collector is responsible for, so a failure it
// never got to report is filed against kernel.sysctl, which is what KERNEL
// checks require and look up.
func (Collector) Produces() []fact.ID { return []fact.ID{fact.SysctlID} }

// DependsOn is nil. Reading /proc/sys needs nothing else observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// Most of /proc/sys is world-readable and the parameters that are not are the
// interesting ones. Declaring CapRoot would make an unprivileged scan skip the
// collector entirely and report only that it was skipped; running it means
// each parameter records whether it was readable, and a check resolves to
// UNKNOWN(insufficient_privileges) for exactly the ones that were not. That is
// a specific answer rather than a blanket one.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap. A dozen reads of files the kernel generates on demand; no
// walk, no exec, no network.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds.
//
// Every read here is a few bytes from a kernel-generated file and should
// complete in microseconds. The budget is not sized for the normal case: a
// /proc/sys read is a call into the subsystem that owns the parameter, and a
// wedged driver can block one. Ten seconds is long enough that no healthy host
// approaches it and short enough that an audit does not hang on a broken one.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// Collect reads the running parameters and the configuration that sets them.
//
// It returns nil in almost every circumstance. A parameter that could not be
// read is recorded as that parameter's state, not as a failure of the whole
// fact: the difference between "we could not read one key" and "we know
// nothing about this kernel" is the difference between one UNKNOWN finding and
// fifteen.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	sc := fact.Sysctl{
		Running:    map[string]fact.SysctlRunning{},
		Configured: map[string][]fact.SysctlSetting{},
		Digests:    map[string]string{},
	}

	keys := append([]string(nil), probedKeys...)
	keys = append(keys, enumerateInterfaces(s)...)
	sort.Strings(keys)

	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			// Record what we have rather than returning an error: the runner
			// discards a collector that errors under a fired deadline, and the
			// parameters already read are true observations.
			break
		}
		sc.Running[key] = readRunning(s, key, procPathFor(key))
	}

	readConfiguration(ctx, s, &sc)

	if len(sc.Configured) == 0 {
		sc.Configured = nil
	}
	if len(sc.Digests) == 0 {
		sc.Digests = nil
	}
	fs.Put(sc)
	return nil
}

// procPathFor maps a dotted sysctl key to its /proc/sys path.
func procPathFor(key string) string {
	return path.Join(ProcSysRoot, strings.ReplaceAll(key, ".", "/"))
}

// keyForProcPath is the inverse, used for the enumerated parameters where the
// path is authoritative and the dotted name is derived from it.
func keyForProcPath(p string) string {
	rel := strings.TrimPrefix(path.Clean(p), ProcSysRoot+"/")
	return strings.ReplaceAll(rel, "/", ".")
}

// readRunning reads one parameter, classifying every way the read can fail.
func readRunning(s system.System, key, procPath string) fact.SysctlRunning {
	r := fact.SysctlRunning{Key: key, Path: procPath}

	res, err := s.ReadFile(procPath, maxSysctlRead)
	switch {
	case err == nil:
		if res.Truncated {
			r.State = fact.SysctlError
			r.Msg = "value exceeded the read cap; this is not a sysctl-shaped file"
			return r
		}
		r.State = fact.SysctlObserved
		// /proc/sys values are newline-terminated, and some hold several
		// fields separated by tabs. Trimming the ends is all that is safe
		// here; collapsing the interior would destroy a multi-field value.
		r.Value = strings.TrimSpace(string(res.Data))
		return r

	case errors.Is(err, system.ErrNotExist):
		// The kernel does not implement this parameter: built without the
		// feature, module not loaded, or the LSM is disabled. Nothing to
		// harden, which is NOT_APPLICABLE and not a finding.
		r.State = fact.SysctlAbsent
		r.Msg = "no such parameter in this kernel"
		return r

	case errors.Is(err, system.ErrPermission):
		// It exists and we were refused. It may well be set wrong.
		r.State = fact.SysctlDenied
		r.Msg = "permission denied"
		return r

	default:
		r.State = fact.SysctlError
		r.Msg = err.Error()
		return r
	}
}

// enumerateInterfaces lists the per-interface parameters, one key per
// interface per leaf in perInterfaceLeaves.
//
// The directory is read rather than the interface names guessed, and the keys
// are derived from the paths, because an interface may be named in a way that
// does not survive a round trip through the dotted form — a VLAN device is
// literally called "eth0.1".
func enumerateInterfaces(s system.System) []string {
	listing, err := s.ReadDir(interfaceConfDir, 0)
	if err != nil {
		// No interfaces enumerated. The checks that read them report that they
		// could not enumerate rather than reporting on an empty set, because
		// an empty set reads as "no unfiltered interfaces found".
		return nil
	}
	if listing.Truncated {
		// A partial interface list would let a check conclude that every
		// interface is safe when it only saw some of them. Enumerating nothing
		// at all is the honest failure.
		return nil
	}

	var out []string
	for _, e := range listing.Entries {
		if !e.IsDir || e.IsSymlink {
			continue
		}
		for _, leaf := range perInterfaceLeaves {
			out = append(out, keyForProcPath(path.Join(e.Path, leaf)))
		}
	}
	return out
}

// readConfiguration reads every sysctl configuration file, in application
// order, recording every setting each one makes.
func readConfiguration(ctx context.Context, s system.System, sc *fact.Sysctl) {
	for _, file := range configFileList(s) {
		if err := ctx.Err(); err != nil {
			return
		}
		readConfigFile(s, file, sc)
	}
	readConfigFile(s, mainConfigFile, sc)
}

// configFileList expands the drop-in directories in application order.
//
// Within a directory the files are applied in lexicographic order of their
// names, which is what both systemd-sysctl and procps do, and is why every
// distribution's drop-ins are numbered.
func configFileList(s system.System) []string {
	var out []string
	for _, dir := range configDirs {
		listing, err := s.ReadDir(dir, 0)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range listing.Entries {
			if e.IsDir || !strings.HasSuffix(e.Path, ".conf") {
				continue
			}
			names = append(names, e.Path)
		}
		sort.Strings(names)
		out = append(out, names...)
	}
	return out
}

// readConfigFile parses one file into sc, recording it as unreadable if it
// exists and cannot be read.
func readConfigFile(s system.System, file string, sc *fact.Sysctl) {
	res, err := s.ReadFile(file, maxConfigRead)
	switch {
	case errors.Is(err, system.ErrNotExist):
		return
	case errors.Is(err, system.ErrPermission):
		sc.UnreadableFiles = append(sc.UnreadableFiles, fact.SysctlUnreadableFile{
			File: file, Kind: fact.ErrPermission, Msg: "permission denied",
		})
		return
	case err != nil:
		// It is there and we could not read it. A check comparing running
		// against configured must not conclude "not configured" while one of
		// these is outstanding.
		sc.UnreadableFiles = append(sc.UnreadableFiles, fact.SysctlUnreadableFile{
			File: file, Kind: fact.ErrInternal, Msg: err.Error(),
		})
		return
	}
	if res.Truncated {
		sc.UnreadableFiles = append(sc.UnreadableFiles, fact.SysctlUnreadableFile{
			File: file, Kind: fact.ErrTruncated, Msg: "file exceeded the read cap",
		})
		return
	}
	// Recorded as unreadable rather than skipped, so that KERNEL-0007's
	// running-versus-configured comparison keeps its "one of these is
	// outstanding" state. Skipping it would let a sysctl.d file full of
	// garbage read as a file that configures nothing, and a parameter set
	// there would be reported as unconfigured drift.
	if why := collect.NotText(res.Data); why != "" {
		sc.UnreadableFiles = append(sc.UnreadableFiles, fact.SysctlUnreadableFile{
			File: file, Kind: fact.ErrParse, Msg: why,
		})
		return
	}

	sc.Files = append(sc.Files, file)
	sc.Digests[file] = res.SHA256

	for n, raw := range strings.Split(string(res.Data), "\n") {
		key, value, ok := parseSysctlLine(raw)
		if !ok {
			continue
		}
		sc.Configured[key] = append(sc.Configured[key], fact.SysctlSetting{
			Key:   key,
			Value: value,
			File:  file,
			Line:  n + 1,
		})
	}
}

// parseSysctlLine parses one `key = value` line of sysctl.conf(5).
//
// Comments start with # or ;. A leading "-" on the key means "do not fail if
// this key does not exist", which is an instruction to the tool applying the
// setting and not part of the key. Values may contain spaces and are taken
// verbatim after the first "="; whitespace around both sides is not
// significant.
func parseSysctlLine(raw string) (key, value string, ok bool) {
	line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", "", false
	}
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	key = strings.TrimPrefix(key, "-")
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false
	}
	// A key may be written with slashes instead of dots; sysctl accepts both.
	// Normalising here means a check comparing against a running key does not
	// have to know which form the operator used.
	key = strings.ReplaceAll(key, "/", ".")
	return key, strings.TrimSpace(line[eq+1:]), true
}

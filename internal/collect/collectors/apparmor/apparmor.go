// Package apparmor collects the state of the AppArmor mandatory-access-control
// layer and the profiles it has loaded.
//
// **It reads files and runs nothing**, which is the same rule the network
// collector states for the same reason: a scan has to work against a mounted
// image and against a bundle collected months ago, and `aa-status` on the
// scanning host answers for the scanning host. Everything aa-status reports is
// read out of securityfs anyway — /sys/kernel/security/apparmor/profiles is
// the file it parses — so the exec buys nothing but a dependency on the
// apparmor-utils package being installed.
//
// **What a mounted image can and cannot answer is worth stating.** /sys is a
// kernel interface, so an image has none: scanning one establishes whether
// profiles are *installed* and nothing about whether they are loaded. The fact
// records those as separate observations rather than merging them, so a check
// can say "AppArmor is not running" and "AppArmor was never set up" as the two
// different findings they are.
package apparmor

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "apparmor"

// Well-known paths.
const (
	// EnabledPath is the module parameter: "Y" or "N". It exists whenever the
	// LSM is built in, whether or not it is switched on, which is what makes
	// its absence mean "this kernel has no AppArmor".
	EnabledPath = "/sys/module/apparmor/parameters/enabled"
	// ProfilesPath is securityfs. One line per loaded profile:
	// `/usr/sbin/cupsd (enforce)`.
	ProfilesPath = "/sys/kernel/security/apparmor/profiles"
	// ProfileDir is where the packages put profiles on disk. It answers the
	// only half of this fact a mounted image has.
	ProfileDir = "/etc/apparmor.d"
)

// maxRead bounds the profiles interface. A host with a container runtime can
// load a few thousand profiles; each line is a path and a mode, so a megabyte
// is generous and anything past it is not this file.
const maxRead = 1 << 20 // 1 MiB

// maxUnconfining is how many not-confining profile names are kept.
//
// The names are an inventory of what is installed on the host and a bundle
// travels, so the fact keeps counts in full and names only enough for a
// finding to be recognisable — the same trade the filesystem rows and the
// firewall sources make.
const maxUnconfining = 5

// Collector implements collect.Collector for AppArmor.
type Collector struct{}

// New returns the AppArmor collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.AppArmorID} }

// DependsOn is nil. Reading securityfs needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone, deliberately, even though securityfs is root-only on
// most hosts.
//
// Declaring CapRoot would make an unprivileged scan report the whole fact as
// never collected, when it can in fact still answer whether the LSM is enabled
// (the module parameter is world-readable) and whether profiles are installed.
// A refused read of the profile list is recorded as a refusal, which resolves
// to UNKNOWN in the check rather than to a fabricated verdict.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: three bounded reads and one directory listing, no walk.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds. securityfs answers immediately or not at all.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// Collect records the LSM's state, its loaded profiles, and what is installed.
//
// It returns nil in every case. Absent, refused and malformed are observations
// about the host, not failures of the collector.
func (Collector) Collect(_ context.Context, s system.System, fs *fact.Set) error {
	a := fact.AppArmor{
		Path:         EnabledPath,
		ProfilesPath: ProfilesPath,
		ProfileDir:   ProfileDir,
		Counts:       map[fact.AppArmorMode]int{},
	}

	a.State, a.Msg = readEnabled(s)
	readProfiles(s, &a)
	readProfileDir(s, &a)

	if len(a.Counts) == 0 {
		a.Counts = nil
	}
	fs.Put(a)
	return nil
}

// readEnabled reads the module parameter.
//
// **ENOENT here is the SELinux host**, and it is the reason this file is read
// at all rather than inferring the LSM's state from an empty profile list: a
// kernel with no AppArmor and a kernel whose profiles we were not allowed to
// read both produce nothing from securityfs, and they are opposite findings.
func readEnabled(s system.System) (fact.AppArmorState, string) {
	res, err := s.ReadFile(EnabledPath, 64)
	switch {
	case errors.Is(err, system.ErrNotExist):
		return fact.AppArmorAbsent, ""
	case errors.Is(err, system.ErrPermission):
		return fact.AppArmorDenied, "permission denied; run as root"
	case err != nil:
		return fact.AppArmorError, err.Error()
	}

	switch strings.TrimSpace(string(res.Data)) {
	case "Y", "y", "1":
		return fact.AppArmorEnabled, ""
	case "N", "n", "0":
		return fact.AppArmorDisabled, ""
	default:
		// A value neither Y nor N is not a value this build understands, and
		// guessing which way it leans would be guessing about whether a host
		// is confined.
		return fact.AppArmorError, "unrecognised value in " + EnabledPath
	}
}

// readProfiles parses the securityfs profile list.
func readProfiles(s system.System, a *fact.AppArmor) {
	res, err := s.ReadFile(ProfilesPath, maxRead)
	switch {
	case errors.Is(err, system.ErrNotExist):
		a.ProfilesState = fact.AppArmorAbsent
		return
	case errors.Is(err, system.ErrPermission):
		a.ProfilesState = fact.AppArmorDenied
		a.ProfilesMsg = "permission denied; securityfs is root-only on most distributions"
		return
	case err != nil:
		a.ProfilesState = fact.AppArmorError
		a.ProfilesMsg = err.Error()
		return
	case collect.NotText(res.Data) != "":
		a.ProfilesState = fact.AppArmorError
		a.ProfilesMsg = collect.NotText(res.Data)
		return
	}

	a.ProfilesState = fact.AppArmorEnabled
	a.Digest = res.SHA256

	for _, line := range strings.Split(string(res.Data), "\n") {
		name, mode, ok := parseProfile(line)
		if !ok {
			continue
		}
		a.Counts[mode]++
		if !mode.Confining() && len(a.Unconfining) < maxUnconfining {
			a.Unconfining = append(a.Unconfining, fact.AppArmorProfile{Name: name, Mode: mode})
		}
	}
}

// parseProfile reads one line of the profiles interface.
//
// The format is `name (mode)`, and a profile name can contain spaces and
// parentheses — it is a path, or a label a package chose. So the mode is taken
// from the *last* parenthesised group and the name is everything before it,
// rather than by splitting on the first space.
func parseProfile(line string) (string, fact.AppArmorMode, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasSuffix(line, ")") {
		return "", "", false
	}
	open := strings.LastIndex(line, "(")
	if open <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:open])
	if name == "" {
		return "", "", false
	}
	return name, modeOf(line[open+1 : len(line)-1]), true
}

// modeOf maps the word in the parentheses onto a mode.
//
// **An unrecognised mode is AppArmorOther and never enforce.** A newer kernel
// may add one, and a build that fell back to "assume it confines" would report
// a host as protected on the strength of a word it had never seen.
func modeOf(s string) fact.AppArmorMode {
	switch strings.TrimSpace(s) {
	case "enforce":
		return fact.AppArmorEnforce
	case "complain":
		return fact.AppArmorComplain
	case "kill":
		return fact.AppArmorKill
	case "unconfined":
		return fact.AppArmorUnconfined
	case "prompt":
		return fact.AppArmorPrompt
	default:
		return fact.AppArmorOther
	}
}

// readProfileDir counts what is installed on disk.
//
// It is the only half of this fact a mounted image can answer, and it is what
// separates "AppArmor is switched off" from "AppArmor was never set up" on a
// host whose kernel interface says nothing.
func readProfileDir(s system.System, a *fact.AppArmor) {
	res, err := s.ReadDir(ProfileDir, 0)
	switch {
	case errors.Is(err, system.ErrNotExist):
		a.ProfileDirState = fact.SourceAbsent
		return
	case errors.Is(err, system.ErrPermission):
		a.ProfileDirState = fact.SourceDenied
		return
	case err != nil:
		a.ProfileDirState = fact.SourceError
		return
	}

	a.ProfileDirState = fact.SourcePresent
	for _, e := range res.Entries {
		// Profiles are files; abstractions/, tunables/ and local/ are
		// directories of fragments that are included rather than loaded, and
		// counting them would inflate the number an operator compares against
		// what securityfs reports.
		if !e.IsDir {
			a.ProfileFiles++
		}
	}
}

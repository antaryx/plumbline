package cli

import (
	"fmt"
	"path/filepath"
)

// Config file search order, highest priority first (CLI-SPEC.md §5):
//
//	--config PATH
//	$PLUMBLINE_CONFIG
//	./plumbline.yaml          — ignored when euid is 0
//	~/.config/plumbline/config.yaml
//	/etc/plumbline/config.yaml
const (
	cwdConfig    = "plumbline.yaml"
	userConfig   = ".config/plumbline/config.yaml"
	systemConfig = "/etc/plumbline/config.yaml"
)

// ConfigSearch is where a config file may be found, in priority order, given
// the environment a run started in.
type ConfigSearch struct {
	Explicit string // --config
	Env      string // $PLUMBLINE_CONFIG
	Cwd      string // working directory
	Home     string // $HOME
	Euid     int
}

// ConfigCandidates returns the paths that will be consulted, in order.
//
// The working-directory config is dropped when euid is 0 unless it was named
// explicitly with --config. A root-run scanner that honours ./plumbline.yaml
// can be steered by anyone able to write a file into a directory root happens
// to cd into: disable the checks that would catch them, redirect the output
// somewhere they can read it. The attack needs no privilege at all, only
// patience (THREAT-MODEL.md T-07, audit A-30).
//
// System and user configuration are unaffected — those paths are already
// root-owned, so honouring them grants nothing an attacker did not have.
// Explicit --config is also unaffected: the operator typed it, which is the
// difference between configuration and ambient influence.
func ConfigCandidates(s ConfigSearch) []string {
	if s.Explicit != "" {
		return []string{s.Explicit}
	}

	var out []string
	if s.Env != "" {
		out = append(out, s.Env)
	}
	if s.Cwd != "" && s.Euid != 0 {
		out = append(out, filepath.Join(s.Cwd, cwdConfig))
	}
	if s.Home != "" {
		out = append(out, filepath.Join(s.Home, userConfig))
	}
	return append(out, systemConfig)
}

// IgnoredForPrivilege reports the working-directory config that was skipped
// because the run is privileged, so the operator can be told rather than left
// wondering why their file had no effect. Silence here looks like a bug and
// invites someone to "fix" it by removing the control.
func IgnoredForPrivilege(s ConfigSearch) string {
	if s.Explicit == "" && s.Cwd != "" && s.Euid == 0 {
		return filepath.Join(s.Cwd, cwdConfig)
	}
	return ""
}

// errUsage marks an error as a usage or configuration problem, which exits 1:
// nothing was scanned, so the run says nothing about the host.
type errUsage struct{ err error }

func (e errUsage) Error() string { return e.err.Error() }
func (e errUsage) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return errUsage{fmt.Errorf(format, args...)}
}

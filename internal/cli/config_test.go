package cli_test

import (
	"reflect"
	"testing"

	"github.com/antaryx/plumbline/internal/cli"
)

// TestWorkingDirectoryConfigIsIgnoredWhenPrivileged is THREAT-MODEL.md T-07
// and audit A-30. A root-run scanner that honours ./plumbline.yaml can be
// steered by anyone who can write a file into a directory root happens to cd
// into -- disable the checks that would catch them, redirect the output. The
// attack needs no privilege, only patience.
func TestWorkingDirectoryConfigIsIgnoredWhenPrivileged(t *testing.T) {
	base := cli.ConfigSearch{Cwd: "/srv/attacker", Home: "/root"}

	unprivileged := base
	unprivileged.Euid = 1000
	if got := cli.ConfigCandidates(unprivileged); !reflect.DeepEqual(got, []string{
		"/srv/attacker/plumbline.yaml",
		"/root/.config/plumbline/config.yaml",
		"/etc/plumbline/config.yaml",
	}) {
		t.Errorf("unprivileged candidates = %v", got)
	}

	privileged := base
	privileged.Euid = 0
	got := cli.ConfigCandidates(privileged)
	for _, p := range got {
		if p == "/srv/attacker/plumbline.yaml" {
			t.Errorf("a privileged run would read the working-directory config: %v", got)
		}
	}
	// System and user config are unaffected: those paths are already
	// root-owned, so honouring them grants an attacker nothing new.
	if !reflect.DeepEqual(got, []string{
		"/root/.config/plumbline/config.yaml",
		"/etc/plumbline/config.yaml",
	}) {
		t.Errorf("privileged candidates = %v", got)
	}

	// The skip is reported rather than silent: a control that looks like a bug
	// invites someone to fix it by removing it.
	if cli.IgnoredForPrivilege(privileged) != "/srv/attacker/plumbline.yaml" {
		t.Error("the skipped config is not reported")
	}
	if cli.IgnoredForPrivilege(unprivileged) != "" {
		t.Error("an unprivileged run reported a skip it did not make")
	}
}

// TestExplicitConfigIsHonouredEvenAsRoot: the operator typed it, which is the
// difference between configuration and ambient influence.
func TestExplicitConfigIsHonouredEvenAsRoot(t *testing.T) {
	s := cli.ConfigSearch{Explicit: "/tmp/mine.yaml", Cwd: "/srv/attacker", Home: "/root", Euid: 0}
	if got := cli.ConfigCandidates(s); !reflect.DeepEqual(got, []string{"/tmp/mine.yaml"}) {
		t.Errorf("candidates = %v, want only the explicit file", got)
	}
	if cli.IgnoredForPrivilege(s) != "" {
		t.Error("an explicit --config reported a working-directory skip")
	}
}

// TestEnvironmentConfigRanksBelowFlagAndAboveCwd, per CLI-SPEC.md §5.
func TestEnvironmentConfigRanksBelowFlagAndAboveCwd(t *testing.T) {
	s := cli.ConfigSearch{Env: "/etc/ci/plumbline.yaml", Cwd: "/work", Home: "/home/u", Euid: 1000}
	got := cli.ConfigCandidates(s)
	if len(got) == 0 || got[0] != "/etc/ci/plumbline.yaml" {
		t.Errorf("candidates = %v, want the environment path first", got)
	}
	if got[1] != "/work/plumbline.yaml" {
		t.Errorf("candidates = %v, want the working directory second", got)
	}
}

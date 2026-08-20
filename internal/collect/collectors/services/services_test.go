package services_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/services"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collect(t *testing.T, name string) fact.Services {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect %s: %v", name, err)
	}
	sv, ferr, ok := fact.Get[fact.Services](facts, fact.ServicesID)
	if !ok || ferr != nil {
		t.Fatalf("fact missing from %s: ok=%v err=%v", name, ok, ferr)
	}
	return sv
}

func linkAt(t *testing.T, sv fact.Services, path string) fact.UnitLink {
	t.Helper()
	for _, l := range sv.Links {
		if l.Path == path {
			return l
		}
	}
	t.Fatalf("no enablement symlink recorded at %s", path)
	return fact.UnitLink{}
}

// TestEnablementTopologyIsRecovered is the acceptance criterion for the whole
// work package: systemctl's answer, reconstructed from symlinks alone.
func TestEnablementTopologyIsRecovered(t *testing.T) {
	sv := collect(t, "services-compliant")

	if !sv.Systemd {
		t.Fatal("Systemd = false on a host with unit directories")
	}

	for _, tc := range []struct {
		unit string
		want fact.UnitStatus
	}{
		{"sshd.service", fact.StatusEnabled},
		{"chronyd.service", fact.StatusEnabled},
		{"dbus.service", fact.StatusEnabled},
		// Installed and switched off. The distinction from StatusAbsent is
		// what lets a finding say "one command away from running" rather than
		// "not installed", which are different amounts of remaining exposure.
		{"systemd-timesyncd.service", fact.StatusNotEnabled},
		{"telnet.socket", fact.StatusAbsent},
	} {
		if got := sv.Status(tc.unit); got != tc.want {
			t.Errorf("Status(%s) = %s, want %s", tc.unit, got, tc.want)
		}
	}

	l := linkAt(t, sv, "/etc/systemd/system/multi-user.target.wants/sshd.service")
	if l.Target != "multi-user.target" || l.Kind != fact.LinkWants {
		t.Errorf("link target/kind = %s/%s, want multi-user.target/wants", l.Target, l.Kind)
	}
	if l.Origin != fact.OriginAdmin {
		t.Errorf("origin = %s, want %s", l.Origin, fact.OriginAdmin)
	}
	if l.DestState != fact.DestPresent {
		t.Errorf("dest state = %s, want %s", l.DestState, fact.DestPresent)
	}
}

// TestRelativeLinkTargetResolvesAgainstItsOwnDirectory.
//
// systemctl always writes an absolute target, but an administrator running
// `ln -s ../../../../usr/lib/systemd/system/dbus.service .` does not, and a
// relative target read as absolute names a completely different file — one
// that almost never exists, which would report a working enablement as a
// dangling link.
func TestRelativeLinkTargetResolvesAgainstItsOwnDirectory(t *testing.T) {
	sv := collect(t, "services-compliant")
	l := linkAt(t, sv, "/etc/systemd/system/multi-user.target.wants/dbus.service")

	if l.Dest != "../../../../usr/lib/systemd/system/dbus.service" {
		t.Errorf("Dest = %q; the raw target must be preserved for evidence, not normalised away", l.Dest)
	}
	if l.Resolved != "/usr/lib/systemd/system/dbus.service" {
		t.Errorf("Resolved = %q, want /usr/lib/systemd/system/dbus.service", l.Resolved)
	}
	if l.DestState != fact.DestPresent {
		t.Errorf("dest state = %s, want %s — the relative target was not followed", l.DestState, fact.DestPresent)
	}
}

// TestMaskIsRecordedAsAMaskAndNotAsAUnitFile.
func TestMaskIsRecordedAsAMaskAndNotAsAUnitFile(t *testing.T) {
	sv := collect(t, "services-masked")

	u, ok := sv.Effective("telnet.socket")
	if !ok {
		t.Fatal("no unit file recorded for telnet.socket")
	}
	if u.Origin != fact.OriginAdmin {
		t.Errorf("origin = %s, want %s: /etc outranks /usr/lib and is what systemd loads", u.Origin, fact.OriginAdmin)
	}
	if !u.Masked() {
		t.Errorf("Masked() = false for %s -> %q", u.Path, u.Dest)
	}
}

// TestDanglingAndUnresolvedAreDifferentStates.
//
// "The target is not there" and "we could not look" produce opposite verdicts —
// FAIL and UNKNOWN — and a single boolean would have collapsed them into a
// guess. This is the same distinction fact.CronPathState draws, for the same
// reason.
func TestDanglingAndUnresolvedAreDifferentStates(t *testing.T) {
	dangling := collect(t, "services-dangling")
	if got := len(dangling.Dangling()); got != 1 {
		t.Errorf("Dangling() = %d, want 1", got)
	}
	if got := len(dangling.Unresolved()); got != 0 {
		t.Errorf("Unresolved() = %d, want 0", got)
	}

	unresolved := collect(t, "services-unresolved")
	if got := len(unresolved.Dangling()); got != 0 {
		t.Errorf("Dangling() = %d, want 0: a target we were refused is not a target that is absent", got)
	}
	if got := len(unresolved.Unresolved()); got != 1 {
		t.Errorf("Unresolved() = %d, want 1", got)
	}
}

// TestAbsentInitSystemDegradesGracefully: a host with no unit directory
// produces a fact, not an error. The collector's job is to report what the host
// looks like, and "this is not a systemd host" is an observation.
func TestAbsentInitSystemDegradesGracefully(t *testing.T) {
	sv := collect(t, "services-absent")

	if sv.Systemd {
		t.Error("Systemd = true on a host with no unit directory")
	}
	if len(sv.Units) != 0 || len(sv.Links) != 0 {
		t.Errorf("units=%d links=%d, want 0/0", len(sv.Units), len(sv.Links))
	}
	// Every probed directory is still recorded. "We looked and it was not
	// there" is a different claim from "we did not look", and only the fact
	// can carry the difference.
	if len(sv.Dirs) != 4 {
		t.Errorf("recorded %d directories, want 4", len(sv.Dirs))
	}
	for _, d := range sv.Dirs {
		if d.State != fact.DirAbsent {
			t.Errorf("%s = %s, want %s", d.Path, d.State, fact.DirAbsent)
		}
	}
	if !sv.Complete() {
		t.Error("Complete() = false; four directories confirmed absent is a complete observation, not a gap")
	}
}

// TestRefusedDirectoryIsNotAnAbsentOne: an unprivileged scan must not report
// that a host has no enabled services because it could not read the directory
// that lists them.
func TestRefusedDirectoryIsNotAnAbsentOne(t *testing.T) {
	sv := collect(t, "services-denied")

	if !sv.Systemd {
		t.Error("Systemd = false; a directory we were refused is still a directory that is there")
	}
	if sv.Complete() {
		t.Fatal("Complete() = true despite a refused directory")
	}
	bad := sv.Incomplete()
	if len(bad) != 1 || bad[0].Path != "/etc/systemd/system" {
		t.Errorf("Incomplete() = %v, want just /etc/systemd/system", bad)
	}
	if bad[0].State != fact.DirDenied {
		t.Errorf("state = %s, want %s", bad[0].State, fact.DirDenied)
	}
}

// TestUnitBodiesAreNeverCollected guards the rule the package comment states.
//
// A unit file's ExecStart and Environment= lines are operator data, routinely
// including credentials, and no check in this module reads them — so nothing
// should put them in a bundle designed to travel. Every fixture unit body
// carries a marker string; if it ever reaches the serialised fact, somebody
// has started collecting contents and has to argue for it in review.
func TestUnitBodiesAreNeverCollected(t *testing.T) {
	sv := collect(t, "services-compliant")
	if len(sv.Units) == 0 {
		t.Fatal("fixture recorded no unit files")
	}

	encoded, err := json.Marshal(sv)
	if err != nil {
		t.Fatalf("marshal fact: %v", err)
	}
	const marker = "unit bodies are never read"
	if bytes.Contains(encoded, []byte(marker)) {
		t.Errorf("the serialised fact contains a unit file's body; this collector reads metadata and link targets only")
	}
}

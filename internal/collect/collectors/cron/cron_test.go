package cron_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/cron"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collectFixture(t *testing.T, name string) fact.Cron {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	c, _, ok := fact.Get[fact.Cron](facts, fact.CronID)
	if !ok {
		t.Fatalf("cron fact missing for %s", name)
	}
	return c
}

// TestOwnershipSurvivesTheSeam is ADR-0016's central claim, tested end to end.
//
// The fixture's manifest names an owner; the fake applies it; the collector
// copies it into the fact. If any link in that chain drops the field, every
// ownership check silently reads uid 0 — "owned by root" — and passes. There is
// no sentinel that would catch it, which is exactly why it needs a test rather
// than a convention.
func TestOwnershipSurvivesTheSeam(t *testing.T) {
	c := collectFixture(t, "cron-writable")

	d, ok := c.Get("/etc/cron.d")
	if !ok {
		t.Fatal("/etc/cron.d was not probed")
	}
	if d.State != fact.CronObserved {
		t.Fatalf("state = %q, want observed", d.State)
	}
	if d.UID != 1001 || d.GID != 1001 {
		t.Errorf("uid/gid = %d/%d, want 1001/1001; the manifest override did not reach the fact, "+
			"and an ownership check reading 0 here would report the directory as root-owned", d.UID, d.GID)
	}
	if d.RootOwned() {
		t.Error("RootOwned() is true for a directory owned by uid 1001")
	}

	// And the mode override, which git also cannot carry.
	hourly, _ := c.Get("/etc/cron.hourly")
	if hourly.Perm() != fs.FileMode(0o775) {
		t.Errorf("mode = %04o, want 0775", hourly.Perm())
	}
	if !hourly.GroupOrOtherWritable() {
		t.Error("a 0775 directory is not reported as group-writable")
	}
}

// TestRefusedStatIsNotAbsence. The two look alike from a caller that only
// checks for an error, and they produce opposite verdicts: absence can be
// NOT_APPLICABLE, a refusal must be UNKNOWN. Conflating them would let an
// unprivileged scan report that a host has no cron.
func TestRefusedStatIsNotAbsence(t *testing.T) {
	denied := collectFixture(t, "cron-denied")
	for _, p := range denied.Paths {
		if p.State != fact.CronDenied {
			t.Errorf("%s state = %q, want denied", p.Path, p.State)
		}
		if p.Msg == "" {
			t.Errorf("%s carries no reason", p.Path)
		}
	}
	if !denied.Installed {
		t.Error("Installed is false when every path was refused; a refusal is not evidence of absence, " +
			"and reporting it as such would tell an unprivileged operator their host has no cron")
	}

	absent := collectFixture(t, "cron-absent")
	for _, p := range absent.Paths {
		if p.State != fact.CronAbsent {
			t.Errorf("%s state = %q, want absent", p.Path, p.State)
		}
	}
	if absent.Installed {
		t.Error("Installed is true on a host with none of the cron paths")
	}
}

// TestSymlinkIsRecordedAsItself. Stat must not follow the link: the mode and
// owner of the target would describe a file cron may not even read, and the
// link itself is the finding.
func TestSymlinkIsRecordedAsItself(t *testing.T) {
	c := collectFixture(t, "cron-symlink")

	tab, _ := c.Get("/etc/crontab")
	if !tab.IsSymlink {
		t.Errorf("/etc/crontab is not recorded as a symlink: %+v", tab)
	}
	if tab.IsRegular {
		t.Error("/etc/crontab is recorded as a regular file as well as a symlink")
	}

	dir, _ := c.Get("/etc/cron.d")
	if !dir.IsSymlink || dir.IsDir {
		t.Errorf("/etc/cron.d should be a symlink and not a directory: %+v", dir)
	}
}

// TestEveryPathIsProbedInAFixedOrder. The fact is a slice rather than a map so
// that nothing downstream has to sort it; that only holds if the order is
// actually fixed.
func TestEveryPathIsProbedInAFixedOrder(t *testing.T) {
	want := []string{
		"/etc/crontab",
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly",
		"/etc/cron.allow", "/etc/cron.deny",
	}

	for i := 0; i < 10; i++ {
		c := collectFixture(t, "cron-compliant")
		if len(c.Paths) != len(want) {
			t.Fatalf("probed %d paths, want %d", len(c.Paths), len(want))
		}
		for n, p := range c.Paths {
			if p.Path != want[n] {
				t.Fatalf("path %d = %s, want %s", n, p.Path, want[n])
			}
		}
	}
}

// TestNoFileContentsAreCollected. The fact carries metadata and nothing else.
// A future field holding a crontab line would put script paths, hostnames and
// argument-passed credentials into a bundle designed to travel, for checks that
// never read them.
func TestNoFileContentsAreCollected(t *testing.T) {
	c := collectFixture(t, "cron-compliant")
	for _, p := range c.Paths {
		// The fixture's crontab contains this; nothing in the fact may.
		if p.Msg != "" && p.State == fact.CronObserved {
			t.Errorf("%s carries a message on an observed path: %q", p.Path, p.Msg)
		}
	}
}

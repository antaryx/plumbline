package kernel_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/kernel"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collectFixture(t *testing.T, name string) fact.Sysctl {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	sc, ferr, ok := fact.Get[fact.Sysctl](facts, fact.SysctlID)
	if !ok {
		t.Fatalf("kernel.sysctl missing after collection: %v", ferr)
	}
	return sc
}

// TestCollectorContract asserts the declarations the runner schedules on.
func TestCollectorContract(t *testing.T) {
	c := collector.New()
	if got, want := c.ID(), "kernel"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got := c.Produces(); len(got) != 1 || got[0] != fact.SysctlID {
		t.Errorf("Produces = %v, want [%s]", got, fact.SysctlID)
	}
	if got, want := c.Cost(), collect.Cheap; got != want {
		t.Errorf("Cost = %v, want %v", got, want)
	}
	// CapNone deliberately: an unprivileged run must record which parameters
	// it could not read, not be skipped wholesale and report nothing.
	if got, want := c.Requires(), collect.CapNone; got != want {
		t.Errorf("Requires = %v, want %v", got, want)
	}
	if c.Timeout() <= 0 || c.Timeout() > time.Minute {
		t.Errorf("Timeout = %v; the collector must declare a budget it can justify", c.Timeout())
	}
	if _, ok := collect.Default().Get("kernel"); !ok {
		t.Errorf("the kernel collector did not register itself; the registry holds %v", collect.Default().IDs())
	}
}

// TestRunningStatesAreDistinguished is the module's central collector
// invariant. "This kernel has no such parameter" and "we were not allowed to
// read it" are different observations that lead to different verdicts, and a
// collector that reported both as missing would turn an unprivileged scan into
// a clean bill of health.
func TestRunningStatesAreDistinguished(t *testing.T) {
	observed := collectFixture(t, "kernel-hardened")
	r, ok := observed.Run("kernel.randomize_va_space")
	if !ok {
		t.Fatal("kernel.randomize_va_space was not probed")
	}
	if r.State != fact.SysctlObserved || r.Value != "2" {
		t.Errorf("hardened: state=%s value=%q, want observed/2", r.State, r.Value)
	}
	if r.Path != "/proc/sys/kernel/randomize_va_space" {
		t.Errorf("path = %q", r.Path)
	}

	absent := collectFixture(t, "kernel-absent")
	if r, _ := absent.Run("kernel.yama.ptrace_scope"); r.State != fact.SysctlAbsent {
		t.Errorf("absent kernel: state = %s, want %s", r.State, fact.SysctlAbsent)
	}
	if r, _ := absent.Run("kernel.unprivileged_bpf_disabled"); r.State != fact.SysctlAbsent {
		t.Errorf("absent bpf: state = %s, want %s", r.State, fact.SysctlAbsent)
	}

	denied := collectFixture(t, "kernel-denied")
	r, ok = denied.Run("kernel.randomize_va_space")
	if !ok {
		t.Fatal("a denied parameter must still be probed and recorded")
	}
	if r.State != fact.SysctlDenied {
		t.Errorf("denied: state = %s, want %s", r.State, fact.SysctlDenied)
	}
	if _, parsed := r.Int(); parsed {
		t.Error("a denied parameter must not yield an integer; a fabricated 0 is a fabricated verdict")
	}
}

// TestNonIntegerValueDoesNotParse: Int must refuse rather than invent.
func TestNonIntegerValueDoesNotParse(t *testing.T) {
	sc := collectFixture(t, "kernel-unparseable")
	r, _ := sc.Run("kernel.randomize_va_space")
	if r.State != fact.SysctlObserved {
		t.Fatalf("state = %s, want observed: the file was readable", r.State)
	}
	if r.Value != "enabled" {
		t.Errorf("value = %q, want %q", r.Value, "enabled")
	}
	if n, ok := r.Int(); ok {
		t.Errorf("Int() returned %d for %q; it must refuse", n, r.Value)
	}
}

// TestInterfaceEnumeration: the per-interface parameters are discovered from
// the directory, because the set of interfaces is a property of the host.
func TestInterfaceEnumeration(t *testing.T) {
	sc := collectFixture(t, "kernel-hardened")

	got := sc.RunningMatching("net.ipv4.conf.", ".rp_filter")
	want := map[string]bool{
		"net.ipv4.conf.all.rp_filter":     true,
		"net.ipv4.conf.default.rp_filter": true,
		"net.ipv4.conf.lo.rp_filter":      true,
		"net.ipv4.conf.eth0.rp_filter":    true,
	}
	if len(got) != len(want) {
		t.Fatalf("enumerated %d interfaces, want %d: %+v", len(got), len(want), got)
	}
	for _, r := range got {
		if !want[r.Key] {
			t.Errorf("unexpected key %q", r.Key)
		}
	}

	// Sorted, because MaxHits-style truncation aside, a fact built from a map
	// that is iterated unsorted produces findings that change between runs.
	for i := 1; i < len(got); i++ {
		if got[i-1].Key >= got[i].Key {
			t.Errorf("RunningMatching is not sorted: %q before %q", got[i-1].Key, got[i].Key)
		}
	}
}

// TestConfiguredPrecedence: drop-ins are applied in directory order and
// /etc/sysctl.conf goes last, which is what both systemd-sysctl and procps
// arrive at.
func TestConfiguredPrecedence(t *testing.T) {
	sc := collectFixture(t, "kernel-drift")

	set, found := sc.EffectiveConfigured("kernel.randomize_va_space")
	if !found {
		t.Fatal("kernel.randomize_va_space is set in /etc/sysctl.conf and was not recorded")
	}
	if set.Value != "2" || set.File != "/etc/sysctl.conf" {
		t.Errorf("effective configured = %q from %s, want 2 from /etc/sysctl.conf", set.Value, set.File)
	}
	if set.Line != 2 {
		t.Errorf("line = %d, want 2 (line 1 is a comment)", set.Line)
	}

	// /etc/sysctl.conf is applied after every drop-in.
	if len(sc.Files) < 2 || sc.Files[len(sc.Files)-1] != "/etc/sysctl.conf" {
		t.Errorf("files = %v; /etc/sysctl.conf must be applied last", sc.Files)
	}
	// A digest per file, so a finding can cite evidence an auditor can verify.
	for _, f := range sc.Files {
		if sc.Digests[f] == "" {
			t.Errorf("no digest recorded for %s", f)
		}
	}
}

// TestConfiguredConflictIsDetected: two files, two values. The fact says so
// rather than picking, because which one wins depends on the host's sysctl
// implementation.
func TestConfiguredConflictIsDetected(t *testing.T) {
	sc := collectFixture(t, "kernel-conflict")

	if !sc.ConfiguredConflict("kernel.kptr_restrict") {
		t.Errorf("two files set kernel.kptr_restrict differently and the fact did not record a conflict: %+v",
			sc.Configured["kernel.kptr_restrict"])
	}
	if got := len(sc.Configured["kernel.kptr_restrict"]); got != 2 {
		t.Errorf("recorded %d settings, want 2: every occurrence is retained so a finding can name the file to edit", got)
	}
	// A key set once is not a conflict.
	if sc.ConfiguredConflict("kernel.randomize_va_space") {
		t.Error("a parameter set in one file was reported as conflicting")
	}
}

// TestUnreadableConfigFileIsRecordedWithItsReason: a check comparing running
// against configured must be able to map the gap to the right UNKNOWN code.
func TestUnreadableConfigFileIsRecordedWithItsReason(t *testing.T) {
	sc := collectFixture(t, "kernel-denied")

	if len(sc.UnreadableFiles) != 1 {
		t.Fatalf("unreadable files = %+v, want exactly one", sc.UnreadableFiles)
	}
	u := sc.UnreadableFiles[0]
	if u.File != "/etc/sysctl.d/60-hardening.conf" {
		t.Errorf("file = %q", u.File)
	}
	if u.Kind != fact.ErrPermission {
		t.Errorf("kind = %q, want %q", u.Kind, fact.ErrPermission)
	}
	if kind, ok := sc.WorstUnreadableKind(); !ok || kind != fact.ErrPermission {
		t.Errorf("WorstUnreadableKind = %q/%v, want permission/true", kind, ok)
	}
	// A file that could not be read is not a file that set nothing.
	if _, found := sc.EffectiveConfigured("kernel.randomize_va_space"); found {
		t.Error("a setting was recorded from a file that could not be read")
	}
}

// TestConfigParsing covers sysctl.conf(5) syntax that shows up in the wild.
func TestConfigParsing(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"_plumbline/fixture.json":   `{"description":"sysctl.conf syntax"}`,
		"proc/sys/fs/suid_dumpable": "0\n",
		"etc/sysctl.conf": "" +
			"# a comment\n" +
			"; another comment style\n" +
			"\n" +
			"   kernel.dmesg_restrict   =   1   \n" +
			"-kernel.kptr_restrict = 1\r\n" +
			"kernel/randomize_va_space = 2\n" +
			"not a setting line\n" +
			"fs.suid_dumpable=0\n",
	})

	sys, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatal(err)
	}
	sc, _, _ := fact.Get[fact.Sysctl](facts, fact.SysctlID)

	for _, tc := range []struct{ key, want string }{
		// Whitespace around the key, the equals sign and the value.
		{"kernel.dmesg_restrict", "1"},
		// A leading "-" is an instruction to the tool applying the setting,
		// not part of the key, and the line ends with CRLF.
		{"kernel.kptr_restrict", "1"},
		// sysctl accepts slashes as well as dots; normalising means a check
		// does not have to know which form the operator used.
		{"kernel.randomize_va_space", "2"},
		// No spaces at all.
		{"fs.suid_dumpable", "0"},
	} {
		set, found := sc.EffectiveConfigured(tc.key)
		if !found {
			t.Errorf("%s was not parsed out of /etc/sysctl.conf", tc.key)
			continue
		}
		if set.Value != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, set.Value, tc.want)
		}
	}

	// Comments and junk produce no settings.
	for _, key := range []string{"a", "not a setting line", "#"} {
		if _, found := sc.EffectiveConfigured(key); found {
			t.Errorf("parsed a setting out of %q", key)
		}
	}
	if got := len(sc.ConfiguredKeys()); got != 4 {
		t.Errorf("parsed %d keys, want 4: %v", got, sc.ConfiguredKeys())
	}
}

// TestCancelledContextStillRecordsWhatItRead: the runner discards a collector
// that errors under a fired deadline, and the parameters already read are true
// observations.
func TestCancelledContextStillRecordsWhatItRead(t *testing.T) {
	sys, err := fake.New(filepath.Join(fixtureRoot, "kernel-hardened"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	facts := fact.NewSet()
	if err := collector.New().Collect(ctx, sys, facts); err != nil {
		t.Fatalf("Collect returned an error for a cancelled context: %v", err)
	}
	if _, _, ok := fact.Get[fact.Sysctl](facts, fact.SysctlID); !ok {
		t.Error("a cancelled collection wrote no fact at all")
	}
}

// writeTree materialises a fixture tree at test time. Used where the scenario
// is about parsing rather than about the host, so committing a directory per
// syntax case would add nine fixtures nobody can tell apart.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := mkdirAll(filepath.Dir(p)); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(p, content); err != nil {
			t.Fatal(err)
		}
	}
}

// mkdirAll and writeFile keep the os import in one place, next to the helper
// that needs it, rather than at the top of a file about kernel parameters.
func mkdirAll(dir string) error   { return os.MkdirAll(dir, 0o755) }
func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }

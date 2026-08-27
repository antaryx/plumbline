package kernel_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/kernel"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
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

// TestASymlinkedDropInIsFollowedToItsTarget is the Debian and Ubuntu layout,
// and it is the common case rather than an edge one.
//
// /etc/sysctl.d/99-sysctl.conf is a symbolic link to /etc/sysctl.conf, which is
// how the traditional file comes to be applied last among the drop-ins. The
// seam opens with O_NOFOLLOW, so the collector used to record the link as an
// unreadable file — and KERNEL-0007 and KERNEL-0017 both declined to answer on
// every host in that family, which is most of them.
//
// The fixture's placeholder file holds the opposite values on purpose. If the
// collector ever reads the placeholder instead of following the link, the
// assertions below invert rather than merely weakening.
func TestASymlinkedDropInIsFollowedToItsTarget(t *testing.T) {
	sc := collectFixture(t, "kernel-symlinked-config")

	if len(sc.UnreadableFiles) != 0 {
		t.Fatalf("the link was recorded as unreadable: %+v", sc.UnreadableFiles)
	}

	const link = "/etc/sysctl.d/99-sysctl.conf"
	target, ok := sc.ResolvedFrom(link)
	if !ok {
		t.Fatalf("no resolution recorded for %s; Resolved = %v", link, sc.Resolved)
	}
	if target != "/etc/sysctl.conf" {
		t.Errorf("resolved to %q, want /etc/sysctl.conf", target)
	}

	// The values are the target's, not the placeholder's.
	for _, c := range []struct{ key, want string }{
		{"kernel.unprivileged_bpf_disabled", "1"},
		{"net.core.bpf_jit_harden", "2"},
	} {
		set, found := sc.EffectiveConfigured(c.key)
		if !found {
			t.Errorf("%s is not configured; the link was not followed", c.key)
			continue
		}
		if set.Value != c.want {
			t.Errorf("%s = %q, want %q — the placeholder was read instead of the target", c.key, set.Value, c.want)
		}
	}

	// Both paths are read, because procps `sysctl --system` reads both, and
	// the duplicate is harmless: two identical values are not a conflict.
	for _, key := range []string{"kernel.unprivileged_bpf_disabled", "net.core.bpf_jit_harden"} {
		if sc.ConfiguredConflict(key) {
			t.Errorf("%s reported as conflicting; the same file read twice is not a disagreement: %+v",
				key, sc.Configured[key])
		}
	}

	// The setting is attributed to the link rather than to the target, because
	// the link's name is what decides where it sorts among the drop-ins — and
	// an operator asking "why is this in force" needs that name.
	set, _ := sc.EffectiveConfigured("kernel.kptr_restrict")
	if set.File != "/etc/sysctl.conf" {
		t.Errorf("last writer = %q; /etc/sysctl.conf is applied after the drop-ins", set.File)
	}
	var viaLink bool
	for _, s := range sc.Configured["kernel.kptr_restrict"] {
		if s.File == link {
			viaLink = true
		}
	}
	if !viaLink {
		t.Errorf("the link is not credited with the setting it applies: %+v", sc.Configured["kernel.kptr_restrict"])
	}

	// The same bytes give the same digest by either path, which is what lets a
	// finding citing the link resolve against the blob the direct read stored.
	if sc.Digests[link] == "" || sc.Digests[link] != sc.Digests["/etc/sysctl.conf"] {
		t.Errorf("digests differ across the link: %q vs %q", sc.Digests[link], sc.Digests["/etc/sysctl.conf"])
	}
}

// TestAFollowedLinkDoesNotPutItsTargetInTheBundle is the safety half.
//
// Following symlinks in a sysctl.d directory is necessary — refusing would put
// the Debian family back where it was — and it hands whoever can write that
// directory a choice of what this collector reads. Configuration files are
// read with ReadFile, so their bytes reach the evidence store; a *link* is
// therefore a way to copy an arbitrary file into an artifact designed to
// travel.
//
// The target is read through ReadOpaque instead, which collect.recordingSystem
// excludes from the evidence store by construction. The parse still happens and
// the digest is still recorded, so nothing about the Debian case is lost.
func TestAFollowedLinkDoesNotPutItsTargetInTheBundle(t *testing.T) {
	base, err := fake.New(filepath.Join(fixtureRoot, "kernel-symlink-escape"))
	if err != nil {
		t.Fatal(err)
	}
	spy := &configReadSpy{System: base}

	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), spy, facts); err != nil {
		t.Fatal(err)
	}

	for _, p := range spy.readFile {
		if p == "/etc/shadow" {
			t.Errorf("a symlinked drop-in was followed with ReadFile, so /etc/shadow is in the evidence store: %v", spy.readFile)
		}
	}
	var opaque bool
	for _, p := range spy.readOpaque {
		if p == "/etc/shadow" {
			opaque = true
		}
	}
	if !opaque {
		t.Errorf("the link was not followed at all; that is safe and puts Debian back where it was: opaque=%v", spy.readOpaque)
	}
}

// TestADanglingLinkIsNotAnUnreadableFile. `sysctl --system` skips a drop-in
// pointing at nothing, and so does this: a link to a file that does not exist
// configures nothing, so there is no gap for a check to be missing. Recording
// it as unreadable would turn a tidy-up somebody forgot into an UNKNOWN on
// every check that reads the configuration.
func TestADanglingLinkIsNotAnUnreadableFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/sysctl.d/50-dangling.conf": "placeholder\n",
		"etc/sysctl.conf":               "kernel.kptr_restrict = 1\n",
		"_plumbline/fixture.json": `{"description":"a drop-in pointing at nothing",
			"symlinks":{"/etc/sysctl.d/50-dangling.conf":"/etc/sysctl.d/gone.conf"}}`,
	})

	sc := collectRoot(t, root)
	if len(sc.UnreadableFiles) != 0 {
		t.Errorf("a dangling link was recorded as unreadable: %+v", sc.UnreadableFiles)
	}
	if _, ok := sc.ResolvedFrom("/etc/sysctl.d/50-dangling.conf"); ok {
		t.Error("a dangling link was recorded as resolved")
	}
	// The rest of the configuration is unaffected.
	if _, found := sc.EffectiveConfigured("kernel.kptr_restrict"); !found {
		t.Error("a dangling link stopped the other files being read")
	}
}

// TestALinkChainIsBounded. A loop, or a chain long enough to look like one, is
// recorded and abandoned rather than followed — the same cap
// internal/collect/unit applies, for the same reason.
func TestALinkChainIsBounded(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/sysctl.d/50-loop.conf": "placeholder\n",
		"etc/sysctl.d/51-loop.conf": "placeholder\n",
		"_plumbline/fixture.json": `{"description":"two links pointing at each other",
			"symlinks":{
				"/etc/sysctl.d/50-loop.conf":"/etc/sysctl.d/51-loop.conf",
				"/etc/sysctl.d/51-loop.conf":"/etc/sysctl.d/50-loop.conf"}}`,
	})

	sc := collectRoot(t, root)
	if len(sc.UnreadableFiles) == 0 {
		t.Fatal("a symlink loop was followed or silently dropped; it must be recorded")
	}
	var said bool
	for _, f := range sc.UnreadableFiles {
		if strings.Contains(f.Msg, "too long to follow") {
			said = true
		}
	}
	if !said {
		t.Errorf("the loop is not described as one: %+v", sc.UnreadableFiles)
	}
}

// configReadSpy records which door each read went through.
type configReadSpy struct {
	*fake.System
	readFile   []string
	readOpaque []string
}

func (s *configReadSpy) ReadFile(p string, max int64) (system.ReadResult, error) {
	s.readFile = append(s.readFile, p)
	return s.System.ReadFile(p, max)
}

func (s *configReadSpy) ReadOpaque(p string, max int64) (system.ReadResult, error) {
	s.readOpaque = append(s.readOpaque, p)
	return s.System.ReadOpaque(p, max)
}

func collectRoot(t *testing.T, root string) fact.Sysctl {
	t.Helper()
	sys, err := fake.New(root)
	if err != nil {
		t.Fatalf("load %s: %v", root, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatal(err)
	}
	sc, _, ok := fact.Get[fact.Sysctl](facts, fact.SysctlID)
	if !ok {
		t.Fatal("kernel.sysctl missing after collection")
	}
	return sc
}

// TestResolutionSurvivesTheBundle. Sysctl.Resolved is what stops a finding
// citing a symlink from sending an operator to open one, and it is only useful
// if it is still there when the bundle is re-evaluated months later.
func TestResolutionSurvivesTheBundle(t *testing.T) {
	sc := collectFixture(t, "kernel-symlinked-config")

	blob, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	var back fact.Sysctl
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}

	target, ok := back.ResolvedFrom("/etc/sysctl.d/99-sysctl.conf")
	if !ok || target != "/etc/sysctl.conf" {
		t.Errorf("resolution lost across the bundle: %q/%v", target, ok)
	}

	// A fact with no links at all omits the map rather than carrying an empty
	// one, so absence reads as "nothing was a link" rather than as a field
	// somebody forgot to populate.
	plain, err := json.Marshal(collectFixture(t, "kernel-hardened"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), `"resolved"`) {
		t.Errorf("a fact with no symlinks carries an empty resolved map: %s", plain)
	}
}

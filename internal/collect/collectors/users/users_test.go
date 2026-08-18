package users_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/users"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collectFixture(t *testing.T, name string) *fact.Set {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	return facts
}

func TestCollectorContract(t *testing.T) {
	c := collector.New()
	if got, want := c.ID(), "users"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	want := []fact.ID{fact.PasswdID, fact.ShadowID, fact.GroupID}
	got := c.Produces()
	if len(got) != len(want) {
		t.Fatalf("Produces = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Produces = %v, want %v", got, want)
		}
	}
	if c.Cost() != collect.Cheap {
		t.Errorf("Cost = %v, want cheap", c.Cost())
	}
	// CapNone is load-bearing here: CapRoot would make an unprivileged scan
	// skip the collector outright and report all three facts as never
	// collected, including the two it could have read perfectly well.
	if c.Requires() != collect.CapNone {
		t.Errorf("Requires = %v, want none", c.Requires())
	}
	if c.Timeout() <= 0 || c.Timeout() > time.Minute {
		t.Errorf("Timeout = %v", c.Timeout())
	}
	if _, ok := collect.Default().Get("users"); !ok {
		t.Errorf("the users collector did not register itself: %v", collect.Default().IDs())
	}
}

// TestShadowDenialDoesNotStopTheOthers is the collector's central property.
func TestShadowDenialDoesNotStopTheOthers(t *testing.T) {
	facts := collectFixture(t, "users-unprivileged")

	p, ferr, ok := fact.Get[fact.Passwd](facts, fact.PasswdID)
	if !ok {
		t.Fatalf("users.passwd missing (err=%v); the collector failed as a unit", ferr)
	}
	if len(p.Entries) == 0 {
		t.Error("users.passwd was recorded but parsed no accounts")
	}
	if _, _, ok := fact.Get[fact.Group](facts, fact.GroupID); !ok {
		t.Error("users.group missing")
	}

	e, bad := facts.Err(fact.ShadowID)
	if !bad {
		t.Fatal("users.shadow was not recorded as an error")
	}
	if e.Kind != fact.ErrPermission || e.Path != "/etc/shadow" {
		t.Errorf("shadow error = %+v, want permission on /etc/shadow", e)
	}
	// The message has to be actionable: an operator reading it should know
	// what to do differently.
	if !strings.Contains(e.Msg, "root") {
		t.Errorf("shadow error message does not say how to fix it: %q", e.Msg)
	}
}

// TestCredentialFilesAreNeverStoredAsEvidence is a security property of the
// seam. A bundle travels; a password hash inside one is a credential in a form
// an attacker can work on offline.
func TestCredentialFilesAreNeverStoredAsEvidence(t *testing.T) {
	for _, path := range []string{"/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"} {
		if !collect.IsCredentialFile(path) {
			t.Errorf("%s is not excluded from the evidence store", path)
		}
	}
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/ssh/sshd_config"} {
		if collect.IsCredentialFile(path) {
			t.Errorf("%s is excluded from the evidence store but should not be", path)
		}
	}

	// End to end through the runner, which is where the exclusion is wired.
	sys, err := fake.New(filepath.Join(fixtureRoot, "users-clean"))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner := collect.Runner{
		Registry: registryWith(t, collector.New()),
		Evidence: rec,
	}
	facts := fact.NewSet()
	if err := runner.Run(context.Background(), sys, facts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(rec.stored) == 0 {
		t.Fatal("nothing was recorded as evidence; the test is not exercising the recorder")
	}
	for _, blob := range rec.stored {
		if strings.Contains(blob, "$6$") || strings.Contains(blob, "$y$") {
			t.Errorf("a password hash reached the evidence store:\n%s", blob)
		}
	}
	// /etc/passwd is not a credential file and must still be stored, or the
	// exclusion has been applied too widely.
	var sawPasswd bool
	for _, blob := range rec.stored {
		if strings.Contains(blob, "root:x:0:0:") {
			sawPasswd = true
		}
	}
	if !sawPasswd {
		t.Error("/etc/passwd was not stored as evidence; findings citing it would have no source")
	}
}

// TestShadowFactCarriesNoHashMaterial: the exclusion above stops the bytes
// reaching the bundle through evidence; this stops them reaching it through
// the fact.
func TestShadowFactCarriesNoHashMaterial(t *testing.T) {
	facts := collectFixture(t, "users-clean")
	s, _, ok := fact.Get[fact.Shadow](facts, fact.ShadowID)
	if !ok {
		t.Fatal("users.shadow missing")
	}
	for _, e := range s.Entries {
		if strings.Contains(string(e.Algorithm), "$") {
			t.Errorf("%s: algorithm field carries hash syntax: %q", e.Name, e.Algorithm)
		}
	}
	root, _ := s.Entry("root")
	if root.Algorithm != fact.HashSHA512 || root.Locked || root.Empty {
		t.Errorf("root = %+v, want sha512, unlocked, non-empty", root)
	}
	alice, _ := s.Entry("alice")
	if alice.Algorithm != fact.HashYescrypt {
		t.Errorf("alice algorithm = %q, want yescrypt", alice.Algorithm)
	}
	daemon, _ := s.Entry("daemon")
	if !daemon.Locked || daemon.Algorithm != fact.HashNone {
		t.Errorf("daemon = %+v, want locked with no algorithm", daemon)
	}
}

// TestAlgorithmFor covers the crypt(3) formats a real host produces. It is a
// table over the classifier rather than over fixtures because the interesting
// input space is password-field syntax, not filesystem layout.
func TestAlgorithmFor(t *testing.T) {
	for _, tc := range []struct {
		field  string
		alg    fact.HashAlgorithm
		locked bool
		empty  bool
	}{
		{field: "", empty: true},
		{field: "*", alg: fact.HashNone, locked: true},
		{field: "!", alg: fact.HashNone, locked: true},
		{field: "!!", alg: fact.HashNone, locked: true},
		{field: "*LK*", alg: fact.HashNone, locked: true},
		{field: "ab0123456789x", alg: fact.HashDES},
		{field: "$1$salt$hash", alg: fact.HashMD5},
		{field: "$5$salt$hash", alg: fact.HashSHA256},
		{field: "$6$salt$hash", alg: fact.HashSHA512},
		{field: "$6$rounds=656000$salt$hash", alg: fact.HashSHA512},
		{field: "$y$j9T$salt$hash", alg: fact.HashYescrypt},
		{field: "$gy$j9T$salt$hash", alg: fact.HashGostYescrypt},
		{field: "$7$salt$hash", alg: fact.HashScrypt},
		{field: "$2b$12$salt", alg: fact.HashBcryptA},
		{field: "$2y$12$salt", alg: fact.HashBcryptA},
		// A lock applied over a real hash: the account cannot authenticate,
		// and the scheme underneath is still what it will use when unlocked.
		{field: "!$6$salt$hash", alg: fact.HashSHA512, locked: true},
		{field: "!!$1$salt$hash", alg: fact.HashMD5, locked: true},
		// Unrecognised is neither weak nor strong, and must not be guessed.
		{field: "$99$salt$hash", alg: fact.HashUnknown},
		{field: "x", alg: fact.HashUnknown},
	} {
		t.Run(tc.field, func(t *testing.T) {
			alg, locked, empty := fact.AlgorithmFor(tc.field)
			if alg != tc.alg || locked != tc.locked || empty != tc.empty {
				t.Errorf("AlgorithmFor(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tc.field, alg, locked, empty, tc.alg, tc.locked, tc.empty)
			}
			if tc.alg == fact.HashUnknown && (alg.Weak() || alg.Strong()) {
				t.Errorf("an unrecognised scheme was classified as weak or strong")
			}
		})
	}
}

// TestMalformedLinesAreRecordedNotDropped: a line we could not parse is a line
// that could have held the account a negative assertion claims is absent.
func TestMalformedLinesAreRecordedNotDropped(t *testing.T) {
	facts := collectFixture(t, "users-malformed")

	p, _, _ := fact.Get[fact.Passwd](facts, fact.PasswdID)
	if len(p.Malformed) != 2 {
		t.Errorf("passwd malformed lines = %v, want 2 (the colon-free line and the non-numeric uid)", p.Malformed)
	}
	// The lines that did parse are still recorded.
	if len(p.Entries) != 3 {
		t.Errorf("passwd entries = %d, want 3", len(p.Entries))
	}

	s, _, _ := fact.Get[fact.Shadow](facts, fact.ShadowID)
	if len(s.Malformed) != 1 {
		t.Errorf("shadow malformed lines = %v, want 1", s.Malformed)
	}
}

// TestCompatEntriesAreNotAccounts: a "+" line imports accounts, it is not one.
func TestCompatEntriesAreNotAccounts(t *testing.T) {
	facts := collectFixture(t, "users-nis")
	p, _, _ := fact.Get[fact.Passwd](facts, fact.PasswdID)

	if len(p.CompatEntries) != 2 {
		t.Fatalf("compat entries = %+v, want 2", p.CompatEntries)
	}
	for _, e := range p.Entries {
		if strings.HasPrefix(e.Name, "+") || strings.HasPrefix(e.Name, "-") {
			t.Errorf("a compatibility line was parsed as an account: %+v", e)
		}
	}
	if len(p.Entries) != 3 {
		t.Errorf("passwd entries = %d, want 3 real accounts", len(p.Entries))
	}
}

// TestMissingDatabaseIsAnError: a Linux host without /etc/passwd is not a host
// with no accounts, and the two must not look alike.
func TestMissingDatabaseIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	sys, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("Collect returned an error: %v", err)
	}
	for _, id := range []fact.ID{fact.PasswdID, fact.ShadowID, fact.GroupID} {
		e, bad := facts.Err(id)
		if !bad {
			t.Errorf("%s was not recorded as an error when the file was absent", id)
			continue
		}
		if e.Path == "" {
			t.Errorf("%s error names no path: %+v", id, e)
		}
	}
}

// recorder captures what the runner stores as evidence.
type recorder struct{ stored []string }

func (r *recorder) Add(data []byte) string {
	r.stored = append(r.stored, string(data))
	return "sha-" + string(rune('a'+len(r.stored)))
}
func (r *recorder) MarkTruncated(string) {}

// registryWith builds a registry holding just the collector under test, so the
// evidence assertion is not diluted by whatever else is registered.
func registryWith(t *testing.T, c collect.Collector) *collect.Registry {
	t.Helper()
	reg := collect.NewRegistry()
	reg.Register(c)
	return reg
}

package bundle_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
)

var (
	created  = time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	started  = time.Date(2026, 3, 14, 9, 26, 51, 0, time.UTC)
	finished = time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
)

// sshdConfig is a realistic fact: an include that resolved, a Match-scoped
// directive, and an include that did not resolve. Anything that survives this
// survives a real collection.
func sshdConfig() fact.SSHDConfig {
	return fact.SSHDConfig{
		Installed: true,
		Files: []string{
			"/etc/ssh/sshd_config",
			"/etc/ssh/sshd_config.d/50-cloud-init.conf",
		},
		Directives: []fact.Directive{
			{Keyword: "PermitRootLogin", Value: "no", File: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Line: 1},
			{Keyword: "Port", Value: "22", File: "/etc/ssh/sshd_config", Line: 2},
			{
				Keyword:       "PermitRootLogin",
				Value:         "yes",
				File:          "/etc/ssh/sshd_config",
				Line:          9,
				InMatch:       true,
				MatchCriteria: "Address 10.0.0.0/8",
			},
		},
		UnresolvedIncludes: []string{"/etc/ssh/sshd_config.d/*.conf"},
	}
}

// testSet is the acceptance criterion's fact set: one sshd.config, one error.
func testSet() *fact.Set {
	s := fact.NewSet()
	s.Put(sshdConfig())
	s.PutError(fact.Error{
		Fact: fact.ID("kernel.params"),
		Kind: fact.ErrPermission,
		Msg:  "open /proc/cmdline: permission denied",
		Path: "/proc/cmdline",
	})
	return s
}

func testBundle(s *fact.Set) bundle.Bundle {
	return bundle.Bundle{
		Manifest: bundle.Manifest{
			BundleID:       "0123456789abcdef0123456789abcdef",
			Tool:           bundle.Tool{Version: "0.1.0"},
			CatalogVersion: 1,
			Created:        created,
			Scan: bundle.Scan{
				Root:     "",
				EUID:     0,
				Started:  started,
				Finished: finished,
				Profile:  "default",
			},
		},
		Meta: bundle.Meta{
			Hostname:  "audit-host",
			OSRelease: "debian 12 (bookworm)",
			Kernel:    "6.1.0-18-amd64",
			Arch:      "amd64",
		},
		Facts: s,
	}
}

func write(t *testing.T, b bundle.Bundle) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := bundle.Write(&buf, b); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func read(t *testing.T, raw []byte) bundle.Bundle {
	t.Helper()
	b, err := bundle.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return b
}

// TestRoundTrip is the acceptance criterion: a fact set with sshd.config and a
// fact error survives a write and a read unchanged.
func TestRoundTrip(t *testing.T) {
	src := testSet()
	got := read(t, write(t, testBundle(src)))

	if !reflect.DeepEqual(src, got.Facts) {
		t.Errorf("fact set changed across the round trip:\n want %#v\n  got %#v", src, got.Facts)
	}

	// The typed read still works, which is what a check will actually do.
	cfg, ferr, ok := fact.Get[fact.SSHDConfig](got.Facts, fact.SSHDConfigID)
	if !ok {
		t.Fatalf("sshd.config not readable after round trip: err=%v", ferr)
	}
	if !reflect.DeepEqual(cfg, sshdConfig()) {
		t.Errorf("sshd.config changed:\n want %#v\n  got %#v", sshdConfig(), cfg)
	}
	d, found := cfg.Effective("PermitRootLogin")
	if !found || d.Value != "no" || d.Line != 1 {
		t.Errorf("effective directive wrong after round trip: %+v (found=%v)", d, found)
	}

	// The error survives with its kind intact: a bundle that loses why a fact
	// is missing cannot explain the gap later, which is the whole reason
	// errors are stored rather than dropped.
	fe, bad := got.Facts.Err(fact.ID("kernel.params"))
	if !bad {
		t.Fatal("fact error lost across the round trip")
	}
	if fe.Kind != fact.ErrPermission || fe.Path != "/proc/cmdline" {
		t.Errorf("fact error changed: %+v", fe)
	}
}

// TestRoundTripManifest asserts the index describes the archive, and that what
// the caller supplied comes back as supplied.
func TestRoundTripManifest(t *testing.T) {
	src := testBundle(testSet())
	got := read(t, write(t, src))

	if got.Manifest.Schema != bundle.Schema {
		t.Errorf("schema = %q, want %q", got.Manifest.Schema, bundle.Schema)
	}
	if got.Manifest.Tool.Name != "plumbline" || got.Manifest.Tool.Version != "0.1.0" {
		t.Errorf("tool = %+v", got.Manifest.Tool)
	}
	if got.Manifest.BundleID != src.Manifest.BundleID {
		t.Errorf("bundle_id = %q, want %q", got.Manifest.BundleID, src.Manifest.BundleID)
	}
	if got.Manifest.CatalogVersion != 1 {
		t.Errorf("catalog_version = %d, want 1", got.Manifest.CatalogVersion)
	}
	if !got.Manifest.Created.Equal(created) {
		t.Errorf("created = %s, want %s", got.Manifest.Created, created)
	}
	if got.Manifest.Scan != src.Manifest.Scan {
		t.Errorf("scan = %+v, want %+v", got.Manifest.Scan, src.Manifest.Scan)
	}
	if got.Meta != src.Meta {
		t.Errorf("meta = %+v, want %+v", got.Meta, src.Meta)
	}
	if got.Manifest.Integrity != (bundle.Integrity{Member: "integrity.json", Algorithm: "sha256"}) {
		t.Errorf("integrity descriptor = %+v", got.Manifest.Integrity)
	}
	if len(got.Manifest.Facts) != 1 {
		t.Fatalf("fact index has %d entries, want 1", len(got.Manifest.Facts))
	}
	ref := got.Manifest.Facts[0]
	if ref.ID != fact.SSHDConfigID || ref.FactVersion != 1 || ref.Member != "facts/sshd.config.json" {
		t.Errorf("fact index entry = %+v", ref)
	}
	if len(ref.SHA256) != 64 {
		t.Errorf("fact index digest is not a sha256: %q", ref.SHA256)
	}

	// Writing what was read reproduces what was read. A bundle that drifts on
	// re-serialisation is not an archival format.
	again := read(t, write(t, got))
	if !reflect.DeepEqual(got, again) {
		t.Errorf("bundle changed on the second round trip:\n first %#v\n again %#v", got, again)
	}
}

// TestMembersAndLayout asserts the archive is laid out as DATA-MODEL §6 says,
// with integrity.json last because it digests everything before it.
func TestMembersAndLayout(t *testing.T) {
	names := memberNames(t, write(t, testBundle(testSet())))
	want := []string{
		"manifest.json",
		"meta.json",
		"facts/sshd.config.json",
		"errors.json",
		"integrity.json",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("members = %v, want %v", names, want)
	}
}

// TestTamperedMemberFailsIntegrity is the acceptance criterion: changing a
// byte of any member makes Read fail with a typed integrity error rather than
// a warning or a best-effort parse.
func TestTamperedMemberFailsIntegrity(t *testing.T) {
	for _, target := range []string{"facts/sshd.config.json", "manifest.json", "meta.json", "errors.json"} {
		t.Run(target, func(t *testing.T) {
			raw := tamper(t, write(t, testBundle(testSet())), target, func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[len(out)/2] ^= 0x01 // one bit, same length
				return out
			})

			_, err := bundle.Read(bytes.NewReader(raw))
			if err == nil {
				t.Fatal("Read accepted a tampered bundle")
			}
			var ie *bundle.IntegrityError
			if !errors.As(err, &ie) {
				t.Fatalf("error is %T (%v), want *bundle.IntegrityError", err, err)
			}
			if ie.Member != target {
				t.Errorf("integrity error names %q, want %q", ie.Member, target)
			}
			if ie.Want == "" || ie.Got == "" || ie.Want == ie.Got {
				t.Errorf("integrity error does not report both digests: %+v", ie)
			}
		})
	}
}

// TestTruncatedIntegrityMemberIsRejected covers the other direction: removing
// integrity.json must not read as "nothing to verify".
func TestTruncatedIntegrityMemberIsRejected(t *testing.T) {
	raw := drop(t, write(t, testBundle(testSet())), "integrity.json")
	_, err := bundle.Read(bytes.NewReader(raw))
	if !errors.Is(err, bundle.ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

// TestRemovedMemberFailsIntegrity: a member integrity.json vouches for that is
// no longer in the archive is a failure, not an absence.
func TestRemovedMemberFailsIntegrity(t *testing.T) {
	raw := drop(t, write(t, testBundle(testSet())), "meta.json")
	_, err := bundle.Read(bytes.NewReader(raw))
	var ie *bundle.IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("error is %T (%v), want *bundle.IntegrityError", err, err)
	}
	if ie.Member != "meta.json" || ie.Got != "" {
		t.Errorf("integrity error = %+v, want meta.json absent", ie)
	}
}

// futureFact stands in for a fact written by a later binary: this build has
// never heard of the ID.
type futureFact struct {
	Ring    int      `json:"ring"`
	Modules []string `json:"modules"`
	Tainted bool     `json:"tainted"`
}

func (futureFact) FactID() fact.ID  { return fact.ID("future.kernel.fact") }
func (futureFact) FactVersion() int { return 3 }

// TestUnknownFactIDIsPreserved is the acceptance criterion for forward
// compatibility: an old binary opens a newer bundle, and the fact it cannot
// type is kept verbatim instead of being dropped or guessed at.
func TestUnknownFactIDIsPreserved(t *testing.T) {
	src := fact.NewSet()
	src.Put(sshdConfig())
	src.Put(futureFact{Ring: 0, Modules: []string{"kvm", "nf_tables"}, Tainted: true})

	got := read(t, write(t, testBundle(src)))

	// The bundle opened, and the fact this build understands is unaffected by
	// the one it does not.
	if _, _, ok := fact.Get[fact.SSHDConfig](got.Facts, fact.SSHDConfigID); !ok {
		t.Error("a known fact was lost because an unknown one was present")
	}

	u, ferr, ok := fact.Get[bundle.UnknownFact](got.Facts, fact.ID("future.kernel.fact"))
	if !ok {
		t.Fatalf("unknown fact not preserved: err=%v", ferr)
	}
	if u.Version != 3 {
		t.Errorf("fact_version = %d, want 3", u.Version)
	}

	// Preserved as raw JSON: the bytes still say what the writer wrote.
	var back futureFact
	if err := json.Unmarshal(u.Raw, &back); err != nil {
		t.Fatalf("preserved bytes are not the fact's JSON: %v (%s)", err, u.Raw)
	}
	if !reflect.DeepEqual(back, futureFact{Ring: 0, Modules: []string{"kvm", "nf_tables"}, Tainted: true}) {
		t.Errorf("preserved fact changed: %+v", back)
	}

	// It is not typed as the fact it names, so no check can read it as one:
	// preserving the bytes must not become a back door to interpreting them.
	if _, _, ok := fact.Get[futureFact](got.Facts, fact.ID("future.kernel.fact")); ok {
		t.Error("an unrecognised fact was handed out as a typed fact")
	}

	// And it survives being written again, so a bundle does not decay by
	// passing through a binary that predates part of it.
	relayed := read(t, write(t, got))
	u2, _, ok := fact.Get[bundle.UnknownFact](relayed.Facts, fact.ID("future.kernel.fact"))
	if !ok {
		t.Fatal("unknown fact lost when the bundle was rewritten")
	}
	if !bytes.Equal(u.Raw, u2.Raw) {
		t.Errorf("preserved bytes changed on rewrite:\n first %s\n again %s", u.Raw, u2.Raw)
	}
}

// futureSSHD is a registered fact ID at a fact_version this build does not
// understand.
type futureSSHD struct {
	Installed bool   `json:"installed"`
	Something string `json:"something_new"`
}

func (futureSSHD) FactID() fact.ID  { return fact.SSHDConfigID }
func (futureSSHD) FactVersion() int { return 99 }

// TestUnknownFactVersionIsPreserved: a known ID at an unknown version is also
// kept opaque. Decoding it into today's struct would silently drop whatever
// the version bump was about, and a check reading the result would answer
// confidently from a structure it misunderstood (DATA-MODEL §2.2).
func TestUnknownFactVersionIsPreserved(t *testing.T) {
	src := fact.NewSet()
	src.Put(futureSSHD{Installed: true, Something: "a field this build has never seen"})

	got := read(t, write(t, testBundle(src)))

	if _, _, ok := fact.Get[fact.SSHDConfig](got.Facts, fact.SSHDConfigID); ok {
		t.Fatal("a fact at an unknown version was decoded into the current struct")
	}
	u, _, ok := fact.Get[bundle.UnknownFact](got.Facts, fact.SSHDConfigID)
	if !ok {
		t.Fatal("a fact at an unknown version was dropped instead of preserved")
	}
	if u.Version != 99 {
		t.Errorf("fact_version = %d, want 99", u.Version)
	}
	if !bytes.Contains(u.Raw, []byte("something_new")) {
		t.Errorf("preserved bytes lost the unrecognised field: %s", u.Raw)
	}
}

// TestWriteRejectsInvalidManifest guards the manifest schema's own
// constraints, so an unusable bundle is never produced in the first place.
func TestWriteRejectsInvalidManifest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bundle.Bundle)
	}{
		{"no bundle_id", func(b *bundle.Bundle) { b.Manifest.BundleID = "" }},
		{"bundle_id not hex", func(b *bundle.Bundle) { b.Manifest.BundleID = "ZZZ456789abcdef0123456789abcdef0" }},
		{"bundle_id wrong length", func(b *bundle.Bundle) { b.Manifest.BundleID = "abc" }},
		{"catalog_version below minimum", func(b *bundle.Bundle) { b.Manifest.CatalogVersion = 0 }},
		{"no fact set", func(b *bundle.Bundle) { b.Facts = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := testBundle(testSet())
			tc.mutate(&b)
			if err := bundle.Write(io.Discard, b); err == nil {
				t.Error("Write accepted an invalid bundle")
			}
		})
	}
}

// TestEmptyFactSet: a collection that produced nothing still writes a readable
// bundle. A scan that found nothing and a scan that failed to write must not
// look the same on disk.
func TestEmptyFactSet(t *testing.T) {
	got := read(t, write(t, testBundle(fact.NewSet())))
	if len(got.Facts.IDs()) != 0 || len(got.Facts.Errors()) != 0 {
		t.Errorf("empty bundle came back with %d facts and %d errors",
			len(got.Facts.IDs()), len(got.Facts.Errors()))
	}
	if got.Manifest.Facts == nil {
		t.Error("fact index is null; it must be an empty array")
	}
}

// --- archive helpers -------------------------------------------------------
//
// These rebuild the archive around one changed member, which is how a bundle
// would be edited in transit. They deliberately do not use anything unexported
// from the package under test.

func members(t *testing.T, raw []byte) ([]string, map[string][]byte) {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer zr.Close()

	var order []string
	out := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			t.Fatalf("tar member %s: %v", hdr.Name, err)
		}
		order = append(order, hdr.Name)
		out[hdr.Name] = buf.Bytes()
	}
	return order, out
}

func memberNames(t *testing.T, raw []byte) []string {
	t.Helper()
	order, _ := members(t, raw)
	return order
}

func rebuild(t *testing.T, order []string, data map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	tw := tar.NewWriter(zw)
	for _, name := range order {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(data[name])),
			ModTime:  created,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("header %s: %v", name, err)
		}
		if _, err := tw.Write(data[name]); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zstd: %v", err)
	}
	return buf.Bytes()
}

// tamper rewrites one member's bytes, leaving integrity.json as written.
func tamper(t *testing.T, raw []byte, name string, mutate func([]byte) []byte) []byte {
	t.Helper()
	order, data := members(t, raw)
	if _, ok := data[name]; !ok {
		t.Fatalf("no member %q to tamper with", name)
	}
	data[name] = mutate(data[name])
	return rebuild(t, order, data)
}

// drop removes a member entirely.
func drop(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	order, data := members(t, raw)
	kept := make([]string, 0, len(order))
	for _, n := range order {
		if n != name {
			kept = append(kept, n)
		}
	}
	if len(kept) == len(order) {
		t.Fatalf("no member %q to drop", name)
	}
	delete(data, name)
	return rebuild(t, kept, data)
}

// TestRoundTripWalkerFacts covers the fs.* namespace, whose IDs are not in the
// decoder registry because there is one per walker interest. A fact that reads
// back untyped is a fact every filesystem check resolves to UNKNOWN over, and
// re-evaluating an old bundle is the whole reason bundles exist.
func TestRoundTripWalkerFacts(t *testing.T) {
	src := fact.NewSet()
	src.Put(fact.FSMatches{
		Interest: "suid",
		Roots:    []string{"/"},
		Rows: []fact.FSRow{
			{Path: "/usr/bin/passwd", Mode: 0o755 | fs.ModeSetuid, UID: 0, GID: 0, Size: 63960, IsRegular: true},
		},
		InodesVisited: 4211,
	})
	src.Put(fact.FSMatches{
		Interest:          "world_writable",
		Roots:             []string{"/"},
		Rows:              []fact.FSRow{{Path: "/var/tmp/scratch", Mode: 0o666, UID: 1000, GID: 1000, IsRegular: true}},
		Truncated:         true,
		TruncationReasons: []fact.TruncationReason{fact.TruncDeadline},
		Overflow:          17,
		InodesVisited:     4211,
	})

	got := read(t, write(t, testBundle(src)))
	if !reflect.DeepEqual(src, got.Facts) {
		t.Errorf("walker facts changed across the round trip:\n want %#v\n  got %#v", src, got.Facts)
	}

	suid, ferr, ok := fact.Get[fact.FSMatches](got.Facts, fact.FSFactID("suid"))
	if !ok {
		t.Fatalf("fs.suid did not decode to fact.FSMatches after a round trip: err=%v", ferr)
	}
	if len(suid.Rows) != 1 || suid.Rows[0].Path != "/usr/bin/passwd" {
		t.Errorf("fs.suid rows changed: %+v", suid.Rows)
	}
	if suid.Rows[0].Mode&fs.ModeSetuid == 0 {
		t.Errorf("the setuid bit did not survive the round trip: %v", suid.Rows[0].Mode)
	}
	if !suid.Complete() {
		t.Errorf("fs.suid gained a truncation marker across the round trip: %v", suid.TruncationReasons)
	}

	// The truncation marker is the field a check's verdict depends on, so it
	// matters most that it survives.
	ww, _, ok := fact.Get[fact.FSMatches](got.Facts, fact.FSFactID("world_writable"))
	if !ok {
		t.Fatalf("fs.world_writable did not decode")
	}
	if ww.Complete() {
		t.Errorf("a truncated fact came back claiming completeness; every negative assertion over it would flip from UNKNOWN to PASS")
	}
	if got, want := ww.Overflow, 17; got != want {
		t.Errorf("overflow = %d, want %d", got, want)
	}
	if len(ww.TruncationReasons) != 1 || ww.TruncationReasons[0] != fact.TruncDeadline {
		t.Errorf("truncation reasons = %v, want [%s]", ww.TruncationReasons, fact.TruncDeadline)
	}
}

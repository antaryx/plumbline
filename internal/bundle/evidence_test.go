package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loginDefs stands in for a file several checks cite. Two checks citing one
// file is the ordinary case, not the edge case: /etc/login.defs alone answers
// questions for password ageing, umask and uid ranges.
var loginDefs = []byte("UMASK 022\nPASS_MAX_DAYS 99999\nUID_MIN 1000\n")

// TestEvidenceIsDeduplicated is the acceptance criterion: two checks citing
// one file produce one blob.
//
// Deduplication is not bookkeeping here — it falls out of addressing content
// by its digest. Two citations of the same bytes are the same key, so the
// second store is a no-op and both findings point at one blob.
func TestEvidenceIsDeduplicated(t *testing.T) {
	store := bundle.NewEvidenceStore()

	// Two checks, citing the same file, through two separate reads: the
	// second read gets its own byte slice, as a real second collector would.
	first := store.Add(loginDefs)
	second := store.Add(append([]byte(nil), loginDefs...))

	if first != second {
		t.Fatalf("identical content produced two digests: %s and %s", first, second)
	}
	if got := store.Len(); got != 1 {
		t.Errorf("store holds %d blobs, want 1", got)
	}
	if got := store.TotalBytes(); got != len(loginDefs) {
		t.Errorf("store totals %d bytes, want %d", got, len(loginDefs))
	}

	// Different content is a different blob, or the store would be losing
	// evidence rather than sharing it.
	store.Add([]byte("Port 22\n"))
	if got := store.Len(); got != 2 {
		t.Fatalf("distinct content did not produce a second blob: %d", got)
	}

	// And the archive carries exactly what the store holds.
	b := testBundle(testSet())
	b.Evidence = store
	names := memberNames(t, write(t, b))

	var blobs []string
	for _, n := range names {
		if strings.HasPrefix(n, "evidence/") {
			blobs = append(blobs, n)
		}
	}
	if len(blobs) != 2 {
		t.Fatalf("archive holds %d evidence members, want 2: %v", len(blobs), names)
	}
	want := "evidence/" + sha(loginDefs) + ".blob"
	if blobs[0] != want && blobs[1] != want {
		t.Errorf("no member named for the content digest; got %v, want one of them to be %s", blobs, want)
	}
}

// TestEvidenceRoundTrip: the blobs come back byte-identical, and the manifest
// summary matches what the archive actually holds.
func TestEvidenceRoundTrip(t *testing.T) {
	store := bundle.NewEvidenceStore()
	sum := store.Add(loginDefs)
	store.Add([]byte("Port 22\n"))
	store.MarkTruncated("/var/log/huge.log")

	b := testBundle(testSet())
	b.Evidence = store
	got := read(t, write(t, b))

	if got.Evidence == nil {
		t.Fatal("evidence store was lost across the round trip")
	}
	blob, ok := got.Evidence.Get(sum)
	if !ok {
		t.Fatalf("blob %s is missing after the round trip", sum)
	}
	if !bytes.Equal(blob, loginDefs) {
		t.Errorf("blob changed: %q", blob)
	}
	if idx := got.Manifest.Evidence; idx == nil {
		t.Error("manifest carries no evidence summary")
	} else if idx.Count != 2 || idx.TotalBytes != len(loginDefs)+len("Port 22\n") {
		t.Errorf("evidence summary = %+v", idx)
	}
	if want := []string{"/var/log/huge.log"}; !reflect.DeepEqual(got.Evidence.TruncatedSources(), want) {
		t.Errorf("truncated sources = %v, want %v", got.Evidence.TruncatedSources(), want)
	}
}

// TestFindingCitesAStoredBlob is the point of the whole store: a finding's
// SHA256 resolves to bytes an auditor can re-read, so a disputed excerpt can
// be checked against the source instead of being taken on trust.
func TestFindingCitesAStoredBlob(t *testing.T) {
	store := bundle.NewEvidenceStore()
	sum := store.Add(loginDefs)

	ev := finding.NewEvidence("/etc/login.defs", 1, "UMASK 022", sum)
	if ev.SHA256 != sum {
		t.Fatalf("evidence digest = %q, want %q", ev.SHA256, sum)
	}

	b := testBundle(testSet())
	b.Evidence = store
	got := read(t, write(t, b))

	blob, ok := got.Evidence.Get(ev.SHA256)
	if !ok {
		t.Fatal("a finding cites a digest the bundle does not contain")
	}
	if !strings.Contains(string(blob), ev.Excerpt) {
		t.Errorf("the excerpt is not in the source it claims to come from: %q not in %q", ev.Excerpt, blob)
	}
}

// TestTamperedBlobIsCaught: a blob is named for its own digest, so altering it
// contradicts its own name. That is checked independently of integrity.json —
// an archive can be internally consistent about the wrong content.
func TestTamperedBlobIsCaught(t *testing.T) {
	store := bundle.NewEvidenceStore()
	sum := store.Add(loginDefs)

	b := testBundle(testSet())
	b.Evidence = store
	member := "evidence/" + sum + ".blob"

	raw := tamper(t, write(t, b), member, func(in []byte) []byte {
		out := append([]byte(nil), in...)
		out[0] ^= 0x01
		return out
	})

	if _, err := bundle.Read(bytes.NewReader(raw)); err == nil {
		t.Fatal("Read accepted a blob that does not match its own digest")
	}
}

// TestBundleWithoutEvidence stays valid: not every scan keeps evidence, and a
// bundle that does not must not claim an empty store it never had.
func TestBundleWithoutEvidence(t *testing.T) {
	got := read(t, write(t, testBundle(testSet())))
	if got.Evidence != nil {
		t.Errorf("a bundle with no evidence came back with a store: %+v", got.Evidence)
	}
	if got.Manifest.Evidence != nil {
		t.Errorf("a bundle with no evidence carries an evidence summary: %+v", got.Manifest.Evidence)
	}
}

// TestEvidenceStoreIsConcurrencySafe: collectors run concurrently and all
// register into one store. A race here corrupts an audit rather than crashing,
// which is the worst way for a bug to behave.
func TestEvidenceStoreIsConcurrencySafe(t *testing.T) {
	store := bundle.NewEvidenceStore()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for k := 0; k < 50; k++ {
				store.Add(loginDefs)                // the same bytes
				store.Add([]byte{byte(i), byte(k)}) // and distinct ones
				store.MarkTruncated("/proc/self/mem")
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if _, ok := store.Get(sha(loginDefs)); !ok {
		t.Error("the shared blob is missing after concurrent writes")
	}
	if got := len(store.TruncatedSources()); got != 1 {
		t.Errorf("truncated sources = %d, want 1", got)
	}
}

// factSetIsUnaffected guards the obvious regression: adding evidence must not
// disturb the facts.
func TestFactsSurviveAlongsideEvidence(t *testing.T) {
	store := bundle.NewEvidenceStore()
	store.Add(loginDefs)

	src := testSet()
	b := testBundle(src)
	b.Evidence = store
	got := read(t, write(t, b))

	if !reflect.DeepEqual(src, got.Facts) {
		t.Error("facts changed when evidence was added to the bundle")
	}
	if _, _, ok := fact.Get[fact.SSHDConfig](got.Facts, fact.SSHDConfigID); !ok {
		t.Error("sshd.config is unreadable in a bundle carrying evidence")
	}
}

// Package bundle reads and writes the durable fact artifact: a zstd-compressed
// tar with the layout specified in docs/DATA-MODEL.md §6 and indexed by
// manifest.json, whose shape is normative in schema/bundle-v1.schema.json.
//
//	manifest.json          the index; schema, tool, catalog version, fact list
//	meta.json              host descriptors
//	facts/<id>.json        one member per fact, each carrying its fact_version
//	evidence/<sha>.blob    content-addressed raw sources, deduplicated
//	errors.json            every fact error
//	integrity.json         sha256 of every other member; written last
//
// Two asymmetries shape this package.
//
// Read support is forever and write support is current-only: a bundle is an
// archival artifact, and a bundle that cannot be reopened breaks the product's
// central promise. So Read is permissive about what it does not recognise —
// an unregistered fact ID is preserved as opaque bytes — and strict about what
// it cannot trust.
//
// A bundle handed to `plumbline eval` came from anywhere (docs/THREAT-MODEL.md
// T-09). Members are read into memory by name and never extracted to disk, the
// decompressed stream is capped, fact decoding is by registered ID into a typed
// struct, and an integrity mismatch is a typed error rather than a warning.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/antaryx/plumbline/internal/fact"
)

// Schema is the bundle schema this package writes. Readers accept older
// schemas forever; the writer only ever emits the current one.
const Schema = "bundle/v1"

// toolName is fixed by schema/bundle-v1.schema.json, which constrains
// tool.name to this constant.
const toolName = "plumbline"

// hashAlgorithm is the only algorithm integrity.json may name in v1.
const hashAlgorithm = "sha256"

// Member names. facts/<id>.json is derived; the rest are fixed.
const (
	manifestMember  = "manifest.json"
	metaMember      = "meta.json"
	errorsMember    = "errors.json"
	integrityMember = "integrity.json"
	factsPrefix     = "facts/"
	factsSuffix     = ".json"
	evidencePrefix  = "evidence/"
	evidenceSuffix  = ".blob"
)

// maxDecompressedBytes caps the decompressed archive. A bundle is untrusted
// input to a process that may be running as root, and zstd will happily expand
// a few kilobytes into a few terabytes. v0.1 bundles carry facts only; WP-09
// adds evidence blobs and should revisit this number deliberately rather than
// discovering it in production.
const maxDecompressedBytes int64 = 256 << 20

// ErrMalformed reports a bundle whose structure is wrong: a missing index, a
// member nothing points at, a fact member disagreeing with the manifest. It is
// deliberately distinct from IntegrityError, which means the bytes changed.
var ErrMalformed = errors.New("malformed bundle")

// ErrTooLarge reports a bundle that decompresses past maxDecompressedBytes.
var ErrTooLarge = errors.New("bundle exceeds the decompressed size cap")

// IntegrityError reports that a member's content does not match the digest
// recorded for it in integrity.json. Integrity is not authenticity: this type
// says the archive is internally inconsistent, never that it came — or did not
// come — from anyone in particular. Only a detached signature says that, and a
// renderer that conflates the two is repeating audit finding A-14.
type IntegrityError struct {
	Member string // the member at fault
	Want   string // digest recorded in integrity.json; empty if unrecorded
	Got    string // digest of the bytes actually present; empty if absent
}

func (e *IntegrityError) Error() string {
	switch {
	case e.Want == "":
		return fmt.Sprintf("bundle member %q is not recorded in %s", e.Member, integrityMember)
	case e.Got == "":
		return fmt.Sprintf("bundle member %q is recorded in %s but absent from the archive", e.Member, integrityMember)
	default:
		return fmt.Sprintf("bundle member %q fails integrity: recorded %s, computed %s", e.Member, e.Want, e.Got)
	}
}

// Bundle is one collection: its index, its host descriptors, and the facts and
// fact errors it carries.
type Bundle struct {
	Manifest Manifest
	Meta     Meta
	Facts    *fact.Set
	// Evidence holds the raw sources findings cite by digest. Nil means this
	// scan kept no evidence, which is different from a scan whose evidence was
	// lost: an empty store still writes an evidence summary saying so.
	Evidence *EvidenceStore
}

// Manifest is manifest.json. Fields and their requiredness come from
// schema/bundle-v1.schema.json, which sets additionalProperties:false — so
// this struct must never marshal a key the schema does not name. Optional
// fields that no work package produces yet (evidence, redaction, collector
// provenance, signing) are absent by design rather than reserved.
type Manifest struct {
	Schema         string    `json:"schema"`
	BundleID       string    `json:"bundle_id"`
	Tool           Tool      `json:"tool"`
	CatalogVersion int       `json:"catalog_version"`
	Created        time.Time `json:"created"`
	// Redacted records that --redact was used, so a reader can tell a bundle
	// with no hostname from a bundle whose host had no name. Redaction happens
	// at collection time, which is what makes a redacted bundle safe to attach
	// to a bug report.
	Redacted   bool   `json:"redacted,omitempty"`
	MetaMember string `json:"meta_member,omitempty"`
	Scan       Scan   `json:"scan"`
	// Facts indexes the facts/ members. Write derives it from the fact set;
	// anything a caller puts here is replaced, because the index describes the
	// archive rather than the caller's intent.
	Facts []FactRef `json:"facts"`
	// Evidence summarises the evidence/ members. Like Facts, Write derives it
	// from the store rather than trusting the caller.
	Evidence     *EvidenceIndex `json:"evidence,omitempty"`
	ErrorsMember string         `json:"errors_member,omitempty"`
	Integrity    Integrity      `json:"integrity"`
}

// Tool identifies the binary that wrote the bundle.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Scan records the conditions of the collection: where it looked, as whom, and
// for how long. It explains a gap that host state alone cannot.
type Scan struct {
	Root     string    `json:"root"`
	EUID     int       `json:"euid"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Profile  string    `json:"profile"`
}

// FactRef is one entry in the manifest's fact index.
type FactRef struct {
	ID          fact.ID `json:"id"`
	FactVersion int     `json:"fact_version"`
	Member      string  `json:"member"`
	SHA256      string  `json:"sha256"`
}

// Integrity is the manifest's pointer at integrity.json.
type Integrity struct {
	Member    string `json:"member"`
	Algorithm string `json:"algorithm"`
}

// Meta is meta.json: the host descriptors named by schema/bundle-v1.schema.json
// as "os-release, kernel, arch, hostname". Every field is optional because
// --redact (WP-12) drops the identifying ones, and because no collector
// produces them yet — a host collector will settle their structure.
type Meta struct {
	Hostname  string `json:"hostname,omitempty"`
	OSRelease string `json:"os_release,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

// factDoc is the on-disk form of a facts/<id>.json member. DATA-MODEL §6
// requires each fact member to carry its own fact_version, so the fact's own
// JSON sits under "data" rather than being merged with the envelope: merging
// would put the envelope's keys into the fact's namespace, where a future fact
// field could collide with them, and would make an unrecognised fact
// impossible to preserve byte-for-byte.
type factDoc struct {
	ID          fact.ID         `json:"id"`
	FactVersion int             `json:"fact_version"`
	Data        json.RawMessage `json:"data"`
}

// integrityDoc is integrity.json. It records every member except itself; a
// digest cannot cover the file it is written into.
type integrityDoc struct {
	Algorithm string            `json:"algorithm"`
	Members   map[string]string `json:"members"`
}

// UnknownFact preserves a fact this binary cannot type: either its ID is not
// registered, or its fact_version is not the one the registered type
// understands. The bytes are kept verbatim so the bundle survives the round
// trip, and no check can read it — which is the point. A check that required
// this fact resolves to UNKNOWN rather than to a best-effort read of a
// structure nobody here understands, and a best-effort read of a misunderstood
// structure is exactly how a false PASS is produced (DATA-MODEL §2.2).
type UnknownFact struct {
	ID      fact.ID
	Version int
	Raw     json.RawMessage
}

func (u UnknownFact) FactID() fact.ID  { return u.ID }
func (u UnknownFact) FactVersion() int { return u.Version }

// MarshalJSON returns the preserved bytes unaltered, so that writing a bundle
// that was read is a faithful copy rather than a re-interpretation.
func (u UnknownFact) MarshalJSON() ([]byte, error) {
	if len(u.Raw) == 0 {
		return []byte("null"), nil
	}
	return u.Raw, nil
}

// decoder builds a typed fact from a member's data. The registry is the whole
// of fact decoding: an ID that is not here is preserved opaquely, never
// guessed at.
type decoder struct {
	version int
	decode  func(json.RawMessage) (fact.Fact, error)
}

var registry = map[fact.ID]decoder{
	fact.RsyslogID: {
		version: fact.Rsyslog{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Rsyslog
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.JournaldID: {
		version: fact.Journald{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Journald
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.ServicesID: {
		version: fact.Services{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Services
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.CronID: {
		version: fact.Cron{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Cron
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.SysctlID: {
		version: fact.Sysctl{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Sysctl
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.PasswdID: {
		version: fact.Passwd{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Passwd
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.ShadowID: {
		version: fact.Shadow{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Shadow
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.GroupID: {
		version: fact.Group{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.Group
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
	fact.SSHDConfigID: {
		version: fact.SSHDConfig{}.FactVersion(),
		decode: func(raw json.RawMessage) (fact.Fact, error) {
			var f fact.SSHDConfig
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			return f, nil
		},
	},
}

// fsMatchesDecoder handles the fs.* namespace, whose IDs cannot be listed in
// the registry above because there is one per walker interest and the set is
// decided by which modules are compiled in. A bundle collected by a build that
// had a FILESYS interest the reader does not must still decode: the fact's
// shape is fixed by fact.FSMatches regardless of which interest produced it,
// and falling back to UnknownFact here would silently turn every filesystem
// check into UNKNOWN when an old bundle is re-evaluated — which is the product
// promise in DATA-MODEL.md §6.1 broken by an implementation detail.
var fsMatchesDecoder = decoder{
	version: fact.FSMatches{}.FactVersion(),
	decode: func(raw json.RawMessage) (fact.Fact, error) {
		var f fact.FSMatches
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		return f, nil
	},
}

// decoderFor resolves a fact ID to its decoder. Exact registrations win; the
// fs.* namespace is matched by prefix. An ID matching neither is preserved
// opaquely, never guessed at.
func decoderFor(id fact.ID) (decoder, bool) {
	if d, ok := registry[id]; ok {
		return d, true
	}
	if strings.HasPrefix(string(id), fact.FSFactPrefix) && len(id) > len(fact.FSFactPrefix) {
		return fsMatchesDecoder, true
	}
	return decoder{}, false
}

// member is one tar entry held in memory, in write order.
type member struct {
	name string
	data []byte
}

// Write serialises b. Members are emitted in layout order with integrity.json
// last, because it digests every member before it.
//
// Write sets the fields that describe the archive rather than the collection —
// schema, tool name, the fact index, the integrity pointer — over whatever the
// caller supplied, so a caller cannot produce a bundle whose index disagrees
// with its contents.
func Write(w io.Writer, b Bundle) error {
	if b.Facts == nil {
		return fmt.Errorf("bundle: no fact set to write")
	}
	if err := validateBundleID(b.Manifest.BundleID); err != nil {
		return err
	}
	if b.Manifest.CatalogVersion < 1 {
		return fmt.Errorf("bundle: catalog_version must be at least 1, got %d", b.Manifest.CatalogVersion)
	}

	// Facts first: their digests are part of the manifest that precedes them.
	factMembers, index, err := factMembers(b.Facts)
	if err != nil {
		return err
	}

	m := b.Manifest
	m.Schema = Schema
	m.Tool.Name = toolName
	m.MetaMember = metaMember
	m.ErrorsMember = errorsMember
	m.Facts = index
	m.Evidence = nil
	if b.Evidence != nil {
		m.Evidence = b.Evidence.index()
	}
	m.Integrity = Integrity{Member: integrityMember, Algorithm: hashAlgorithm}

	manifestJSON, err := marshal(m)
	if err != nil {
		return fmt.Errorf("bundle: encoding %s: %w", manifestMember, err)
	}
	metaJSON, err := marshal(b.Meta)
	if err != nil {
		return fmt.Errorf("bundle: encoding %s: %w", metaMember, err)
	}
	// Errors() sorts by fact ID, and an empty set marshals as [] rather than
	// null so the member is always a JSON array.
	errs := b.Facts.Errors()
	if errs == nil {
		errs = []fact.Error{}
	}
	errorsJSON, err := marshal(errs)
	if err != nil {
		return fmt.Errorf("bundle: encoding %s: %w", errorsMember, err)
	}

	members := []member{{manifestMember, manifestJSON}, {metaMember, metaJSON}}
	members = append(members, factMembers...)
	members = append(members, evidenceMembers(b.Evidence)...)
	members = append(members, member{errorsMember, errorsJSON})

	digests := make(map[string]string, len(members))
	for _, mem := range members {
		digests[mem.name] = digest(mem.data)
	}
	integrityJSON, err := marshal(integrityDoc{Algorithm: hashAlgorithm, Members: digests})
	if err != nil {
		return fmt.Errorf("bundle: encoding %s: %w", integrityMember, err)
	}
	members = append(members, member{integrityMember, integrityJSON})

	return writeArchive(w, members, m.Created)
}

// writeArchive tars the members and compresses the result.
func writeArchive(w io.Writer, members []member, modTime time.Time) error {
	// Concurrency 1 keeps one Bundle value producing one byte sequence.
	// Bundles are not reproducible across collections — timestamps move — but
	// they should not vary run to run for identical input.
	zw, err := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return fmt.Errorf("bundle: zstd writer: %w", err)
	}
	tw := tar.NewWriter(zw)

	// Second precision keeps the tar in USTAR format; sub-second times force
	// PAX extension records, which add nothing here.
	mod := modTime.UTC().Truncate(time.Second)
	for _, mem := range members {
		hdr := &tar.Header{
			Name:     mem.name,
			Mode:     0o600, // bundles are sensitive; members inherit that
			Size:     int64(len(mem.data)),
			ModTime:  mod,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("bundle: writing header for %s: %w", mem.name, err)
		}
		if _, err := tw.Write(mem.data); err != nil {
			return fmt.Errorf("bundle: writing %s: %w", mem.name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("bundle: closing tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("bundle: closing zstd stream: %w", err)
	}
	return nil
}

// factMembers serialises every fact in the set, in sorted ID order, and
// returns the manifest index alongside.
func factMembers(s *fact.Set) ([]member, []FactRef, error) {
	ids := s.IDs()
	members := make([]member, 0, len(ids))
	index := make([]FactRef, 0, len(ids))

	for _, id := range ids {
		// fact.Fact satisfies its own constraint, so this reads the fact
		// without the bundle needing to know its concrete type.
		f, _, ok := fact.Get[fact.Fact](s, id)
		if !ok {
			// Unreachable: IDs() lists exactly the facts that are present.
			return nil, nil, fmt.Errorf("bundle: fact %s vanished between listing and reading", id)
		}

		data, err := json.Marshal(f)
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: encoding fact %s: %w", id, err)
		}
		doc, err := marshal(factDoc{ID: id, FactVersion: f.FactVersion(), Data: data})
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: encoding fact %s: %w", id, err)
		}

		name := factsPrefix + string(id) + factsSuffix
		members = append(members, member{name, doc})
		index = append(index, FactRef{
			ID:          id,
			FactVersion: f.FactVersion(),
			Member:      name,
			SHA256:      digest(doc),
		})
	}
	return members, index, nil
}

// evidenceMembers emits one member per stored blob, named for its own digest.
// Deduplication has already happened: the store is keyed by content, so two
// checks citing one file were one entry before they got here.
func evidenceMembers(store *EvidenceStore) []member {
	if store == nil {
		return nil
	}
	digests := store.Digests()
	out := make([]member, 0, len(digests))
	for _, sum := range digests {
		data, ok := store.Get(sum)
		if !ok {
			continue // unreachable: Digests lists exactly what is stored
		}
		out = append(out, member{evidencePrefix + sum + evidenceSuffix, data})
	}
	return out
}

// Read parses and verifies a bundle. Every member is digested and checked
// against integrity.json before anything is interpreted: unverified bytes are
// not parsed, so a crafted bundle cannot reach the decoders by failing the
// integrity check afterwards.
func Read(r io.Reader) (Bundle, error) {
	var b Bundle

	members, err := readArchive(r)
	if err != nil {
		return b, err
	}

	if err := verifyIntegrity(members); err != nil {
		return b, err
	}

	manifestJSON, ok := members[manifestMember]
	if !ok {
		return b, fmt.Errorf("%w: no %s", ErrMalformed, manifestMember)
	}
	if err := json.Unmarshal(manifestJSON, &b.Manifest); err != nil {
		return b, fmt.Errorf("%w: %s: %w", ErrMalformed, manifestMember, err)
	}

	if metaJSON, ok := members[metaMember]; ok {
		if err := json.Unmarshal(metaJSON, &b.Meta); err != nil {
			return b, fmt.Errorf("%w: %s: %w", ErrMalformed, metaMember, err)
		}
	}

	b.Facts = fact.NewSet()
	if err := readFacts(&b, members); err != nil {
		return b, err
	}

	if err := readEvidence(&b, members); err != nil {
		return b, err
	}

	if errorsJSON, ok := members[errorsMember]; ok {
		var errs []fact.Error
		if err := json.Unmarshal(errorsJSON, &errs); err != nil {
			return b, fmt.Errorf("%w: %s: %w", ErrMalformed, errorsMember, err)
		}
		for _, e := range errs {
			b.Facts.PutError(e)
		}
	}

	return b, nil
}

// readArchive decompresses and untars into memory. Nothing is written to disk,
// so a member named ../../etc/passwd has no target; it is still rejected,
// because a name that could only be an attack is not worth carrying further.
func readArchive(r io.Reader) (map[string][]byte, error) {
	zr, err := zstd.NewReader(r,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(uint64(maxDecompressedBytes)))
	if err != nil {
		return nil, fmt.Errorf("bundle: zstd reader: %w", err)
	}
	defer zr.Close()

	members := map[string][]byte{}
	tr := tar.NewReader(zr)
	remaining := maxDecompressedBytes

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: reading tar: %w", ErrMalformed, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: member %q is not a regular file", ErrMalformed, hdr.Name)
		}
		if err := validMemberName(hdr.Name); err != nil {
			return nil, err
		}
		if _, dup := members[hdr.Name]; dup {
			// Two members with one name: the second would silently shadow the
			// first, and which one integrity.json vouched for is unanswerable.
			return nil, fmt.Errorf("%w: duplicate member %q", ErrMalformed, hdr.Name)
		}

		// hdr.Size is attacker-controlled, so it is never used to size an
		// allocation. Copying one byte past the budget is what detects the
		// overrun.
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(tr, remaining+1))
		if err != nil {
			return nil, fmt.Errorf("%w: reading member %q: %w", ErrMalformed, hdr.Name, err)
		}
		if n > remaining {
			return nil, ErrTooLarge
		}
		remaining -= n
		members[hdr.Name] = buf.Bytes()
	}

	return members, nil
}

// validMemberName rejects absolute and traversing names.
func validMemberName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		return fmt.Errorf("%w: unsafe member name %q", ErrMalformed, name)
	}
	return nil
}

// verifyIntegrity checks every member against integrity.json, in both
// directions: a member whose digest differs, a member nothing vouched for, and
// a vouched-for member that is missing are all integrity failures.
func verifyIntegrity(members map[string][]byte) error {
	raw, ok := members[integrityMember]
	if !ok {
		return fmt.Errorf("%w: no %s, so the archive cannot be verified", ErrMalformed, integrityMember)
	}

	var doc integrityDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrMalformed, integrityMember, err)
	}
	if doc.Algorithm != hashAlgorithm {
		return fmt.Errorf("%w: %s names algorithm %q, this build verifies %q only",
			ErrMalformed, integrityMember, doc.Algorithm, hashAlgorithm)
	}

	for _, name := range sortedNames(members) {
		if name == integrityMember {
			continue // a digest cannot cover the file holding it
		}
		want, recorded := doc.Members[name]
		got := digest(members[name])
		if !recorded {
			return &IntegrityError{Member: name, Got: got}
		}
		if want != got {
			return &IntegrityError{Member: name, Want: want, Got: got}
		}
	}

	for _, name := range sortedKeys(doc.Members) {
		if _, present := members[name]; !present {
			return &IntegrityError{Member: name, Want: doc.Members[name]}
		}
	}
	return nil
}

// readFacts decodes the facts the manifest indexes. An ID the registry does
// not know, or a fact_version the registered type does not understand, is
// preserved as UnknownFact: an old binary must be able to open a newer
// bundle, and the checks that depend on that fact degrade to UNKNOWN.
func readFacts(b *Bundle, members map[string][]byte) error {
	indexed := map[string]bool{}

	for _, ref := range b.Manifest.Facts {
		raw, ok := members[ref.Member]
		if !ok {
			return fmt.Errorf("%w: manifest indexes %s, which is not in the archive", ErrMalformed, ref.Member)
		}
		indexed[ref.Member] = true

		// The index carries a digest of its own; disagreeing with
		// integrity.json means one of the two was rewritten.
		if got := digest(raw); got != ref.SHA256 {
			return &IntegrityError{Member: ref.Member, Want: ref.SHA256, Got: got}
		}

		var doc factDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrMalformed, ref.Member, err)
		}
		if doc.ID != ref.ID || doc.FactVersion != ref.FactVersion {
			return fmt.Errorf("%w: %s declares %s v%d, manifest indexes it as %s v%d",
				ErrMalformed, ref.Member, doc.ID, doc.FactVersion, ref.ID, ref.FactVersion)
		}

		d, known := decoderFor(doc.ID)
		if !known || d.version != doc.FactVersion {
			b.Facts.Put(UnknownFact{ID: doc.ID, Version: doc.FactVersion, Raw: doc.Data})
			continue
		}
		f, err := d.decode(doc.Data)
		if err != nil {
			return fmt.Errorf("%w: decoding fact %s: %w", ErrMalformed, doc.ID, err)
		}
		b.Facts.Put(f)
	}

	// A facts/ member the manifest does not index is a fact smuggled past the
	// index. It is verified but unaccounted for, and silently ignoring it
	// would let a bundle carry data no reader agrees exists.
	for _, name := range sortedNames(members) {
		if strings.HasPrefix(name, factsPrefix) && !indexed[name] {
			return fmt.Errorf("%w: %s is in the archive but not in the manifest index", ErrMalformed, name)
		}
	}
	return nil
}

// readEvidence rebuilds the evidence store from the evidence/ members.
//
// Every blob is checked against the digest it is named for. integrity.json has
// already confirmed the archive is internally consistent; this confirms
// something integrity.json cannot, which is that a blob is the bytes a finding
// citing that digest expects. Without it, an archive could be internally
// consistent about the wrong content.
func readEvidence(b *Bundle, members map[string][]byte) error {
	var store *EvidenceStore

	for _, name := range sortedNames(members) {
		if !strings.HasPrefix(name, evidencePrefix) {
			continue
		}
		sum, ok := strings.CutSuffix(strings.TrimPrefix(name, evidencePrefix), evidenceSuffix)
		if !ok || !isSHA256(sum) {
			return fmt.Errorf("%w: evidence member %q is not named for a sha256", ErrMalformed, name)
		}
		if got := digest(members[name]); got != sum {
			return &IntegrityError{Member: name, Want: sum, Got: got}
		}
		if store == nil {
			store = NewEvidenceStore()
		}
		store.Add(members[name])
	}

	if idx := b.Manifest.Evidence; idx != nil {
		if store == nil {
			store = NewEvidenceStore()
		}
		for _, src := range idx.TruncatedSources {
			store.MarkTruncated(src)
		}
		// The manifest and the archive have to agree about what is in it. A
		// disagreement means one of the two was edited, and guessing which is
		// not a reader's job.
		if idx.Count != store.Len() || idx.TotalBytes != store.TotalBytes() {
			return fmt.Errorf("%w: manifest claims %d evidence blob(s) totalling %d bytes, archive holds %d totalling %d",
				ErrMalformed, idx.Count, idx.TotalBytes, store.Len(), store.TotalBytes())
		}
	}

	b.Evidence = store
	return nil
}

// isSHA256 reports whether s is a lowercase hex sha256, which is what an
// evidence member must be named.
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// marshal encodes without HTML escaping, so paths and values in facts survive
// as written rather than as < sequences.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// validateBundleID enforces the manifest schema's ^[a-f0-9]{32}$.
func validateBundleID(id string) error {
	const want = 32
	if len(id) != want {
		return fmt.Errorf("bundle: bundle_id must be %d hex characters, got %d", want, len(id))
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("bundle: bundle_id must be lowercase hex, got %q", id)
		}
	}
	return nil
}

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

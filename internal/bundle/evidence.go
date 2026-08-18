package bundle

import (
	"sort"
	"sync"

	"github.com/antaryx/plumbline/internal/sanitize"
)

// EvidenceStore holds the raw sources a scan read, addressed by their sha256.
//
// Content addressing is what makes deduplication automatic rather than
// bookkeeping: ten checks citing /etc/login.defs cite one digest, and the
// bundle stores those bytes once. It also makes the store self-verifying — a
// blob whose name does not match its content has been altered, and Read says
// so without consulting anything else.
//
// A finding cites evidence by digest (finding.Evidence.SHA256). The excerpt in
// the finding is for a human to read; the blob is what an auditor re-checks
// when the excerpt is disputed.
//
// The store is safe for concurrent use: collectors run concurrently and all
// register into the same one.
type EvidenceStore struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	truncated map[string]bool
}

// NewEvidenceStore returns an empty store.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{blobs: map[string][]byte{}, truncated: map[string]bool{}}
}

// Add stores data and returns its sha256. Adding the same bytes again returns
// the same digest and stores nothing further.
func (s *EvidenceStore) Add(data []byte) string {
	sum := digest(data)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blobs == nil {
		s.blobs = map[string][]byte{}
	}
	if _, have := s.blobs[sum]; !have {
		// Copied: the caller's slice may be a reused read buffer, and evidence
		// that changes after it was cited is not evidence.
		s.blobs[sum] = append([]byte(nil), data...)
	}
	return sum
}

// Get returns the bytes stored under a digest.
func (s *EvidenceStore) Get(sha string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[sha]
	return b, ok
}

// MarkTruncated notes a source that exceeded the read cap. A finding citing it
// is annotated rather than being allowed to imply the file ended where the
// evidence does.
func (s *EvidenceStore) MarkTruncated(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.truncated == nil {
		s.truncated = map[string]bool{}
	}
	// The source is a path from the host, so it is untrusted text that ends up
	// in a manifest an operator reads (THREAT-MODEL.md T-03).
	s.truncated[sanitize.Text(source)] = true
}

// Digests returns every stored digest, sorted.
func (s *EvidenceStore) Digests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.blobs))
	for sum := range s.blobs {
		out = append(out, sum)
	}
	sort.Strings(out)
	return out
}

// TruncatedSources returns the sources that hit the read cap, sorted.
func (s *EvidenceStore) TruncatedSources() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.truncated) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.truncated))
	for src := range s.truncated {
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// Len reports how many distinct sources are stored.
func (s *EvidenceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.blobs)
}

// TotalBytes reports the size of the store after deduplication.
func (s *EvidenceStore) TotalBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, b := range s.blobs {
		total += len(b)
	}
	return total
}

// index summarises the store for the manifest.
func (s *EvidenceStore) index() *EvidenceIndex {
	return &EvidenceIndex{
		Count:            s.Len(),
		TotalBytes:       s.TotalBytes(),
		TruncatedSources: s.TruncatedSources(),
	}
}

// EvidenceIndex is the manifest's summary of the evidence store. The blobs
// themselves are not listed: they are addressed by content, so a finding's
// sha256 is the only index anyone needs.
type EvidenceIndex struct {
	Count            int      `json:"count"`
	TotalBytes       int      `json:"total_bytes"`
	TruncatedSources []string `json:"truncated_sources,omitempty"`
}

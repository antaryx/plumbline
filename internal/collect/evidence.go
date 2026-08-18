package collect

import (
	"github.com/antaryx/plumbline/internal/system"
)

// EvidenceRecorder stores the raw bytes a collector read, addressed by their
// digest, so that a finding can cite the source itself rather than only an
// excerpt of it. bundle.EvidenceStore implements it.
//
// It is declared here, at the consumer, rather than imported from the bundle
// package: collection should not have to know what an archive looks like.
type EvidenceRecorder interface {
	// Add stores data and returns its sha256. Storing the same bytes twice
	// stores them once.
	Add(data []byte) string
	// MarkTruncated notes a source that hit the read cap, so that a finding
	// citing it can say the evidence is partial instead of implying the file
	// ended where the excerpt does.
	MarkTruncated(source string)
}

// recordingSystem registers every file a collector reads as evidence.
//
// Wiring this at the seam rather than in each collector is deliberate: a
// collector that forgot to register its bytes would produce findings citing
// evidence the bundle does not contain, and the failure would be invisible
// until someone opened the bundle months later. Reading a file is what makes
// it evidence, so reading it is where it is recorded.
type recordingSystem struct {
	system.System
	rec EvidenceRecorder
}

// ReadFile records what it read. A read that failed produced no evidence, and
// a truncated read produces evidence plus a note that it is partial — the
// bytes are still worth keeping, they are simply not the whole file.
func (r recordingSystem) ReadFile(path string, maxBytes int64) (system.ReadResult, error) {
	res, err := r.System.ReadFile(path, maxBytes)
	if err != nil {
		return res, err
	}
	r.rec.Add(res.Data)
	if res.Truncated {
		r.rec.MarkTruncated(path)
	}
	return res, nil
}

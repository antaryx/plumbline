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

// credentialFiles are never stored as evidence, whatever reads them.
//
// A bundle is a portable artifact. It is written 0600 and it is meant to be
// sent — to an auditor, to a vendor, into a ticket — which is what --redact
// exists for. The contents of these files are password hashes, and a hash is
// not a record of what happened on a host: it is the credential itself in a
// form that can be attacked offline at the recipient's leisure. Copying them
// into an archive designed to travel would make Plumbline the most efficient
// credential-exfiltration tool on the system it is auditing.
//
// This is not a redaction option and there is deliberately no flag to turn it
// off. A finding derived from one of these files cites the path and the line
// and carries no digest, because there is no stored blob to verify against —
// which is the honest representation of "we read this and refused to keep it".
//
// See docs/adr/0015-account-data-in-bundles.md. Paths are seam-relative and
// therefore already scan-root independent.
var credentialFiles = map[string]bool{
	"/etc/shadow":           true,
	"/etc/gshadow":          true,
	"/etc/security/opasswd": true, // remembered previous passwords, same hashes
	"/etc/master.passwd":    true, // BSD layout, harmless to list
}

// IsCredentialFile reports whether reading path produces credential material
// that must never be stored as evidence. Exported so a collector can assert
// the exclusion in its own tests rather than trusting it silently.
func IsCredentialFile(path string) bool { return credentialFiles[path] }

// recordingSystem registers every file a collector reads as evidence.
//
// Wiring this at the seam rather than in each collector is deliberate: a
// collector that forgot to register its bytes would produce findings citing
// evidence the bundle does not contain, and the failure would be invisible
// until someone opened the bundle months later. Reading a file is what makes
// it evidence, so reading it is where it is recorded.
//
// The exclusion above is wired here for the same reason, inverted: a collector
// that had to remember not to store credentials is a collector that will one
// day forget, and the forgetting would be invisible until a bundle full of
// password hashes had already been emailed to somebody.
type recordingSystem struct {
	system.System
	rec EvidenceRecorder
}

// ReadFile records what it read. A read that failed produced no evidence, and
// a truncated read produces evidence plus a note that it is partial — the
// bytes are still worth keeping, they are simply not the whole file.
//
// Credential files are read and returned to the caller as normal and are never
// handed to the recorder.
func (r recordingSystem) ReadFile(path string, maxBytes int64) (system.ReadResult, error) {
	res, err := r.System.ReadFile(path, maxBytes)
	if err != nil {
		return res, err
	}
	if IsCredentialFile(path) {
		return res, nil
	}
	r.rec.Add(res.Data)
	if res.Truncated {
		r.rec.MarkTruncated(path)
	}
	return res, nil
}

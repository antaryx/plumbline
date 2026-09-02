// Package version holds build identity: what binary this is, what catalog it
// carries, and what document schema it emits.
//
// All three appear in every findings document and every bundle, because a
// report six months old is only interpretable if you know what produced it.
package version

import "github.com/antaryx/plumbline/internal/catalog"

// Schema is the findings document schema this build emits. Read support for
// older schemas is permanent; write support is current-only (ADR-0007).
const Schema = "findings/v1"

// Build identity, overridden at link time by the Makefile's -ldflags. The
// defaults are what a `go run` or a test binary reports, and they say so
// rather than pretending to be a release.
var (
	Version = "2.0.0"
	Commit  = "none"
	Date    = "unknown"
)

// Set records the build identity stamped into the binary. main calls it once,
// before any command runs.
func Set(version, commit, date string) {
	if version != "" {
		Version = version
	}
	if commit != "" {
		Commit = commit
	}
	if date != "" {
		Date = date
	}
}

// Catalog is the catalog version this build carries. It is not stamped at link
// time: the catalog is compiled in, so asking the catalog is the only answer
// that cannot drift from what actually runs.
func Catalog() int { return catalog.Version }

// Package fact defines the typed system state that collectors produce and
// checks consume. Facts are the entire vocabulary available to a check: if it
// is not in the FactSet, no check may assert it.
//
// See docs/DATA-MODEL.md for the normative description.
package fact

import (
	"fmt"
	"sort"
)

// ID names a fact. Stable forever; a fact ID appears in bundles on disk.
type ID string

// Fact is one typed observation about the system.
type Fact interface {
	FactID() ID
	// FactVersion is bumped when the fact's shape changes incompatibly. A
	// check declares which versions it understands; a mismatch resolves to
	// UNKNOWN rather than to a wrong answer.
	FactVersion() int
}

// Opaque is implemented by a fact that is *present* and whose shape this build
// cannot interpret — a fact ID it has never heard of, or a known ID at a
// FactVersion it does not understand.
//
// It exists because "present" and "usable" are different states and the gap
// between them was silently a third thing. A bundle written by a newer build
// carries facts this one cannot decode; the reader preserves them verbatim so
// that forwarding the bundle loses nothing, which is right. But a preserved
// fact still satisfies "the required fact is present", so a check's Eval ran,
// its typed accessor got the zero value, and an sshd.config it could not
// decode was reported as **NOT_APPLICABLE: the SSH server is not configured on
// this host** — a statement about the host manufactured out of a decode
// failure.
//
// The marker is an interface rather than a concrete type because the fact that
// carries it is produced by internal/bundle, and internal/catalog must not
// import the serialisation layer to evaluate anything.
//
// finding.ReasonFactVersion is the reason code for it, and was declared for
// this case before anything produced it.
type Opaque interface {
	Fact
	// OpaqueFact reports the version the producer declared, which is the
	// number an operator needs in order to know which build wrote the bundle.
	OpaqueFact() int
}

// ErrorKind classifies why a fact is absent. Checks map these to UNKNOWN
// reason codes, which is how ignorance stays visible instead of becoming a
// false PASS.
type ErrorKind string

const (
	ErrNotCollected ErrorKind = "not_collected" // collector did not run (profile, filter)
	ErrPermission   ErrorKind = "permission"    // insufficient privileges
	ErrTimeout      ErrorKind = "timeout"       // collector exceeded its budget
	ErrParse        ErrorKind = "parse"         // source found but unintelligible
	ErrTruncated    ErrorKind = "truncated"     // source exceeded the read cap
	ErrUnsupported  ErrorKind = "unsupported"   // not meaningful on this platform
	ErrInternal     ErrorKind = "internal"      // collector bug; always a test failure in CI
)

// Error records why a fact could not be produced. It is stored in the bundle
// so that a report can explain a gap months later.
type Error struct {
	Fact ID        `json:"fact"`
	Kind ErrorKind `json:"kind"`
	Msg  string    `json:"message"`
	Path string    `json:"path,omitempty"`
}

func (e Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s: %s (%s)", e.Fact, e.Kind, e.Msg, e.Path)
	}
	return fmt.Sprintf("%s: %s: %s", e.Fact, e.Kind, e.Msg)
}

// Set is the collection of facts and fact errors from one collection run. It
// is what a check receives, and what a bundle serialises.
//
// Set is not safe for concurrent writes; the collector runner owns writes and
// hands checks a completed, read-only Set.
type Set struct {
	facts  map[ID]Fact
	errors map[ID]Error
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{facts: map[ID]Fact{}, errors: map[ID]Error{}}
}

// Put records a successfully collected fact.
func (s *Set) Put(f Fact) {
	s.facts[f.FactID()] = f
	delete(s.errors, f.FactID())
}

// PutError records that a fact could not be collected.
func (s *Set) PutError(e Error) {
	s.errors[e.Fact] = e
	delete(s.facts, e.Fact)
}

// Err returns the recorded error for id, if any.
func (s *Set) Err(id ID) (Error, bool) {
	e, ok := s.errors[id]
	return e, ok
}

// Errors returns all fact errors, sorted by fact ID for determinism.
func (s *Set) Errors() []Error {
	out := make([]Error, 0, len(s.errors))
	for _, e := range s.errors {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fact < out[j].Fact })
	return out
}

// Opaque reports whether the fact stored under id is present but not
// interpretable by this build. See the Opaque interface.
func (s *Set) Opaque(id ID) (Opaque, bool) {
	f, ok := s.facts[id]
	if !ok {
		return nil, false
	}
	op, ok := f.(Opaque)
	return op, ok
}

// IDs returns the IDs of all present facts, sorted.
func (s *Set) IDs() []ID {
	out := make([]ID, 0, len(s.facts))
	for id := range s.facts {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Get retrieves a typed fact. The three return values distinguish the three
// states a check must handle separately:
//
//	f, nil, true   -> the fact is present, evaluate normally
//	_, err, false  -> collection failed, resolve to UNKNOWN with err.Kind
//	_, nil, false  -> never collected, resolve to UNKNOWN(not_collected)
//
// Conflating the last two is how scanners end up reporting PASS for things
// they never looked at.
func Get[T Fact](s *Set, id ID) (T, *Error, bool) {
	var zero T
	if e, ok := s.errors[id]; ok {
		return zero, &e, false
	}
	f, ok := s.facts[id]
	if !ok {
		return zero, nil, false
	}
	typed, ok := f.(T)
	if !ok {
		e := Error{Fact: id, Kind: ErrInternal, Msg: fmt.Sprintf("fact %s is %T, not %T", id, f, zero)}
		return zero, &e, false
	}
	return typed, nil, true
}

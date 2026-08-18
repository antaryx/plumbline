// Package collect owns the collector half of the architecture: the code that
// touches the operating system, through system.System and nothing else, and
// turns it into typed facts. Checks never appear here; collectors never make a
// judgement. See CLAUDE.md §1.
//
// This file defines what a collector is and how collectors are ordered. The
// runner that executes them is in runner.go.
package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// Capability is the privilege a collector needs in order to observe anything
// truthful. It exists so that an unprivileged run reports "could not look"
// rather than "found nothing", which are different observations and must never
// be conflated.
//
// v0.1 distinguishes only root from not-root, because that is the only
// distinction any v0.1 collector needs. Finer capabilities
// (cap_dac_read_search, cap_sys_ptrace) get their own values when a collector
// actually requires one; the ordering below is what "exceeds the current euid"
// is measured against.
type Capability int

const (
	// CapNone runs as any user.
	CapNone Capability = iota
	// CapRoot requires euid 0.
	CapRoot
)

func (c Capability) String() string {
	switch c {
	case CapNone:
		return "none"
	case CapRoot:
		return "root"
	default:
		return fmt.Sprintf("capability(%d)", int(c))
	}
}

// satisfiedBy reports whether a scan running as euid holds this capability.
// An unrecognised capability is never satisfied: refusing to run and saying so
// is recoverable, running without the privilege the collector said it needed
// and reporting the result as fact is not.
func (c Capability) satisfiedBy(euid int) bool {
	switch c {
	case CapNone:
		return true
	case CapRoot:
		return euid == 0
	default:
		return false
	}
}

// Cost is how heavy a collector is on the host it is auditing. It is the
// runner's scheduling input, not documentation: Expensive collectors are
// serialised, which is the fix for the audited design's habit of launching a
// dozen simultaneous filesystem walks on a production machine.
type Cost int

const (
	// Cheap collectors read a handful of files and may run concurrently with
	// anything else.
	Cheap Cost = iota
	// Expensive collectors walk filesystems, exec external tools, or otherwise
	// contend for the host's IO. The runner never runs two at once.
	Expensive
)

func (c Cost) String() string {
	switch c {
	case Cheap:
		return "cheap"
	case Expensive:
		return "expensive"
	default:
		return fmt.Sprintf("cost(%d)", int(c))
	}
}

// Collector produces facts from the system.
//
// Collect writes what it observed into fs — both facts and the typed
// fact.Errors that explain what it could not observe, because "I could not
// read this" is itself an observation a check needs. Returning an error is the
// alternative for a failure the collector could not classify; the runner
// records a returned fact.Error as written and anything else as ErrInternal.
//
// A Collector must honour ctx. The runner abandons a collector that outruns
// its budget, and an abandoned collector's goroutine lives until it returns.
type Collector interface {
	// ID is stable and unique within a registry. It names the collector, not
	// the facts it produces.
	ID() string

	// Produces lists the fact IDs this collector is responsible for.
	//
	// It exists so that a failure the collector never got to report — a
	// timeout, a panic, a privilege it did not have — can be recorded against
	// the facts a check will actually look for. Without it the runner can only
	// blame the collector by name, and a check requiring sshd.config resolves
	// to "never collected" when the truth is "timed out": still UNKNOWN, but
	// UNKNOWN for the wrong reason, which is the difference between an
	// operator raising a budget and an operator hunting a bug that is not
	// there.
	Produces() []fact.ID

	// DependsOn lists collector IDs that must complete first. It expresses
	// ordering only: a dependency that failed does not cancel its dependents,
	// which run and record their own account of what was missing.
	DependsOn() []string

	// Requires is the privilege needed to observe truthfully.
	Requires() Capability

	// Cost is the scheduling class.
	Cost() Cost

	// Timeout is this collector's own budget, measured from the moment it
	// starts rather than from when it was queued. ARCHITECTURE.md §"Collectors
	// are budgeted": each collector declares its own, because what is
	// pathological for a config-file read is normal for a filesystem walk.
	// Zero defers to the runner's default.
	Timeout() time.Duration

	// Collect observes the system and records what it found in fs.
	Collect(ctx context.Context, s system.System, fs *fact.Set) error
}

// Registry is an ordered set of collectors.
//
// Registration happens during package initialisation, which Go performs
// sequentially, so Registry is not guarded for concurrent registration. It is
// safe to read from many goroutines once initialisation is complete, which is
// what the runner does.
type Registry struct {
	byID map[string]Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Collector{}}
}

// defaultRegistry is what collectors register themselves into from init.
var defaultRegistry = NewRegistry()

// Default returns the registry that self-registering collectors populate.
func Default() *Registry { return defaultRegistry }

// Register adds c to the default registry. Collectors call it from init, so a
// wiring mistake panics before main runs.
func Register(c Collector) { defaultRegistry.Register(c) }

// Register adds c.
//
// It panics on an unusable graph — an empty or duplicate ID, a collector
// depending on itself, or a dependency cycle — rather than returning an error.
// Registration happens at init, so a panic surfaces on the first test run and
// can never reach a production scan; a cycle discovered at scan time would be
// a deadlock or a silently truncated collection instead.
func (r *Registry) Register(c Collector) {
	id := c.ID()
	switch {
	case id == "":
		panic("collect: collector registered with an empty ID")
	case r.byID[id] != nil:
		panic(fmt.Sprintf("collect: duplicate collector ID %q", id))
	}
	for _, d := range c.DependsOn() {
		if d == id {
			panic(fmt.Sprintf("collect: collector %q depends on itself", id))
		}
	}

	r.byID[id] = c

	// The cycle can only be complete once its last member is registered, so
	// checking after every Register catches it at the moment it exists.
	if cycle := findCycle(r.byID); cycle != nil {
		delete(r.byID, id) // leave the registry usable if a test recovers
		panic(fmt.Sprintf("collect: dependency cycle among collectors: %s", strings.Join(cycle, " -> ")))
	}
}

// Len reports how many collectors are registered.
func (r *Registry) Len() int { return len(r.byID) }

// Get returns a collector by ID.
func (r *Registry) Get(id string) (Collector, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// IDs returns every registered ID, sorted.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.byID))
	for id := range r.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Order returns the collectors in dependency order: every collector appears
// after everything it depends on. Ties are broken lexicographically, so the
// plan for a given registry is always the same one — the runner may execute
// independent branches concurrently, but it never has to guess the plan.
//
// Register rejects cycles, so this always succeeds. Dependencies on collectors
// that are not registered impose no ordering; MissingDependencies reports them.
func (r *Registry) Order() []string {
	indegree := make(map[string]int, len(r.byID))
	dependents := make(map[string][]string, len(r.byID))
	for _, id := range r.IDs() {
		indegree[id] = 0
	}
	for _, id := range r.IDs() {
		for _, d := range r.knownDeps(id) {
			indegree[id]++
			dependents[d] = append(dependents[d], id)
		}
	}

	var ready []string
	for _, id := range r.IDs() {
		if indegree[id] == 0 {
			ready = append(ready, id)
		}
	}

	out := make([]string, 0, len(r.byID))
	for len(ready) > 0 {
		sort.Strings(ready)
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)

		next := append([]string(nil), dependents[id]...)
		sort.Strings(next)
		for _, d := range next {
			indegree[d]--
			if indegree[d] == 0 {
				ready = append(ready, d)
			}
		}
	}
	return out
}

// MissingDependencies reports collectors that name a dependency nobody
// registered, keyed by collector ID. That is a wiring bug — usually a
// collector package that was never imported — and the runner refuses to run
// such a collector rather than running it against facts that will not be
// there.
func (r *Registry) MissingDependencies() map[string][]string {
	var out map[string][]string
	for _, id := range r.IDs() {
		var missing []string
		for _, d := range dedupe(r.byID[id].DependsOn()) {
			if _, known := r.byID[d]; !known {
				missing = append(missing, d)
			}
		}
		if len(missing) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[id] = missing
		}
	}
	return out
}

// knownDeps returns id's registered dependencies, deduplicated and sorted. A
// dependency listed twice must not count twice, or the topological sort never
// releases it.
func (r *Registry) knownDeps(id string) []string {
	var out []string
	for _, d := range dedupe(r.byID[id].DependsOn()) {
		if _, known := r.byID[d]; known {
			out = append(out, d)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// findCycle returns one dependency cycle as a readable path, or nil. The walk
// is over sorted IDs so that a graph with several cycles always reports the
// same one; an error message that changes between runs is an error message
// nobody trusts.
func findCycle(byID map[string]Collector) []string {
	const (
		unvisited = iota
		open      // on the current path
		closed
	)

	state := make(map[string]int, len(byID))
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var path, cycle []string
	var visit func(string) bool
	visit = func(id string) bool {
		state[id] = open
		path = append(path, id)

		for _, d := range dedupe(byID[id].DependsOn()) {
			if _, known := byID[d]; !known {
				continue
			}
			switch state[d] {
			case open:
				for i, s := range path {
					if s == d {
						cycle = append(append([]string(nil), path[i:]...), d)
						break
					}
				}
				return true
			case unvisited:
				if visit(d) {
					return true
				}
			}
		}

		path = path[:len(path)-1]
		state[id] = closed
		return false
	}

	for _, id := range ids {
		if state[id] == unvisited && visit(id) {
			return cycle
		}
	}
	return nil
}

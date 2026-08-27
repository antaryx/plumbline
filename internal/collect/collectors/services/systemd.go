package services

import (
	"context"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/collect/unit"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// SandboxID is the identifier of the collector that reads service sandboxing.
//
// It is a second collector in this package rather than more work inside the
// first, and the reason is the same one that split the Docker collectors in
// two. services.units is built from symlinks and directory listings and
// answers for every unit on the host; this one opens a named handful of unit
// *bodies*, where a single denied drop-in makes one unit's answer unknown
// while the rest are perfectly readable. Keeping them apart means that failure
// resolves SERVICES-0006 to UNKNOWN without touching the five checks that read
// enablement and have nothing to do with it.
const SandboxID = "services-sandbox"

// sandboxDirectives are the only directives read out of a unit.
//
// The list is passed to unit.Assemble, which discards everything else during
// the parse — so this is the privacy boundary rather than a filter applied
// afterwards, and Environment= is never held in memory at all. See the package
// doc.
var sandboxDirectives = []string{
	"NoNewPrivileges",
	"ProtectSystem",
	"ProtectHome",
}

// SandboxCollector reads the sandboxing directives of a named set of units.
type SandboxCollector struct{}

// NewSandbox returns the service sandboxing collector.
func NewSandbox() SandboxCollector { return SandboxCollector{} }

func init() { collect.Register(NewSandbox()) }

var _ collect.Collector = SandboxCollector{}

func (SandboxCollector) ID() string { return SandboxID }

// Produces names the fact this collector is responsible for.
func (SandboxCollector) Produces() []fact.ID { return []fact.ID{fact.ServiceHardeningID} }

// DependsOn is nil. Reading a unit file needs nothing else observed first —
// in particular it does not need services.units, because a unit's sandboxing
// is a property of the file whether or not anything enabled it.
func (SandboxCollector) DependsOn() []string { return nil }

// Requires is CapNone. Unit files are 0644 on every distribution, so an
// unprivileged scan reads them; a drop-in that is not resolves to a fragment
// recorded as denied, which is the specific, actionable observation.
func (SandboxCollector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: a handful of stats and small bounded reads per unit. No walk,
// no exec.
func (SandboxCollector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds — a little more than the Docker unit collector's five
// because this one assembles several units rather than one.
func (SandboxCollector) Timeout() time.Duration { return 10 * time.Second }

// Collect assembles each target unit and records its sandboxing.
func (SandboxCollector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	h := fact.ServiceHardening{Systemd: systemdPresent(s)}

	for _, name := range fact.SandboxTargets {
		if ctx.Err() != nil {
			// An abandoned scan stops reading. The units not reached are
			// recorded as errors rather than omitted, so a check counting
			// targets is not handed a short list it would read as absences.
			h.Services = append(h.Services, fact.ServiceSandbox{
				Unit:  name,
				State: fact.UnitError,
				Msg:   "the scan was abandoned before this unit was read",
			})
			continue
		}
		h.Services = append(h.Services, readSandbox(s, name))
	}

	fs.Put(h)
	return nil
}

// systemdPresent reports whether this host runs systemd at all.
//
// A directory that exists is enough, and a directory we were refused counts as
// present: something is there and we could not read it, which is a different
// answer from "this host runs OpenRC" and must not be collapsed into it.
func systemdPresent(s system.System) bool {
	for _, root := range unit.Roots() {
		if _, err := s.Stat(root); err == nil {
			return true
		}
	}
	return false
}

// readSandbox assembles one unit and pulls the three directives out of it.
func readSandbox(s system.System, name string) fact.ServiceSandbox {
	asm := unit.Assemble(s, unit.Request{
		Name:       name,
		Section:    "Service",
		Directives: sandboxDirectives,
	})

	out := fact.ServiceSandbox{
		Unit:      name,
		State:     asm.State,
		Path:      asm.Path,
		Digest:    asm.Digest,
		Msg:       asm.Msg,
		Fragments: asm.Fragments,
	}
	if asm.State != fact.UnitPresent {
		return out
	}

	if v, set, bad := lastBool(asm, "NoNewPrivileges"); bad {
		out.Malformed = append(out.Malformed, "NoNewPrivileges")
	} else if set {
		out.NoNewPrivileges = &v
	}

	// ProtectSystem takes the last value systemd would accept, for the reason
	// the boolean does: an unparseable one is logged and ignored, leaving the
	// previous value or the default in force. Its grammar is a superset of the
	// booleans, so "true" and "1" are as valid here as "full".
	if v, set, bad := lastEnum(asm, "ProtectSystem", validProtectSystem); bad {
		out.Malformed = append(out.Malformed, "ProtectSystem")
	} else if set {
		out.ProtectSystem = v
	}
	if v, set, bad := lastEnum(asm, "ProtectHome", validProtectHome); bad {
		out.Malformed = append(out.Malformed, "ProtectHome")
	} else if set {
		out.ProtectHome = v
	}
	return out
}

// lastEnum reads the effective value of a directive whose values are a fixed
// set, keeping the last one systemd would accept.
//
// It is lastBool's shape with the parser passed in, because the rule it
// encodes is systemd's rather than any one directive's: an assignment that
// does not parse is logged and skipped, so the effective value is the last
// *valid* one and not the last one. bad reports that something was rejected
// and nothing valid followed it — the case where the file looks configured and
// the host is not.
func lastEnum(asm unit.Unit, name string, valid func(string) bool) (value string, set, bad bool) {
	for _, d := range asm.Directives {
		if d.Name != name {
			continue
		}
		// An empty assignment is systemd's reset: it restores the default and
		// clears anything said before it, including a malformed line.
		if d.Value == "" {
			value, set, bad = "", false, false
			continue
		}
		if !valid(d.Value) {
			bad = true
			continue
		}
		value, set, bad = d.Value, true, false
	}
	return value, set, bad
}

func validProtectSystem(v string) bool {
	_, ok := fact.ParseProtectSystem(v)
	return ok
}

func validProtectHome(v string) bool {
	_, ok := fact.ParseProtectHome(v)
	return ok
}

// lastBool reads the effective value of a boolean directive.
//
// **systemd ignores an assignment it cannot parse.** It logs a warning and
// leaves the previous value — or the compiled-in default — in force, rather
// than treating the line as false or refusing to load the unit. So the
// effective value is the last *parseable* assignment, not the last one, and a
// unit whose only NoNewPrivileges= line reads "maybe" is running with the
// setting off while its file appears to say otherwise.
//
// bad reports that at least one assignment was rejected and none that parsed
// followed it, which is the case worth telling an operator about: the file
// looks configured and the host is not.
func lastBool(asm unit.Unit, name string) (value, set, bad bool) {
	for _, d := range asm.Directives {
		if d.Name != name {
			continue
		}
		// An empty assignment is systemd's reset: it restores the default and
		// clears anything said before it, including a malformed line.
		if d.Value == "" {
			value, set, bad = false, false, false
			continue
		}
		v, ok := fact.ParseSystemdBool(d.Value)
		if !ok {
			bad = true
			continue
		}
		value, set, bad = v, true, false
	}
	return value, set, bad
}

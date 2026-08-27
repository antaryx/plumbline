package services_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	registry "github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/services"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/fake"
)

func collectSandbox(t *testing.T, name string) fact.ServiceHardening {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.NewSandbox().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	h, ferr, ok := fact.Get[fact.ServiceHardening](facts, fact.ServiceHardeningID)
	if !ok {
		t.Fatalf("services.hardening missing after collection: %v", ferr)
	}
	return h
}

// unitIn returns one target's record. Every target is recorded whether or not
// it is installed, so this never has to handle a missing entry.
func unitIn(t *testing.T, h fact.ServiceHardening, name string) fact.ServiceSandbox {
	t.Helper()
	for _, s := range h.Services {
		if s.Unit == name {
			return s
		}
	}
	t.Fatalf("%s is not in the fact at all; every target must be recorded", name)
	return fact.ServiceSandbox{}
}

// TestSandboxCollectorContract asserts the declarations the runner schedules
// on, and that this collector is registered alongside the enablement one
// rather than instead of it.
func TestSandboxCollectorContract(t *testing.T) {
	c := collector.NewSandbox()

	if got := c.Produces(); !reflect.DeepEqual(got, []fact.ID{fact.ServiceHardeningID}) {
		t.Errorf("Produces = %v", got)
	}
	if c.Requires() != registry.CapNone {
		t.Errorf("Requires = %v, want CapNone: unit files are world-readable", c.Requires())
	}
	if c.Cost() != registry.Cheap {
		t.Errorf("Cost = %v, want Cheap", c.Cost())
	}

	ids := registry.Default().IDs()
	for _, want := range []string{"services", "services-sandbox"} {
		if _, ok := registry.Default().Get(want); !ok {
			t.Errorf("collector %q is not registered: %v", want, ids)
		}
	}
}

// TestSystemdBooleanSpellings is the collector's central parsing property.
//
// systemd's parse_boolean accepts far more than yes/no, and it is not
// uniformly case-insensitive: "1" and "0" are compared exactly, every word is
// compared case-insensitively. A re-implementation that folded everything, or
// that accepted only the two spellings the documentation shows, would disagree
// with the host about what its own unit file says — in one direction or the
// other, on the units where somebody wrote "True".
func TestSystemdBooleanSpellings(t *testing.T) {
	for _, v := range []string{"1", "yes", "Yes", "YES", "y", "Y", "true", "True", "TRUE", "t", "T", "on", "On", "ON"} {
		got, ok := collector.ParseBool(v)
		if !ok || !got {
			t.Errorf("ParseBool(%q) = %v/%v, want true/true", v, got, ok)
		}
	}
	for _, v := range []string{"0", "no", "No", "NO", "n", "N", "false", "False", "FALSE", "f", "F", "off", "Off", "OFF"} {
		got, ok := collector.ParseBool(v)
		if !ok || got {
			t.Errorf("ParseBool(%q) = %v/%v, want false/true", v, got, ok)
		}
	}

	// Not booleans. **These are emphatically not false**: systemd logs a
	// warning and ignores the assignment, so the previous value or the default
	// stays in force. A parser returning false here would report a unit as
	// deliberately unhardened when the truth is that its line does nothing.
	for _, v := range []string{"", "maybe", "2", "-1", "yes ", "y e s", "enabled", "01", "TRUE!", "оn"} {
		if got, ok := collector.ParseBool(v); ok {
			t.Errorf("ParseBool(%q) = %v/true, want not-parsed", v, got)
		}
	}

	// "1" and "0" are exact. There is no case to fold, and the point of the
	// assertion is that the numeric branch is not reached through the folding
	// one — a parser that lowercased first and then compared would accept
	// nothing different here, but one that folded and compared "01" or " 1"
	// would.
	if _, ok := collector.ParseBool(" 1"); ok {
		t.Error("ParseBool(\" 1\") parsed; systemd compares the value exactly")
	}
}

// TestEverySpellingReachesTheFact runs the three accepted spellings through
// the whole collector rather than through the parser alone, because a parser
// that is right and a collector that never calls it would pass the test above.
func TestEverySpellingReachesTheFact(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-hardened")

	for _, name := range fact.SandboxTargets {
		s := unitIn(t, h, name)
		if !s.Judgeable() {
			t.Fatalf("%s: state = %s, want present: %s", name, s.State, s.Msg)
		}
		on, set := fact.OptBool(s.NoNewPrivileges)
		if !set || !on {
			t.Errorf("%s: NoNewPrivileges = %v/set=%v, want true", name, on, set)
		}
		if len(s.Malformed) > 0 {
			t.Errorf("%s: recorded a malformed directive it should have parsed: %v", name, s.Malformed)
		}
	}

	// The other two directives, which no check reads yet and which the fact
	// records as written: the three ProtectSystem levels are not
	// interchangeable and folding them to a boolean would lose the difference.
	if got := unitIn(t, h, "cron.service").ProtectSystem; got != "full" {
		t.Errorf("ProtectSystem = %q, want full", got)
	}
	if got := unitIn(t, h, "systemd-journald.service").ProtectSystem; got != "strict" {
		t.Errorf("ProtectSystem = %q, want strict", got)
	}
	if got := unitIn(t, h, "cron.service").ProtectHome; got != "read-only" {
		t.Errorf("ProtectHome = %q, want read-only", got)
	}
}

// TestAValueSystemdRejectsIsNotFalse.
//
// The whole reason ParseBool has an ok return. systemd logs a warning on
// NoNewPrivileges=maybe and *ignores the line*, leaving the default in force —
// so the effective posture is unhardened, which a check must be able to say,
// while the file plainly contains the directive, which an operator must be
// able to be told. Recording it as an explicit false would merge those into
// one wrong sentence.
func TestAValueSystemdRejectsIsNotFalse(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-explicit-off")

	bad := unitIn(t, h, "dbus.service")
	if _, set := fact.OptBool(bad.NoNewPrivileges); set {
		t.Errorf("a value systemd rejects was recorded as a boolean: %v", bad.NoNewPrivileges)
	}
	if !reflect.DeepEqual(bad.Malformed, []string{"NoNewPrivileges"}) {
		t.Errorf("Malformed = %v, want [NoNewPrivileges]", bad.Malformed)
	}

	// And the neighbouring unit, which wrote the directive down and chose off.
	// Same posture, different act, and the fact keeps them apart.
	off := unitIn(t, h, "cron.service")
	on, set := fact.OptBool(off.NoNewPrivileges)
	if !set || on {
		t.Errorf("cron.service NoNewPrivileges = %v/set=%v, want false/set=true", on, set)
	}
	if len(off.Malformed) > 0 {
		t.Errorf("a parseable no was recorded as malformed: %v", off.Malformed)
	}
}

// TestADropInDecidesTheAnswer is the reason this collector cannot read only
// the unit file.
//
// cron.service sets nothing; the answer is in a drop-in. Two drop-ins share
// the basename 50-hardening.conf and disagree, and systemd discards the
// /usr/lib one *entirely* because /etc holds a file of the same name — which
// is how an administrator neutralises a vendor drop-in without editing a file
// they do not own. Applying the loser reports NoNewPrivileges=no on a host
// that set it to yes.
func TestADropInDecidesTheAnswer(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-dropin")
	s := unitIn(t, h, "cron.service")

	on, set := fact.OptBool(s.NoNewPrivileges)
	if !set || !on {
		t.Errorf("NoNewPrivileges = %v/set=%v, want true from the winning drop-in", on, set)
	}
	// The later drop-in still applies; winning a basename contest is not the
	// same as being the only file read.
	if s.ProtectHome != "tmpfs" {
		t.Errorf("ProtectHome = %q, want tmpfs from 90-late.conf", s.ProtectHome)
	}

	// The loser is recorded rather than dropped: a shadowed override is a file
	// somebody edited and systemd never read, which is a mistake worth seeing.
	var shadowed *fact.UnitFragment
	for i, f := range s.Fragments {
		if f.Shadowed {
			shadowed = &s.Fragments[i]
		}
	}
	if shadowed == nil {
		t.Fatalf("the shadowed drop-in is not recorded: %+v", s.Fragments)
	}
	if !strings.HasPrefix(shadowed.Path, "/usr/lib/") {
		t.Errorf("the wrong drop-in was shadowed: %s", shadowed.Path)
	}
	if !strings.HasPrefix(shadowed.ShadowedBy, "/etc/") {
		t.Errorf("ShadowedBy = %q, want the /etc copy", shadowed.ShadowedBy)
	}
	// A shadowed file systemd would not apply is not a gap in what we read.
	if !s.Judgeable() || len(s.Incomplete()) != 0 {
		t.Errorf("a shadowed drop-in was counted as unread: %+v", s.Incomplete())
	}
}

// TestAnUnreadableDropInLeavesTheUnitIncomplete. The unit file itself sets
// NoNewPrivileges=yes and the drop-in beside it cannot be read, which is
// exactly the shape in which a confident PASS would be wrong.
func TestAnUnreadableDropInLeavesTheUnitIncomplete(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-denied")
	s := unitIn(t, h, "cron.service")

	if s.State != fact.UnitPresent {
		t.Fatalf("the unit itself should have read: %s %s", s.State, s.Msg)
	}
	if len(s.Incomplete()) != 1 {
		t.Fatalf("Incomplete = %+v, want the denied drop-in", s.Incomplete())
	}
	if got := s.Incomplete()[0].State; got != fact.UnitDenied {
		t.Errorf("fragment state = %s, want denied", got)
	}
	if len(h.Unreadable()) != 1 {
		t.Errorf("Unreadable = %+v, want cron.service", h.Unreadable())
	}
}

// TestAMaskedUnitIsNotAFinding. `systemctl mask` points the unit at /dev/null
// and systemd then refuses to start it, so the unhardened vendor file
// underneath describes no process that exists.
func TestAMaskedUnitIsNotAFinding(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-masked")

	s := unitIn(t, h, "cron.service")
	if s.State != fact.UnitMasked {
		t.Errorf("state = %s, want masked", s.State)
	}
	if s.Judgeable() {
		t.Error("a masked unit is not judgeable: systemd will not start it")
	}
	if !s.Installed() {
		t.Error("a masked unit is installed; the file is there and systemd ignores it")
	}
	// Masked is not a gap in what this scan could see.
	if len(h.Unreadable()) != 0 {
		t.Errorf("a masked unit was counted as unreadable: %+v", h.Unreadable())
	}
}

// TestAnAbsentUnitIsRecordedRatherThanOmitted.
//
// Every target gets an entry whether or not it exists, so a check counting
// targets is never handed a short list it would have to read as something
// else. dbus.service is not installed in this fixture.
func TestAnAbsentUnitIsRecordedRatherThanOmitted(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-stock")

	if len(h.Services) != len(fact.SandboxTargets) {
		t.Fatalf("recorded %d units, want %d", len(h.Services), len(fact.SandboxTargets))
	}
	absent := unitIn(t, h, "dbus.service")
	if absent.State != fact.UnitAbsent {
		t.Errorf("state = %s, want absent", absent.State)
	}
	if absent.Installed() {
		t.Error("an absent unit reports as installed")
	}
	// It still names where it looked, so a reader is told what was looked for
	// rather than only that nothing was found.
	if absent.Path == "" {
		t.Error("an absent unit does not say where it was looked for")
	}
	if len(h.Installed()) != 2 {
		t.Errorf("Installed = %d units, want 2", len(h.Installed()))
	}
}

// TestOnlyTheRequestedDirectivesReachTheFact is the collector's privacy
// property, and it is structural rather than a filter.
//
// unit.Assemble is given the three directive names and discards everything
// else during the parse, so an Environment= or an ExecStart is never held in
// memory, let alone recorded. That is what makes reading unit bodies here
// compatible with the enablement collector's promise not to — see the package
// doc.
func TestOnlyTheRequestedDirectivesReachTheFact(t *testing.T) {
	h := collectSandbox(t, "services-sandbox-hardened")

	blob, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Every one of these is in the fixture's cron.service and none of them was
	// asked for.
	for _, leaked := range []string{
		"/usr/sbin/cron",     // ExecStart
		"EXTRA_OPTS",         // an unexpanded variable in it
		"/etc/default/cron",  // EnvironmentFile
		"Regular background", // the [Unit] description
		"multi-user.target",  // the [Install] section
	} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("a directive nobody asked for reached the fact: %q\n%s", leaked, blob)
		}
	}

	// What must be there: the digest, so a finding can be verified against the
	// host even though the bytes are not carried.
	if unitIn(t, h, "cron.service").Digest == "" {
		t.Error("no digest recorded; an auditor has nothing to reproduce")
	}
}

// TestUnitBodiesDoNotEnterTheEvidenceStore.
//
// The digest above is only worth having if the bytes are not also in the
// bundle. Fragments go through ReadOpaque, which collect.recordingSystem
// excludes from the evidence store by construction — the exclusion is at the
// seam rather than in the caller, so this asserts the collector uses the right
// door.
func TestUnitBodiesDoNotEnterTheEvidenceStore(t *testing.T) {
	base, err := fake.New(filepath.Join(fixtureRoot, "services-sandbox-hardened"))
	if err != nil {
		t.Fatal(err)
	}
	spy := &sandboxSpy{System: base}

	facts := fact.NewSet()
	if err := collector.NewSandbox().Collect(context.Background(), spy, facts); err != nil {
		t.Fatal(err)
	}

	if len(spy.readFile) > 0 {
		t.Errorf("unit files were read through ReadFile, so their bytes are in the bundle: %v", spy.readFile)
	}
	if len(spy.readOpaque) != len(fact.SandboxTargets) {
		t.Errorf("ReadOpaque calls = %v, want one per installed target", spy.readOpaque)
	}
}

// sandboxSpy records which door each read went through.
type sandboxSpy struct {
	*fake.System
	readFile   []string
	readOpaque []string
}

func (s *sandboxSpy) ReadFile(p string, max int64) (system.ReadResult, error) {
	s.readFile = append(s.readFile, p)
	return s.System.ReadFile(p, max)
}

func (s *sandboxSpy) ReadOpaque(p string, max int64) (system.ReadResult, error) {
	s.readOpaque = append(s.readOpaque, p)
	return s.System.ReadOpaque(p, max)
}

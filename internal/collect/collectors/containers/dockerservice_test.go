package containers_test

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/containers"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/system/fake"
)

func collectService(t *testing.T, name string) fact.DockerService {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.NewService().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	u, ferr, ok := fact.Get[fact.DockerService](facts, fact.DockerServiceID)
	if !ok {
		t.Fatalf("containers.docker_service missing after collection: %v", ferr)
	}
	return u
}

// specs is the socket list a fixture's effective command line asks for, which
// is what almost every assertion below is really about.
func specs(u fact.DockerService) []string {
	var out []string
	for _, h := range u.Hosts() {
		out = append(out, h.Spec)
	}
	return out
}

// TestServiceCollectorContract asserts the declarations the runner schedules
// on, and that this is a second collector rather than a second read inside the
// first.
func TestServiceCollectorContract(t *testing.T) {
	c := collector.NewService()

	if got, want := c.ID(), "containers-service"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got := c.Produces(); len(got) != 1 || got[0] != fact.DockerServiceID {
		t.Errorf("Produces = %v, want [%s]", got, fact.DockerServiceID)
	}
	if got := c.DependsOn(); len(got) != 0 {
		t.Errorf("DependsOn = %v, want nothing", got)
	}
	if got, want := c.Cost(), collect.Cheap; got != want {
		t.Errorf("Cost = %v, want %v", got, want)
	}
	// CapNone: unit directories are world-readable everywhere, and a drop-in
	// that is not must be recorded as denied rather than skipping the lot.
	if got, want := c.Requires(), collect.CapNone; got != want {
		t.Errorf("Requires = %v, want %v", got, want)
	}
	if c.Timeout() <= 0 || c.Timeout() > time.Minute {
		t.Errorf("Timeout = %v; the collector must declare a budget it can justify", c.Timeout())
	}

	reg := collect.Default()
	if _, ok := reg.Get("containers-service"); !ok {
		t.Errorf("the containers-service collector did not register itself; the registry holds %v", reg.IDs())
	}
	// Both halves of the module are in the registry under their own names. A
	// second Register call that had reused the first collector's ID would have
	// replaced it silently and taken daemon.json out of every scan.
	if _, ok := reg.Get("containers"); !ok {
		t.Errorf("registering the service collector displaced the daemon collector; the registry holds %v", reg.IDs())
	}
}

// TestReadsTheVendorUnit is the base case: the unit every distribution ships,
// no drop-ins, one ExecStart.
func TestReadsTheVendorUnit(t *testing.T) {
	u := collectService(t, "containers-docker-service-stock")

	if !u.Judgeable() {
		t.Fatalf("state = %s (%s), want %s", u.State, u.Msg, fact.DockerUnitPresent)
	}
	if got, want := u.Path, "/lib/systemd/system/docker.service"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if u.Digest == "" {
		t.Error("no digest recorded; a finding could not cite the text it read")
	}
	if len(u.ExecStart) != 1 {
		t.Fatalf("ExecStart = %v, want exactly one directive", u.ExecStart)
	}

	e := u.ExecStart[0]
	want := []string{"/usr/bin/dockerd", "-H", "fd://", "--containerd=/run/containerd/containerd.sock"}
	if !reflect.DeepEqual(e.Argv, want) {
		t.Errorf("argv = %v, want %v", e.Argv, want)
	}
	if e.Line == 0 {
		t.Error("no line number recorded; evidence would point at a file rather than at a line")
	}
	if got := specs(u); !reflect.DeepEqual(got, []string{"fd://"}) {
		t.Errorf("hosts = %v, want [fd://]", got)
	}

	// ExecReload=/bin/kill -s HUP $MAINPID is in the same [Service] section.
	// Reading it would both invent a command line and, because of the
	// $MAINPID, report an ambiguity that is not one.
	if got := u.Ambiguities(); len(got) != 0 {
		t.Errorf("ambiguities = %v; only ExecStart is read, and this unit's ExecStart has no variable in it", got)
	}
}

// TestADropInIsWhereTheExposureLives is the collector's reason to exist.
//
// The vendor unit is untouched and says -H fd://. A collector that read only
// the unit file would report this host as binding nothing but the local
// socket, which is the opposite of true.
func TestADropInIsWhereTheExposureLives(t *testing.T) {
	u := collectService(t, "containers-docker-service-tcp")

	if len(u.ExecStart) != 1 {
		t.Fatalf("ExecStart = %v, want one directive: the drop-in resets the list before adding its own", u.ExecStart)
	}
	if got, want := u.ExecStart[0].Origin, "/etc/systemd/system/docker.service.d/override.conf"; got != want {
		t.Errorf("the surviving ExecStart came from %q, want %q", got, want)
	}
	if got, want := specs(u), []string{"fd://", "tcp://0.0.0.0:2375"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
	if !u.Complete() {
		t.Errorf("Complete = false over %v; every fragment here was read", u.Incomplete())
	}
}

// TestABareExecStartResetsTheList pins the fold, which is the whole of why a
// drop-in can replace a command line rather than only add to it.
func TestABareExecStartResetsTheList(t *testing.T) {
	u := collectService(t, "containers-docker-service-tcp")

	for _, e := range u.ExecStart {
		if strings.HasSuffix(e.Origin, "/lib/systemd/system/docker.service") {
			t.Errorf("the vendor ExecStart survived the drop-in's reset: %v", e.Argv)
		}
	}
}

// TestAShadowedDropInIsRecordedAndNotApplied is the precedence rule that a
// naive implementation gets wrong, and getting it wrong is a critical false
// positive rather than a cosmetic one.
//
// Two drop-ins share a filename across two search directories. systemd takes
// the /etc one and ignores the /lib one entirely — that is how an
// administrator neutralises a vendor drop-in — so the tcp:// binding in /lib is
// not in force and this host is not exposed.
func TestAShadowedDropInIsRecordedAndNotApplied(t *testing.T) {
	u := collectService(t, "containers-docker-service-shadowed")

	if got := specs(u); !reflect.DeepEqual(got, []string{"fd://"}) {
		t.Errorf("hosts = %v, want [fd://]: the /lib drop-in is shadowed and must not be applied", got)
	}

	var shadowed *fact.UnitFragment
	for i, f := range u.Fragments {
		if f.Shadowed {
			shadowed = &u.Fragments[i]
		}
	}
	if shadowed == nil {
		t.Fatalf("no fragment recorded as shadowed: %+v", u.Fragments)
	}
	if got, want := shadowed.Path, "/lib/systemd/system/docker.service.d/override.conf"; got != want {
		t.Errorf("shadowed fragment = %q, want %q", got, want)
	}
	if !strings.HasPrefix(shadowed.ShadowedBy, "/etc/") {
		t.Errorf("shadowed by %q, want the /etc drop-in that outranks it", shadowed.ShadowedBy)
	}
	// A shadowed file is not a gap. systemd would not have applied it, so not
	// having folded it changes nothing and must not make the fact incomplete.
	if !u.Complete() {
		t.Errorf("Complete = false over %v; a shadowed drop-in is not a fragment that went unread", u.Incomplete())
	}
}

// TestAContinuedExecStartIsJoined covers how anybody actually writes a command
// line with four TLS flags on it.
func TestAContinuedExecStartIsJoined(t *testing.T) {
	u := collectService(t, "containers-docker-service-tls")

	if len(u.ExecStart) != 1 {
		t.Fatalf("ExecStart = %v, want one directive", u.ExecStart)
	}
	argv := u.ExecStart[0].Argv
	for _, want := range []string{"--tlsverify", "--tlscacert=/etc/docker/ca.pem", "--tlskey=/etc/docker/server-key.pem"} {
		found := false
		for _, tok := range argv {
			if tok == want {
				found = true
			}
		}
		if !found {
			t.Errorf("argv %v is missing %q; the continuation lines were not joined", argv, want)
		}
	}
	if !u.BoolFlag("tlsverify") {
		t.Error("BoolFlag(tlsverify) = false on a command line that sets it")
	}
	if u.BoolFlag("tls") {
		t.Error("BoolFlag(tls) = true on a command line that never names --tls")
	}
}

// TestAnUnreadableDropInLeavesTheFactIncomplete is the property the UNKNOWN
// verdict rests on. The unit reads perfectly; a file that could have changed
// the answer did not.
func TestAnUnreadableDropInLeavesTheFactIncomplete(t *testing.T) {
	u := collectService(t, "containers-docker-service-denied")

	if !u.Judgeable() {
		t.Fatalf("state = %s, want %s: the unit itself was readable", u.State, fact.DockerUnitPresent)
	}
	if u.Complete() {
		t.Fatal("Complete = true, but a drop-in was refused")
	}
	gaps := u.Incomplete()
	if len(gaps) != 1 || gaps[0].State != fact.DockerUnitDenied {
		t.Fatalf("Incomplete = %+v, want one denied drop-in", gaps)
	}
	if !strings.HasSuffix(gaps[0].Path, "/override.conf") {
		t.Errorf("the gap is at %q, want the drop-in", gaps[0].Path)
	}
}

// TestAnUnexpandedVariableIsAnAmbiguityNotAnAbsence is the older Debian
// arrangement, where the flags live in /etc/default/docker.
//
// The collector does not read environment files — that is where a Docker
// host's proxy credentials live — so the variable survives as a token. What it
// must not do is drop it, which would render "dockerd -H fd:// $DOCKER_OPTS"
// as a command line with no options and turn an exposed host into a pass.
func TestAnUnexpandedVariableIsAnAmbiguityNotAnAbsence(t *testing.T) {
	u := collectService(t, "containers-docker-service-envvar")

	argv := u.ExecStart[0].Argv
	if got := argv[len(argv)-1]; got != "$DOCKER_OPTS" {
		t.Errorf("last argument = %q, want $DOCKER_OPTS kept verbatim", got)
	}
	amb := u.Ambiguities()
	if len(amb) != 1 {
		t.Fatalf("ambiguities = %v, want exactly one", amb)
	}
	if !strings.Contains(amb[0], "$DOCKER_OPTS") {
		t.Errorf("ambiguity %q does not name the variable it is about", amb[0])
	}
}

// TestAMaskedUnitIsNotReadAsRunning. `systemctl mask docker` links the unit to
// /dev/null and systemd then refuses to start it. The vendor unit underneath is
// intact and is not in force, so reading its ExecStart would report on a
// command line nothing runs.
func TestAMaskedUnitIsNotReadAsRunning(t *testing.T) {
	u := collectService(t, "containers-docker-service-masked")

	if got, want := u.State, fact.DockerUnitMasked; got != want {
		t.Fatalf("state = %s, want %s", got, want)
	}
	if len(u.ExecStart) != 0 {
		t.Errorf("ExecStart = %v; a masked unit's command line is not in force and must not be recorded as though it were", u.ExecStart)
	}
	if u.Judgeable() {
		t.Error("Judgeable = true for a masked unit")
	}
	if len(u.Fragments) != 1 || u.Fragments[0].Resolved != "/dev/null" {
		t.Errorf("fragments = %+v, want one resolving to /dev/null", u.Fragments)
	}
}

// TestNoUnitIsAbsentRatherThanEmpty. A host with Docker installed and no
// docker.service is a real configuration — a daemon started by hand, or by
// another init — and it must not read as a unit that binds nothing.
func TestNoUnitIsAbsentRatherThanEmpty(t *testing.T) {
	for _, name := range []string{"containers-docker-hardened", "containers-absent"} {
		u := collectService(t, name)
		if got, want := u.State, fact.DockerUnitAbsent; got != want {
			t.Errorf("%s: state = %s, want %s", name, got, want)
		}
		if len(u.ExecStart) != 0 {
			t.Errorf("%s: ExecStart = %v, want nothing", name, u.ExecStart)
		}
	}
}

// TestHostFlagSpellings covers pflag's grammar, which accepts a shorthand's
// value in three forms and a long flag's in two. All five are ways of writing
// the same exposure, and a check that recognised only "-H tcp://..." would be
// evaded by a space.
func TestHostFlagSpellings(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"dockerd", "-H", "tcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}},
		{[]string{"dockerd", "-Htcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}},
		{[]string{"dockerd", "-H=tcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}},
		{[]string{"dockerd", "--host", "tcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}},
		{[]string{"dockerd", "--host=tcp://0.0.0.0:2375"}, []string{"tcp://0.0.0.0:2375"}},
		{[]string{"dockerd", "-H", "fd://", "-H", "tcp://0.0.0.0:2375"}, []string{"fd://", "tcp://0.0.0.0:2375"}},
		// A value that looks like a flag is still the value: pflag consumes
		// the next token whatever it contains.
		{[]string{"dockerd", "-H", "--tlsverify"}, []string{"--tlsverify"}},
		// Nothing to consume. dockerd would refuse to start; inventing a value
		// would be worse than reporting none.
		{[]string{"dockerd", "-H"}, nil},
		{[]string{"dockerd", "--containerd=/run/containerd/containerd.sock"}, nil},
	}

	for _, c := range cases {
		u := fact.DockerService{ExecStart: []fact.DockerExec{{Origin: "u", Line: 1, Argv: c.argv}}}
		var got []string
		for _, h := range u.Hosts() {
			got = append(got, h.Spec)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Hosts(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

// TestClusteredShorthandIsAnAmbiguity. pflag lets shorthands cluster, so -DH
// is -D -H and the value of the -H depends on what the letters before it
// consume. This build does not unpick that, and says so rather than reading it
// wrongly in either direction.
func TestClusteredShorthandIsAnAmbiguity(t *testing.T) {
	u := fact.DockerService{ExecStart: []fact.DockerExec{
		{Origin: "u", Line: 1, Argv: []string{"dockerd", "-DH", "tcp://0.0.0.0:2375"}},
	}}
	if got := u.Hosts(); len(got) != 0 {
		t.Errorf("Hosts = %v; a clustered shorthand must not be read as a plain -H", got)
	}
	if got := u.Ambiguities(); len(got) != 1 || !strings.Contains(got[0], "-DH") {
		t.Errorf("ambiguities = %v, want one naming -DH", got)
	}
}

// TestBoolFlagReadsAnExplicitFalse. pflag booleans are true when named alone
// and take a value only in the --flag=value form, so --tlsverify=false is a
// real way to write off and reading it as on would report an unauthenticated
// socket as an authenticated one.
func TestBoolFlagReadsAnExplicitFalse(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"dockerd", "--tlsverify"}, true},
		{[]string{"dockerd", "--tlsverify=true"}, true},
		{[]string{"dockerd", "--tlsverify=false"}, false},
		{[]string{"dockerd", "--tlsverify=0"}, false},
		{[]string{"dockerd"}, false},
		// Last wins, as pflag does.
		{[]string{"dockerd", "--tlsverify", "--tlsverify=false"}, false},
		// A different flag that merely starts the same way.
		{[]string{"dockerd", "--tlsverifyx"}, false},
	}
	for _, c := range cases {
		u := fact.DockerService{ExecStart: []fact.DockerExec{{Argv: c.argv}}}
		if got := u.BoolFlag("tlsverify"); got != c.want {
			t.Errorf("BoolFlag(tlsverify) over %v = %v, want %v", c.argv, got, c.want)
		}
	}
}

// TestAbandonedScanRecordsWhyItStopped. The runner has stopped waiting, so the
// reads below would be work done on the audited host for a result nobody will
// look at.
func TestAbandonedScanRecordsWhyItStopped(t *testing.T) {
	sys, err := fake.New(filepath.Join(fixtureRoot, "containers-docker-service-tcp"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	facts := fact.NewSet()
	if err := collector.NewService().Collect(ctx, sys, facts); err != nil {
		t.Fatalf("Collect returned %v; the state belongs on the fact", err)
	}
	u, _, _ := fact.Get[fact.DockerService](facts, fact.DockerServiceID)
	if got, want := u.State, fact.DockerUnitError; got != want {
		t.Errorf("state = %s, want %s", got, want)
	}
	if u.Msg == "" {
		t.Error("no reason recorded for an abandoned collection")
	}
}

// readSpy records which seam method a collector reached for.
type readSpy struct {
	*fake.System
	readFile   []string
	readOpaque []string
}

func (s *readSpy) ReadFile(p string, max int64) (system.ReadResult, error) {
	s.readFile = append(s.readFile, p)
	return s.System.ReadFile(p, max)
}

func (s *readSpy) ReadOpaque(p string, max int64) (system.ReadResult, error) {
	s.readOpaque = append(s.readOpaque, p)
	return s.System.ReadOpaque(p, max)
}

// TestUnitBytesDoNotEnterTheBundle is a privacy assertion with teeth.
//
// collect.recordingSystem stores the bytes of everything read through ReadFile
// in the bundle's evidence store, and a bundle is written to travel. A unit
// drop-in is where a Docker host keeps Environment="HTTPS_PROXY=https://user:
// password@proxy", which is the single most common way a credential ends up in
// /etc on such a host, and this collector reads the whole file to find one
// directive in it.
//
// Reading through ReadOpaque is what keeps the rest of the file out of the
// artifact — only the ExecStart arguments reach the fact, and the digest is
// still there to cite. The exclusion holds because of the method this
// collector calls, so the method it calls is what is asserted.
func TestUnitBytesDoNotEnterTheBundle(t *testing.T) {
	base, err := fake.New(filepath.Join(fixtureRoot, "containers-docker-service-tcp"))
	if err != nil {
		t.Fatal(err)
	}
	spy := &readSpy{System: base}

	facts := fact.NewSet()
	if err := collector.NewService().Collect(context.Background(), spy, facts); err != nil {
		t.Fatal(err)
	}

	if len(spy.readFile) != 0 {
		t.Errorf("the collector read %v through ReadFile; those bytes would be stored in the bundle", spy.readFile)
	}
	for _, want := range []string{
		"/lib/systemd/system/docker.service",
		"/etc/systemd/system/docker.service.d/override.conf",
	} {
		found := false
		for _, got := range spy.readOpaque {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not read through ReadOpaque; opaque reads are %v", want, spy.readOpaque)
		}
	}

	// And the digest survives, which is the half of the trade that makes it
	// acceptable: an auditor reproduces it with sha256sum on the host, which
	// is checkable against the running system rather than against a copy.
	u, _, _ := fact.Get[fact.DockerService](facts, fact.DockerServiceID)
	for _, f := range u.Fragments {
		if f.State == fact.DockerUnitPresent && !f.Shadowed && f.Digest == "" {
			t.Errorf("%s was read and carries no digest; there is nothing left to cite", f.Path)
		}
	}
}

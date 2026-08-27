package containers_test

import (
	"context"
	"encoding/json"
	"os"
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
		t.Fatalf("state = %s (%s), want %s", u.State, u.Msg, fact.UnitPresent)
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
		t.Fatalf("state = %s, want %s: the unit itself was readable", u.State, fact.UnitPresent)
	}
	if u.Complete() {
		t.Fatal("Complete = true, but a drop-in was refused")
	}
	gaps := u.Incomplete()
	if len(gaps) != 1 || gaps[0].State != fact.UnitDenied {
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

	if got, want := u.State, fact.UnitMasked; got != want {
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
		if got, want := u.State, fact.UnitAbsent; got != want {
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
	if got, want := u.State, fact.UnitError; got != want {
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
		if f.State == fact.UnitPresent && !f.Shadowed && f.Digest == "" {
			t.Errorf("%s was read and carries no digest; there is nothing left to cite", f.Path)
		}
	}
}

// TestStringFlagSpellings.
//
// The flags CONTAINERS-0008 reads take values and have no shorthand, so the
// grammar is smaller than Hosts has to handle: pflag's "--flag value" and
// "--flag=value", last occurrence winning. What has to be right is the "set"
// return — "--log-driver=" is a value an operator can write, and dockerd
// treats it as unset, so a check that read only the string would see an empty
// driver either way and could not tell the two apart if it needed to.
func TestStringFlagSpellings(t *testing.T) {
	cases := []struct {
		argv []string
		want string
		set  bool
	}{
		{[]string{"dockerd", "--log-driver", "journald"}, "journald", true},
		{[]string{"dockerd", "--log-driver=journald"}, "journald", true},
		// Last wins, as pflag does.
		{[]string{"dockerd", "--log-driver=json-file", "--log-driver", "local"}, "local", true},
		// Written and left empty. Set, and empty.
		{[]string{"dockerd", "--log-driver="}, "", true},
		// Nothing to consume: dockerd would refuse to start and there is no
		// value to report.
		{[]string{"dockerd", "--log-driver"}, "", false},
		{[]string{"dockerd", "-H", "fd://"}, "", false},
		// A prefix is not the flag.
		{[]string{"dockerd", "--log-driver-plugin=x"}, "", false},
	}

	for _, c := range cases {
		u := fact.DockerService{ExecStart: []fact.DockerExec{{Origin: "u", Line: 1, Argv: c.argv}}}
		got, set := u.StringFlag("log-driver")
		if got != c.want || set != c.set {
			t.Errorf("StringFlag(%v) = %q/%v, want %q/%v", c.argv, got, set, c.want, c.set)
		}
	}
}

// TestARepeatedFlagKeepsEveryOccurrence.
//
// --log-opt is given once per option, so taking the last would discard every
// option but one — and the one that decides CONTAINERS-0008's verdict,
// max-size, is rarely the last one written.
func TestARepeatedFlagKeepsEveryOccurrence(t *testing.T) {
	u := fact.DockerService{ExecStart: []fact.DockerExec{{Origin: "u", Line: 1, Argv: []string{
		"dockerd", "-H", "fd://",
		"--log-opt", "max-size=10m",
		"--log-opt=max-file=3",
		"--log-opt", "tag={{.Name}}",
	}}}}

	want := []string{"max-size=10m", "max-file=3", "tag={{.Name}}"}
	if got := u.StringFlags("log-opt"); !reflect.DeepEqual(got, want) {
		t.Errorf("StringFlags = %v, want %v", got, want)
	}

	// And across fragments, in the order the effective command line has them.
	split := fact.DockerService{ExecStart: []fact.DockerExec{
		{Origin: "unit", Line: 9, Argv: []string{"dockerd", "--log-opt", "max-file=3"}},
		{Origin: "drop-in", Line: 4, Argv: []string{"dockerd", "--log-opt", "max-size=50m"}},
	}}
	if got := split.StringFlags("log-opt"); !reflect.DeepEqual(got, []string{"max-file=3", "max-size=50m"}) {
		t.Errorf("StringFlags across fragments = %v", got)
	}
}

// TestLogOptionValuesAreScrubbedFromTheCommandLine is the collector's one
// deliberate departure from recording what the file says, and the test that
// has to hold for it to be worth making.
//
// ExecStart is the only command line a bundle carries, and dockerd takes
// --log-opt on it: splunk-token is an authentication token, and it would
// otherwise travel in an artifact designed to be attached to bug reports. The
// same options written in /etc/docker/daemon.json have only ever had their key
// names recorded, so a bundle disclosing more because of which file an
// operator happened to use was an inconsistency rather than a policy.
//
// The rule is "the key is policy, the value is not", so max-size goes with
// splunk-token even though nothing about "10m" is sensitive. A scrubber that
// kept a list of bad words would be a scrubber that misses the next driver's
// credential option, and the keys are all any check needs.
func TestLogOptionValuesAreScrubbedFromTheCommandLine(t *testing.T) {
	u := collectService(t, "containers-docker-log-secret")

	if u.State != fact.UnitPresent {
		t.Fatalf("state = %s, want present: %s", u.State, u.Msg)
	}

	// The whole fact, marshalled the way a bundle would write it. Asserting on
	// Argv alone would miss a value that had reached Msg, a fragment path or a
	// digest field, and the bundle carries all of them.
	blob, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{
		"secret123",               // the credential
		"splunk.example.internal", // an internal hostname in the --flag= form
		"10m",                     // not sensitive, and still not kept
		"host logs",               // a quoted value with a space in it
	} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("a log-opt value survived into the fact: %q\n%s", secret, blob)
		}
	}

	// What must survive: every key, so a check can still read the options, and
	// an operator can still see that they configured them.
	//
	// The single-dash -log-opt is absent from this list on purpose, and the
	// gap is the design rather than an oversight. **The scrubber is permissive
	// and the reader is exact.** StringFlags models pflag, which does not
	// accept a single-dash long flag, so a check must not read a value from
	// one — but the scrubber redacts it anyway, because being wrong in the
	// permissive direction costs a token nobody reads and being wrong in the
	// other direction costs a secret. The whole-fact sweep above is what
	// proves that half; the assertion below names the token.
	opts := u.StringFlags("log-opt")
	want := []string{
		"splunk-token=[REDACTED]",
		"splunk-url=[REDACTED]",
		"splunk-index=[REDACTED]",
		"$EXTRA_LOG_OPTS",
	}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("StringFlags(log-opt) = %#v,\n                      want %#v", opts, want)
	}

	var argv []string
	for _, e := range u.ExecStart {
		argv = append(argv, e.Argv...)
	}
	if !contains(argv, "max-size=[REDACTED]") {
		t.Errorf("the single-dash spelling was not scrubbed: %v", argv)
	}

	// The flag whose value a check actually reads is untouched. Scrubbing
	// --log-driver as well would have made CONTAINERS-0008 unable to answer
	// its own question, which is the line between an opaque flag and a
	// modelled one.
	if v, set := u.StringFlag("log-driver"); !set || v != "splunk" {
		t.Errorf("StringFlag(log-driver) = %q/%v, want splunk/true", v, set)
	}

	// And so is everything else on the line.
	if got := specs(u); !reflect.DeepEqual(got, []string{"fd://"}) {
		t.Errorf("the socket bindings were disturbed: %v", got)
	}
}

// TestAnUnexpandedVariableIsNotAValueToScrub.
//
// systemd expands $EXTRA_LOG_OPTS into however many words it holds, so an
// unexpanded one is a reason the command line cannot be claimed to have been
// read in full — which is what Ambiguities reports and what CONTAINERS-0006
// turns into UNKNOWN rather than a pass. Redacting the token would have
// removed the "$" that signals it, quietly converting "I could not read this"
// into "there was nothing here".
//
// It costs no disclosure to keep: a variable reference is a name, and the
// value it refers to lives in the EnvironmentFile this collector does not read.
func TestAnUnexpandedVariableIsNotAValueToScrub(t *testing.T) {
	u := collectService(t, "containers-docker-log-secret")

	found := false
	for _, a := range u.Ambiguities() {
		if strings.Contains(a, "$EXTRA_LOG_OPTS") {
			found = true
		}
	}
	if !found {
		t.Errorf("the scrubber swallowed the ambiguity: %v", u.Ambiguities())
	}
}

// TestEverySpellingOfAnOpaqueFlagIsScrubbed.
//
// pflag takes a long flag's value in two forms and dockerd's own documentation
// uses both. The single-dash long form is not one pflag accepts, and it is
// handled anyway: being wrong in the permissive direction costs a redacted
// token that was never a flag, and being wrong in the other direction costs a
// secret.
//
// The negative cases are the other half. A flag that merely starts with the
// same letters is a different flag, and the token after an opaque flag is its
// value rather than a general licence to redact the next thing on the line.
func TestEverySpellingOfAnOpaqueFlagIsScrubbed(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{
			[]string{"dockerd", "--log-opt", "splunk-token=abc"},
			[]string{"dockerd", "--log-opt", "splunk-token=[REDACTED]"},
		},
		{
			[]string{"dockerd", "--log-opt=splunk-token=abc"},
			[]string{"dockerd", "--log-opt=splunk-token=[REDACTED]"},
		},
		{
			[]string{"dockerd", "-log-opt", "splunk-token=abc"},
			[]string{"dockerd", "-log-opt", "splunk-token=[REDACTED]"},
		},
		{
			[]string{"dockerd", "-log-opt=splunk-token=abc"},
			[]string{"dockerd", "-log-opt=splunk-token=[REDACTED]"},
		},
		// A value containing an "=" of its own: the split is on the first one,
		// so the key survives and everything after it does not.
		{
			[]string{"dockerd", "--log-opt", "tag=a=b=c"},
			[]string{"dockerd", "--log-opt", "tag=[REDACTED]"},
		},
		// A "$" inside a value is still a value. Only a token that is nothing
		// but a variable reference is kept.
		{
			[]string{"dockerd", "--log-opt", "splunk-token=a$b"},
			[]string{"dockerd", "--log-opt", "splunk-token=[REDACTED]"},
		},
		// No "=" and no "$": there is no key to keep, so all of it goes.
		{
			[]string{"dockerd", "--log-opt", "nonsense"},
			[]string{"dockerd", "--log-opt", "[REDACTED]"},
		},
		// A trailing flag has no value to scrub, and inventing one would be
		// worse than reporting none.
		{
			[]string{"dockerd", "--log-opt"},
			[]string{"dockerd", "--log-opt"},
		},
		// Not this flag. --log-driver's value is read by CONTAINERS-0008 and
		// --log-opts is not a dockerd flag at all.
		{
			[]string{"dockerd", "--log-driver", "journald"},
			[]string{"dockerd", "--log-driver", "journald"},
		},
		{
			[]string{"dockerd", "--log-opt-extra", "keep=me"},
			[]string{"dockerd", "--log-opt-extra", "keep=me"},
		},
		// The token after a scrubbed pair is an ordinary argument again.
		{
			[]string{"dockerd", "--log-opt", "max-size=10m", "-H", "tcp://0.0.0.0:2375"},
			[]string{"dockerd", "--log-opt", "max-size=[REDACTED]", "-H", "tcp://0.0.0.0:2375"},
		},
	}

	for _, c := range cases {
		got := scrubThroughCollector(t, c.argv)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("scrub(%v)\n = %v\nwant %v", c.argv, got, c.want)
		}
	}
}

// scrubThroughCollector runs one command line through the real collector by
// writing it into a unit file, because the scrubber is unexported and the
// thing worth testing is that it is wired into the path a fact takes rather
// than that a function works.
func scrubThroughCollector(t *testing.T, argv []string) []string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, "lib", "systemd", "system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	unit := "[Service]\nExecStart=" + strings.Join(argv, " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker.service"), []byte(unit), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "_plumbline"), 0o755); err != nil {
		t.Fatalf("mkdir manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "_plumbline", "fixture.json"),
		[]byte(`{"description":"one hand-built command line"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	sys, err := fake.New(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	facts := fact.NewSet()
	if err := collector.NewService().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect: %v", err)
	}
	u, _, ok := fact.Get[fact.DockerService](facts, fact.DockerServiceID)
	if !ok || len(u.ExecStart) != 1 {
		t.Fatalf("expected one ExecStart, got %+v", u)
	}
	return u.ExecStart[0].Argv
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

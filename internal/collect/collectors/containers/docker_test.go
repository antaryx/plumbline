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
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collectFixture(t *testing.T, name string) fact.DockerDaemon {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect fixture %s: %v", name, err)
	}
	d, ferr, ok := fact.Get[fact.DockerDaemon](facts, fact.DockerDaemonID)
	if !ok {
		t.Fatalf("containers.docker_daemon missing after collection: %v", ferr)
	}
	return d
}

// TestCollectorContract asserts the declarations the runner schedules on.
func TestCollectorContract(t *testing.T) {
	c := collector.New()

	if got, want := c.ID(), "containers"; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}
	if got := c.Produces(); len(got) != 1 || got[0] != fact.DockerDaemonID {
		t.Errorf("Produces = %v, want [%s]", got, fact.DockerDaemonID)
	}
	if got := c.DependsOn(); len(got) != 0 {
		t.Errorf("DependsOn = %v, want nothing", got)
	}
	if got, want := c.Cost(), collect.Cheap; got != want {
		t.Errorf("Cost = %v, want %v", got, want)
	}
	// CapNone deliberately: daemon.json is 0644 on a stock installation, and an
	// unprivileged run must record that it was refused rather than be skipped.
	if got, want := c.Requires(), collect.CapNone; got != want {
		t.Errorf("Requires = %v, want %v", got, want)
	}
	if c.Timeout() <= 0 || c.Timeout() > time.Minute {
		t.Errorf("Timeout = %v; the collector must declare a budget it can justify", c.Timeout())
	}
	if _, ok := collect.Default().Get("containers"); !ok {
		t.Errorf("the containers collector did not register itself; the registry holds %v", collect.Default().IDs())
	}
}

// TestParsesAHardenedConfiguration is the collector's reason to exist: every
// modelled option read back as written.
func TestParsesAHardenedConfiguration(t *testing.T) {
	d := collectFixture(t, "containers-docker-hardened")

	if !d.Parsed() {
		t.Fatalf("state = %s (%s), want %s", d.State, d.Msg, fact.DockerConfigPresent)
	}
	if !d.Installed || d.DaemonPath != "/usr/bin/dockerd" {
		t.Errorf("installed = %v at %q, want true at /usr/bin/dockerd", d.Installed, d.DaemonPath)
	}
	if d.Digest == "" {
		t.Error("no digest recorded; a finding could not cite the document it read")
	}
	if d.UsernsRemap != "default" {
		t.Errorf("UsernsRemap = %q, want %q", d.UsernsRemap, "default")
	}
	if d.LogDriver != "journald" {
		t.Errorf("LogDriver = %q, want %q", d.LogDriver, "journald")
	}

	for _, c := range []struct {
		name string
		got  *bool
		want bool
	}{
		{"icc", d.ICC, false},
		{"experimental", d.Experimental, false},
		{"live-restore", d.LiveRestore, true},
		{"no-new-privileges", d.NoNewPrivileges, true},
	} {
		v, set := fact.OptBool(c.got)
		if !set {
			t.Errorf("%s was not recorded as set, though the document sets it", c.name)
			continue
		}
		if v != c.want {
			t.Errorf("%s = %v, want %v", c.name, v, c.want)
		}
	}

	if want := []string{"unix:///var/run/docker.sock"}; !reflect.DeepEqual(d.Hosts, want) {
		t.Errorf("Hosts = %v, want %v", d.Hosts, want)
	}
}

// TestAbsentKeyIsNotAFalseKey is the reason the booleans are pointers.
//
// Docker's defaults are not all false: icc defaults to *on*. A plain bool would
// have turned "the operator never wrote this" into "inter-container
// communication is off", which is the opposite of what the daemon does and
// would report an open network as closed.
func TestAbsentKeyIsNotAFalseKey(t *testing.T) {
	d := collectFixture(t, "containers-docker-permissive")

	if !d.Parsed() {
		t.Fatalf("state = %s (%s)", d.State, d.Msg)
	}

	// Set in the document, and set to true.
	if v, set := fact.OptBool(d.ICC); !set || !v {
		t.Errorf("icc = (%v, set=%v), want (true, set=true)", v, set)
	}
	// Not in the document at all. Both returns are false, and only the second
	// distinguishes this from an explicit "no-new-privileges": false.
	if v, set := fact.OptBool(d.NoNewPrivileges); set || v {
		t.Errorf("no-new-privileges = (%v, set=%v), want (false, set=false) for an absent key", v, set)
	}
	if d.HasKey("no-new-privileges") {
		t.Error("HasKey reports a key the document does not contain")
	}
	if !d.HasKey("icc") {
		t.Error("HasKey does not report a key the document does contain")
	}
	// The daemon's own default for the absent key is the check's business, not
	// the collector's: the fact records what the file says.
	if d.LogDriver != "" {
		t.Errorf("LogDriver = %q, want empty; the collector must not substitute Docker's default", d.LogDriver)
	}
}

// TestUnmodelledKeysAreNamedAndNotCarried. daemon.json holds registry mirrors,
// proxy URLs and storage paths, and a bundle is written to travel. Recording an
// option this build does not model by *name* lets a check tell "the operator
// did not set this" from "this build does not know that option", without the
// values reaching the archive.
func TestUnmodelledKeysAreNamedAndNotCarried(t *testing.T) {
	d := collectFixture(t, "containers-docker-permissive")

	for _, k := range []string{"registry-mirrors", "insecure-registries"} {
		if !d.HasKey(k) {
			t.Errorf("Keys omits %q, which the document sets", k)
		}
	}
	// Keys are sorted, so two collections of an unchanged host produce
	// byte-identical facts.
	if !sortedStrings(d.Keys) {
		t.Errorf("Keys is not sorted: %v", d.Keys)
	}

	// Nothing in the fact carries the values of the options above.
	for _, field := range []string{d.UsernsRemap, d.LogDriver, strings.Join(d.Hosts, " ")} {
		for _, secret := range []string{"mirror.example.internal", "registry.example.internal"} {
			if strings.Contains(field, secret) {
				t.Errorf("a value from an unmodelled option reached the fact: %q", field)
			}
		}
	}
}

// TestMalformedConfigurationIsNeverReadAsDefaults is the module's central
// collector property.
//
// A JSON document has no partial meaning: one stray comma and dockerd refuses
// to start, so the daemon is running the last configuration that parsed or is
// not running at all. Recording such a file as "no options set" would hand a
// check the compiled-in defaults for a host whose actual configuration is
// unknown, which is the false assurance CONTRIBUTING.md rule 3 forbids.
func TestMalformedConfigurationIsNeverReadAsDefaults(t *testing.T) {
	cases := []struct {
		fixture string
		why     string
	}{
		{"containers-docker-malformed", "a trailing comma"},
		{"containers-docker-wrongtype", "a string where a boolean belongs"},
		{"containers-docker-notobject", "an array rather than an object"},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			d := collectFixture(t, c.fixture)

			if d.State != fact.DockerConfigMalformed {
				t.Fatalf("state = %s, want %s (%s)", d.State, fact.DockerConfigMalformed, c.why)
			}
			if d.Parsed() {
				t.Error("Parsed() is true for a document the daemon would reject")
			}
			if d.Msg == "" {
				t.Error("no message recorded; an operator cannot act on 'malformed'")
			}
			// The digest is still recorded: the bytes were read, and a finding
			// should cite the document it refused to trust.
			if d.Digest == "" {
				t.Error("no digest recorded for a file that was read")
			}
			// No modelled value may survive a failed parse. The wrongtype
			// fixture sets log-driver validly beside the bad icc, and reading
			// it would be reading half a configuration the daemon rejected
			// whole.
			if d.LogDriver != "" || d.ICC != nil || len(d.Keys) != 0 {
				t.Errorf("a rejected document yielded values: LogDriver=%q ICC=%v Keys=%v",
					d.LogDriver, d.ICC, d.Keys)
			}
			// Docker is still installed, which is what stops a check reading
			// this as "no container runtime here".
			if !d.Configurable() {
				t.Error("Configurable() is false, though dockerd is present")
			}
		})
	}
}

// TestMissingConfigurationIsNotMissingDocker is the distinction the whole fact
// is shaped around, and the one a scaffold gets wrong.
//
// Both fixtures have no daemon.json. One has dockerd and one does not, and they
// are opposite verdicts: a daemon running on its compiled-in defaults is a
// configuration worth judging — icc is on, userns-remap is off — while a host
// with no Docker has removed the subject of the sentence. A collector that
// reported only "the file is absent" would force every check to pick one of
// those meanings and be wrong on the other half of the fleet.
func TestMissingConfigurationIsNotMissingDocker(t *testing.T) {
	running := collectFixture(t, "containers-docker-defaults")
	none := collectFixture(t, "containers-absent")

	if running.State != fact.DockerConfigAbsent || none.State != fact.DockerConfigAbsent {
		t.Fatalf("states differ (%s, %s); the comparison below proves nothing",
			running.State, none.State)
	}

	if !running.Configurable() {
		t.Error("a host with dockerd and no daemon.json is not reported as having Docker")
	}
	if none.Configurable() {
		t.Error("a host with no dockerd is reported as having Docker")
	}
	if running.DaemonPath == "" {
		t.Error("no daemon path recorded; a finding could not say what it found")
	}

	// Neither carries a digest or a message: there was no file to read, which
	// is not an error and must not be recorded as one.
	for _, d := range []fact.DockerDaemon{running, none} {
		if d.Digest != "" {
			t.Errorf("a digest was recorded for a file that does not exist: %q", d.Digest)
		}
		if d.Msg != "" {
			t.Errorf("an absent configuration recorded a failure message: %q", d.Msg)
		}
	}
	// The path is recorded either way, so a finding can name where it looked.
	if running.Path != collector.DaemonConfigPath {
		t.Errorf("Path = %q, want %q", running.Path, collector.DaemonConfigPath)
	}
}

// TestUnreadableConfigurationIsNotAnAbsentOne. An unprivileged scan that cannot
// open daemon.json knows nothing about the daemon's configuration, and the file
// it could not read is the hardened one. Recording it as absent would report a
// hardened host as running on defaults.
func TestUnreadableConfigurationIsNotAnAbsentOne(t *testing.T) {
	d := collectFixture(t, "containers-docker-denied")

	if d.State != fact.DockerConfigDenied {
		t.Fatalf("state = %s, want %s", d.State, fact.DockerConfigDenied)
	}
	if d.Parsed() {
		t.Error("Parsed() is true for a file that was never opened")
	}
	if !d.Configurable() {
		t.Error("Configurable() is false, though dockerd is present")
	}
	if d.Msg == "" {
		t.Error("no message recorded for a refused read")
	}
}

// TestCollectAlwaysProducesTheFact. Every path through Collect writes the fact,
// including the ones that failed, because "we could not read the Docker
// configuration" is an observation a check needs rather than a reason to
// produce nothing. A missing fact resolves to UNKNOWN(fact_not_collected),
// which is true but says less than the state would have.
func TestCollectAlwaysProducesTheFact(t *testing.T) {
	for _, name := range []string{
		"containers-docker-hardened", "containers-docker-permissive",
		"containers-docker-malformed", "containers-docker-wrongtype",
		"containers-docker-notobject", "containers-docker-defaults",
		"containers-absent", "containers-docker-denied",
	} {
		t.Run(name, func(t *testing.T) {
			d := collectFixture(t, name) // fails the test if the fact is absent
			if d.State == "" {
				t.Error("the fact was produced with no state at all")
			}
			if d.Path == "" {
				t.Error("the fact does not record where it looked")
			}
		})
	}
}

// TestCancelledContextStillRecordsWhatItKnows. The runner abandons a collector
// that outruns its budget. The fact is still written, so a check learns that
// the configuration was not read rather than that Docker is absent.
func TestCancelledContextStillRecordsWhatItKnows(t *testing.T) {
	sys, err := fake.New(filepath.Join(fixtureRoot, "containers-docker-hardened"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	facts := fact.NewSet()
	if err := collector.New().Collect(ctx, sys, facts); err != nil {
		t.Fatalf("collect: %v", err)
	}
	d, _, ok := fact.Get[fact.DockerDaemon](facts, fact.DockerDaemonID)
	if !ok {
		t.Fatal("containers.docker_daemon missing; an abandoned collector must still record what it saw")
	}
	if d.Parsed() {
		t.Error("Parsed() is true after the scan was abandoned before the read")
	}
	if d.State != fact.DockerConfigError || d.Msg == "" {
		t.Errorf("state = %s (%s), want an error state that says why", d.State, d.Msg)
	}
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

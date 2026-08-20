package profile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/profile"
)

func parse(t *testing.T, body string) *profile.Profile {
	t.Helper()
	p, err := profile.Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// the built-ins
// ---------------------------------------------------------------------------

// TestEveryBuiltinParses. The embedded profiles go through the same Parse a
// user's file does, so a built-in that could not be parsed by the public parser
// would be a second undocumented format. This test is what keeps that true.
func TestEveryBuiltinParses(t *testing.T) {
	builtins := profile.Builtins()
	if len(builtins) < 2 {
		t.Fatalf("expected at least the default and cis-l1 profiles, got %d", len(builtins))
	}
	seen := map[string]bool{}
	for _, p := range builtins {
		if !p.Builtin() {
			t.Errorf("%s is not marked as built-in", p.ID)
		}
		if seen[p.ID] {
			t.Errorf("two built-in profiles share the id %q", p.ID)
		}
		seen[p.ID] = true
		if p.Title == "" {
			t.Errorf("%s has no title", p.ID)
		}
	}
	if !seen[profile.DefaultID] {
		t.Errorf("there is no %q profile", profile.DefaultID)
	}
	if !seen["cis-l1"] {
		t.Error("there is no cis-l1 profile")
	}
}

// TestDefaultIsTheWholeCatalog. "No --profile" and "--profile default" must not
// diverge, which is why default is a real profile rather than a nil check.
func TestDefaultIsTheWholeCatalog(t *testing.T) {
	p, ok := profile.Builtin(profile.DefaultID)
	if !ok {
		t.Fatal("no default profile")
	}
	for _, id := range []string{"SSHD-0002", "FILESYS-0010", "ANYTHING-9999"} {
		if !p.Includes(id) {
			t.Errorf("default excludes %s", id)
		}
	}
	// And a nil profile behaves identically.
	var nilProfile *profile.Profile
	if !nilProfile.Includes("SSHD-0002") || nilProfile.Name() != profile.DefaultID {
		t.Error("a nil profile does not behave as the default")
	}
}

// TestCisL1IsNarrowerThanDefault, and says what it is not.
//
// The description is asserted because the honesty of this profile is the
// feature. No check in the catalog carries a CIS mapping, so the selection is
// this project's reading rather than a correspondence to numbered
// recommendations — and a profile named cis-l1 that did not say so would be
// making a compliance claim the data does not support.
func TestCisL1IsNarrowerThanDefault(t *testing.T) {
	p, ok := profile.Builtin("cis-l1")
	if !ok {
		t.Fatal("no cis-l1 profile")
	}
	if p.Includes("SSHD-0009") {
		t.Error("cis-l1 does not apply its own exclusions")
	}
	if !p.Includes("SSHD-0002") {
		t.Error("cis-l1 excludes a check it should carry")
	}
	if p.Includes("SERVICES-0001") {
		t.Error("cis-l1 includes a module it does not name")
	}
	for _, want := range []string{"NOT a CIS benchmark", "not evidence of compliance"} {
		if !strings.Contains(p.Description, want) {
			t.Errorf("the cis-l1 description does not say %q; a profile named for a benchmark "+
				"it has not been verified against must say so", want)
		}
	}
}

// ---------------------------------------------------------------------------
// matching
// ---------------------------------------------------------------------------

func TestWildcardMatching(t *testing.T) {
	p := parse(t, `{"schema":"profile/v1","id":"t","title":"t",
		"included_checks":["SSHD-*","USERS-0001"],
		"excluded_checks":["SSHD-0009"]}`)

	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"SSHD-0002", true},
		{"SSHD-0009", false}, // excluded wins over the module wildcard
		{"USERS-0001", true},
		{"USERS-0002", false}, // included by name only
		{"CRON-0001", false},
	} {
		if got := p.Includes(tc.id); got != tc.want {
			t.Errorf("Includes(%s) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// TestExcludedWinsOverIncluded, stated on its own because the precedence is the
// thing an operator writing a profile has to be able to rely on.
func TestExcludedWinsOverIncluded(t *testing.T) {
	p := parse(t, `{"schema":"profile/v1","id":"t","title":"t",
		"included_checks":["*"],"excluded_checks":["*"]}`)
	if p.Includes("SSHD-0002") {
		t.Error("an exclusion did not win over an inclusion")
	}
}

func TestCountScalesWithTheProfile(t *testing.T) {
	all := []string{"SSHD-0001", "SSHD-0002", "CRON-0001", "USERS-0001"}
	p := parse(t, `{"schema":"profile/v1","id":"t","title":"t","included_checks":["SSHD-*"]}`)
	if got := p.Count(all); got != 2 {
		t.Errorf("Count = %d, want 2", got)
	}
	var nilProfile *profile.Profile
	if got := nilProfile.Count(all); got != len(all) {
		t.Errorf("a nil profile counted %d of %d", got, len(all))
	}
}

// ---------------------------------------------------------------------------
// severity overrides
// ---------------------------------------------------------------------------

func TestSeverityOverride(t *testing.T) {
	p := parse(t, `{"schema":"profile/v1","id":"t","title":"t","included_checks":["*"],
		"severity_overrides":{"CRON-0005":"LOW"}}`)

	got, ok := p.SeverityFor("CRON-0005")
	if !ok || got != finding.Low {
		t.Errorf("SeverityFor = %q,%v; want LOW,true", got, ok)
	}
	if _, ok := p.SeverityFor("SSHD-0002"); ok {
		t.Error("a check with no override reported one")
	}
	var nilProfile *profile.Profile
	if _, ok := nilProfile.SeverityFor("CRON-0005"); ok {
		t.Error("a nil profile reported an override")
	}
}

// ---------------------------------------------------------------------------
// what the parser refuses
// ---------------------------------------------------------------------------

// TestTheParserRefusesAnythingAmbiguous. Every case here is a way a profile
// could quietly scope a scan to something other than what its author meant,
// and a scan scoped wrongly reports a posture for a host nobody audited.
func TestTheParserRefusesAnythingAmbiguous(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"the wrong schema", `{"schema":"profile/v2","id":"t","title":"t","included_checks":["*"]}`, "this build understands"},
		{"no schema", `{"id":"t","title":"t","included_checks":["*"]}`, "this build understands"},
		{"no id", `{"schema":"profile/v1","title":"t","included_checks":["*"]}`, "no id"},
		{"no title", `{"schema":"profile/v1","id":"t","included_checks":["*"]}`, "no title"},
		{"no includes", `{"schema":"profile/v1","id":"t","title":"t","included_checks":[]}`, "includes no checks"},
		{"missing includes", `{"schema":"profile/v1","id":"t","title":"t"}`, "includes no checks"},
		{"a misspelled key", `{"schema":"profile/v1","id":"t","title":"t","included_check":["*"]}`, "unknown field"},
		{"a bad pattern", `{"schema":"profile/v1","id":"t","title":"t","included_checks":["SSHD-[0"]}`, "not a valid pattern"},
		{"a bogus severity", `{"schema":"profile/v1","id":"t","title":"t","included_checks":["*"],"severity_overrides":{"A-1":"SPICY"}}`, "want one of"},
		{"a pattern as an override key", `{"schema":"profile/v1","id":"t","title":"t","included_checks":["*"],"severity_overrides":{"SSHD-*":"LOW"}}`, "looks like a pattern"},
		{"not JSON", `{`, "not valid JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := profile.Parse([]byte(tc.body))
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem (%q)", err, tc.want)
			}
		})
	}
}

// TestBuiltinsAreOrderedWithDefaultFirst. `plumbline profiles` prints this
// order, and the one an operator is already using belongs at the top.
func TestBuiltinsAreOrderedWithDefaultFirst(t *testing.T) {
	ids := profile.BuiltinIDs()
	if len(ids) == 0 || ids[0] != profile.DefaultID {
		t.Errorf("BuiltinIDs = %v; default must come first", ids)
	}
	if fmt.Sprint(ids) != fmt.Sprint(profile.BuiltinIDs()) {
		t.Error("BuiltinIDs is not stable between calls")
	}
}

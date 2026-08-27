package unit_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/antaryx/plumbline/internal/collect/unit"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// assemble writes a unit tree into a temporary root and assembles it, so the
// tests below exercise the real seam rather than a parser in isolation.
//
// files maps a path under the root to its contents. Directories are created as
// needed.
func assemble(t *testing.T, files map[string]string, req unit.Request) unit.Unit {
	t.Helper()

	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "_plumbline"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "_plumbline", "fixture.json"),
		[]byte(`{"description":"a unit tree built by a test"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	sys, err := fake.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return unit.Assemble(sys, req)
}

const vendor = "usr/lib/systemd/system"

// TestPrecedenceIsFirstFoundWins. A unit file in a higher-precedence directory
// *replaces* the one below it — it does not merge with it — which is the
// difference between a unit file and a drop-in and is easy to implement
// backwards.
func TestPrecedenceIsFirstFoundWins(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service":          "[Service]\nA=vendor\nB=vendor\n",
		"etc/systemd/system/x.service": "[Service]\nA=admin\n",
		"run/systemd/system/x.service": "[Service]\nA=runtime\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A", "B"}})

	if u.Path != "/etc/systemd/system/x.service" {
		t.Errorf("Path = %q, want the admin copy", u.Path)
	}
	if d, ok := u.Last("A"); !ok || d.Value != "admin" {
		t.Errorf("A = %q/%v, want admin", d.Value, ok)
	}
	// B exists only in the vendor file, which was replaced rather than merged.
	// A merging implementation would surface it and be wrong about the host.
	if d, ok := u.Last("B"); ok {
		t.Errorf("B = %q, want unset: the vendor unit was replaced, not merged", d.Value)
	}
}

// TestDropInsApplyInLexicalOrderAcrossRoots. The order is by *filename* across
// every directory together, not by directory precedence — so a 10- file from
// /usr/lib is applied before a 20- file from /etc even though /etc outranks it.
func TestDropInsApplyInLexicalOrderAcrossRoots(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service":                          "[Service]\nA=base\n",
		vendor + "/x.service.d/20-vendor.conf":         "[Service]\nA=twenty\n",
		"etc/systemd/system/x.service.d/10-admin.conf": "[Service]\nA=ten\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A"}})

	var got []string
	for _, d := range u.Directives {
		got = append(got, d.Value)
	}
	if !reflect.DeepEqual(got, []string{"base", "ten", "twenty"}) {
		t.Errorf("application order = %v, want [base ten twenty]", got)
	}
	if d, _ := u.Last("A"); d.Value != "twenty" {
		t.Errorf("last value = %q, want twenty", d.Value)
	}
}

// TestASharedBasenameDiscardsTheLowerFileEntirely.
//
// systemd identifies a drop-in by its basename, not its path. 50-x.conf in
// /etc causes 50-x.conf in /usr/lib to be ignored *completely* — not merged,
// not applied first — which is how an administrator neutralises a vendor
// drop-in without editing a file they do not own.
func TestASharedBasenameDiscardsTheLowerFileEntirely(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service":                      "[Service]\n",
		vendor + "/x.service.d/50-h.conf":          "[Service]\nA=vendor\nB=vendor-only\n",
		"etc/systemd/system/x.service.d/50-h.conf": "[Service]\nA=admin\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A", "B"}})

	if d, ok := u.Last("A"); !ok || d.Value != "admin" {
		t.Errorf("A = %q/%v, want admin", d.Value, ok)
	}
	// B is only in the shadowed file. If it appears, the loser was merged.
	if d, ok := u.Last("B"); ok {
		t.Errorf("B = %q, want unset: the shadowed drop-in must not be applied at all", d.Value)
	}

	// The loser is recorded rather than dropped: a file somebody edited and
	// systemd never read is a mistake worth being able to see.
	var shadowed int
	for _, f := range u.Fragments {
		if f.Shadowed {
			shadowed++
			if f.ShadowedBy != "/etc/systemd/system/x.service.d/50-h.conf" {
				t.Errorf("ShadowedBy = %q", f.ShadowedBy)
			}
		}
	}
	if shadowed != 1 {
		t.Errorf("recorded %d shadowed fragments, want 1", shadowed)
	}
	// And it is not counted as unread: systemd would not have applied it, so
	// not reading it changes nothing.
	if !u.Complete() {
		t.Errorf("a shadowed drop-in made the unit incomplete: %+v", u.Incomplete())
	}
}

// TestListAndLastFoldDifferently is why both exist.
//
// systemd has two kinds of setting and the same syntax for each. A list-valued
// one accumulates and is cleared by a bare assignment; a scalar one is
// overwritten and a bare assignment restores its default. Reading ExecStart
// with Last would silently discard every command but the last; reading
// NoNewPrivileges with List would report a setting the operator cleared.
func TestListAndLastFoldDifferently(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service":             "[Service]\nA=one\nA=two\n",
		vendor + "/x.service.d/10-a.conf": "[Service]\nA=three\n",
	}, unit.Request{Name: "x.service", Section: "Section-does-not-match"})

	// Nothing requested and the wrong section: both filters are live.
	if len(u.Directives) != 0 {
		t.Fatalf("directives leaked past the filters: %+v", u.Directives)
	}

	u = assemble(t, map[string]string{
		vendor + "/x.service":             "[Service]\nA=one\nA=two\n",
		vendor + "/x.service.d/10-a.conf": "[Service]\nA=three\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A"}})

	var list []string
	for _, d := range u.List("A") {
		list = append(list, d.Value)
	}
	if !reflect.DeepEqual(list, []string{"one", "two", "three"}) {
		t.Errorf("List = %v, want all three", list)
	}
	if d, ok := u.Last("A"); !ok || d.Value != "three" {
		t.Errorf("Last = %q/%v, want three", d.Value, ok)
	}
}

// TestABareAssignmentResets, in both folds. It clears the list for List, and
// for Last it restores the default — which is reported as "not set" rather
// than as an empty value, because those are what an operator means by them.
func TestABareAssignmentResets(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service":             "[Service]\nA=one\nA=two\n",
		vendor + "/x.service.d/10-a.conf": "[Service]\nA=\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A"}})

	if got := u.List("A"); len(got) != 0 {
		t.Errorf("List after a reset = %+v, want empty", got)
	}
	if d, ok := u.Last("A"); ok {
		t.Errorf("Last after a reset = %q/set=true, want not set", d.Value)
	}

	// And a value after the reset survives it, which is the shape every
	// documented Docker override uses.
	u = assemble(t, map[string]string{
		vendor + "/x.service":             "[Service]\nA=one\n",
		vendor + "/x.service.d/10-a.conf": "[Service]\nA=\nA=after\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A"}})

	var list []string
	for _, d := range u.List("A") {
		list = append(list, d.Value)
	}
	if !reflect.DeepEqual(list, []string{"after"}) {
		t.Errorf("List = %v, want [after]", list)
	}
}

// TestOnlyRequestedDirectivesAreHeld is the privacy boundary, asserted at the
// level it is enforced.
//
// The filter runs during the parse, so a directive nobody asked for is never
// held — which is what lets two collectors read unit bodies without a bundle
// carrying Environment= assignments. A filter applied by the caller afterwards
// would be one a later caller could forget.
func TestOnlyRequestedDirectivesAreHeld(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service": "[Unit]\nDescription=secret-description\n" +
			"[Service]\nEnvironment=\"TOKEN=hunter2\"\nEnvironmentFile=/etc/secrets\n" +
			"ExecStart=/bin/true\nNoNewPrivileges=yes\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"NoNewPrivileges"}})

	if len(u.Directives) != 1 || u.Directives[0].Name != "NoNewPrivileges" {
		t.Fatalf("held more than was asked for: %+v", u.Directives)
	}
	for _, d := range u.Directives {
		if d.Value != "yes" {
			t.Errorf("value = %q", d.Value)
		}
	}
}

// TestCommentsAndContinuationsAreNotDirectives. A commented-out directive that
// continues onto a second line must not have its second line read as live —
// the bug that turns documentation in a unit file into a finding.
func TestCommentsAndContinuationsAreNotDirectives(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/x.service": "[Service]\n" +
			"# A=commented \\\n" +
			"A=still-part-of-the-comment\n" +
			"A=real \\\n" +
			"    continued\n" +
			"; B=semicolon comment\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A", "B"}})

	var got []string
	for _, d := range u.List("A") {
		got = append(got, d.Value)
	}
	if !reflect.DeepEqual(got, []string{"real continued"}) {
		t.Errorf("A = %v, want [\"real continued\"]", got)
	}
	if _, ok := u.Last("B"); ok {
		t.Error("a semicolon comment was read as a directive")
	}
}

// TestAMissingUnitNamesWhereItLooked. A reader told only that nothing was
// found does not know what was looked for, and "absent" is a verdict an
// operator may want to disagree with.
func TestAMissingUnitNamesWhereItLooked(t *testing.T) {
	u := assemble(t, map[string]string{
		vendor + "/other.service": "[Service]\n",
	}, unit.Request{Name: "x.service", Section: "Service", Directives: []string{"A"}})

	if u.State != fact.UnitAbsent {
		t.Errorf("State = %s, want absent", u.State)
	}
	if u.Path == "" {
		t.Error("an absent unit does not say where it was looked for")
	}
	if u.Judgeable() {
		t.Error("an absent unit reports as judgeable")
	}
}

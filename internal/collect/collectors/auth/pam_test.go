package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/auth"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

const fixtureRoot = "../../../../testdata/fixtures"

func collect(t *testing.T, name string) fact.PAM {
	t.Helper()

	sys, err := fake.New(filepath.Join(fixtureRoot, name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("collect %s: %v", name, err)
	}
	p, ferr, ok := fact.Get[fact.PAM](facts, fact.PAMID)
	if !ok || ferr != nil {
		t.Fatalf("fact missing from %s: ok=%v err=%v", name, ok, ferr)
	}
	return p
}

// TestLayoutIsDetectedFromWhatIsThere: the two families keep the same rules in
// differently named files, and the layout is what tells a check which files
// hold the answer. Both families' names are always probed, so the detection
// cannot become an unfalsifiable guess.
func TestLayoutIsDetectedFromWhatIsThere(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    fact.Layout
	}{
		{"auth-rhel", fact.LayoutRedHat},
		{"auth-debian", fact.LayoutDebian},
		{"auth-absent", fact.LayoutNone},
	} {
		if got := collect(t, tc.fixture).Layout(); got != tc.want {
			t.Errorf("%s: layout = %s, want %s", tc.fixture, got, tc.want)
		}
	}
}

// TestAtIncludePullsInEveryManagementGroup.
//
// Debian's sshd stack is five lines and enforces the whole policy, because
// @include inlines the entire file rather than one type. A collector that
// treated it as type-scoped would drop three quarters of the host's rules and
// then report that nothing is configured.
func TestAtIncludePullsInEveryManagementGroup(t *testing.T) {
	p := collect(t, "auth-debian")
	sshd, ok := p.Service("sshd")
	if !ok || sshd.State != fact.FilePresent {
		t.Fatal("sshd stack not read")
	}

	seen := map[fact.PAMType]bool{}
	for _, l := range sshd.Lines {
		seen[l.Type] = true
	}
	for _, want := range []fact.PAMType{fact.PAMAuth, fact.PAMAccount, fact.PAMPassword, fact.PAMSession} {
		if !seen[want] {
			t.Errorf("no %s rule reached the sshd stack; @include was treated as type-scoped", want)
		}
	}
	if !sshd.Complete() {
		t.Errorf("sshd stack is incomplete: %v", sshd.Unresolved)
	}
}

// TestTypeScopedIncludeDoesNotWiden: `auth substack password-auth` must
// contribute auth rules and nothing else. Importing the included file's
// password rules into the auth stack would let a check searching `auth` find a
// pam_pwquality that only ever runs when a password is set.
func TestTypeScopedIncludeDoesNotWiden(t *testing.T) {
	p := collect(t, "auth-rhel")
	sshd, ok := p.Service("sshd")
	if !ok {
		t.Fatal("sshd stack not read")
	}

	// The sshd fixture has `auth substack password-auth` and, separately,
	// `password include password-auth`. Session rules are pulled in by a third
	// directive; account by a fourth. What must never appear is a rule whose
	// type no directive asked for — there is no `session` directive naming
	// password-auth's keyinit line other than the explicit one, so counting is
	// the wrong test. Instead: every rule's type must match a directive that
	// could have brought it in.
	allowed := map[fact.PAMType]bool{
		fact.PAMAuth: true, fact.PAMAccount: true,
		fact.PAMPassword: true, fact.PAMSession: true,
	}
	for _, l := range sshd.Lines {
		if !allowed[l.Type] {
			t.Errorf("rule of unexpected type %s reached the sshd stack", l.Type)
		}
	}

	// The substack is auth-scoped, so pam_pwquality — a password rule in
	// password-auth — must not be present as an auth rule.
	for _, l := range sshd.Lines {
		if l.Type == fact.PAMAuth && l.Module == "pam_pwquality.so" {
			t.Error("a password rule was imported into the auth stack by a type-scoped include")
		}
	}
}

// TestUnresolvedIncludeIsRecordedRatherThanIgnored: a stack that silently
// stopped short reads exactly like a complete one, and every "this module is
// absent" verdict drawn from it would be false.
func TestUnresolvedIncludeIsRecordedRatherThanIgnored(t *testing.T) {
	p := collect(t, "auth-unresolved")

	svc, ok := p.Service("common-password")
	if !ok {
		t.Fatal("no common-password record")
	}
	if svc.Complete() {
		t.Fatal("Complete() = true despite an include that does not exist")
	}
	if len(svc.Unresolved) != 1 {
		t.Fatalf("Unresolved = %v, want one entry", svc.Unresolved)
	}
	inc := svc.Unresolved[0]
	if inc.Directive != "@include" || inc.Target != "site-password-policy" {
		t.Errorf("include = %+v, want the @include directive and its target", inc)
	}
	if inc.Path != "/etc/pam.d/site-password-policy" {
		t.Errorf("path = %q; a bare name resolves against /etc/pam.d", inc.Path)
	}
	if inc.Reason == "" {
		t.Error("no reason recorded; an unresolved include with no reason is not actionable")
	}

	// The auth stack is untouched by the password stack's problem.
	auth, _ := p.Service("common-auth")
	if !auth.Complete() {
		t.Error("common-auth was marked incomplete by a fault in a different stack")
	}
}

// TestContinuationLinesAreJoined: long pam_pwquality argument lists routinely
// use a trailing backslash, and a parser that read each physical line as a
// rule would see the second half as a malformed rule and drop the arguments.
func TestContinuationLinesAreJoined(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "etc/pam.d/common-password",
		"password requisite pam_pwquality.so retry=3 \\\n    minlen=16 minclass=4\n")

	sys, err := fake.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatal(err)
	}
	p, _, _ := fact.Get[fact.PAM](facts, fact.PAMID)

	lines := fact.Find(p.Primary(fact.PAMPassword), fact.PAMPassword, "pam_pwquality.so")
	if len(lines) != 1 {
		t.Fatalf("found %d pam_pwquality rules, want 1", len(lines))
	}
	if n, ok := lines[0].IntArg("minlen"); !ok || n != 16 {
		t.Errorf("minlen = %d (present=%v); the continuation was not joined", n, ok)
	}
	if n, ok := lines[0].IntArg("minclass"); !ok || n != 4 {
		t.Errorf("minclass = %d (present=%v)", n, ok)
	}
}

// TestNoPasswordMaterialReachesTheFact. The PAM files hold policy rather than
// credentials, and nothing here should change that — but the collector reads
// /etc/security, and a future edit that pointed it at /etc/shadow would be a
// one-line mistake with a bundle-shaped consequence.
func TestNoPasswordMaterialReachesTheFact(t *testing.T) {
	p := collect(t, "auth-rhel")
	for path := range p.Digests {
		if path == "/etc/shadow" || path == "/etc/security/opasswd" {
			t.Errorf("the collector read %s; this module reads policy, not credentials", path)
		}
	}
}

// writeFixture builds a one-file fixture tree at test time. A continuation
// line is a property of the parser rather than of any host, so it is generated
// here rather than committed — the same reasoning as the hostile corpus in
// internal/system/live.
func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

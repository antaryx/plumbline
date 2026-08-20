package users_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	collector "github.com/antaryx/plumbline/internal/collect/collectors/users"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/fake"
)

// TestParseNSSwitchLine covers the grammar, including the forms that break a
// naive strings.Fields: an action bracket is a token that may contain spaces,
// and splitting on whitespace first turns "[ NOTFOUND=return ]" into three
// tokens, one of which is a bare "[" no reader would recognise as an action.
func TestParseNSSwitchLine(t *testing.T) {
	cases := []struct {
		line    string
		db      string
		sources []string
		ok      bool
	}{
		{"passwd: files", "passwd", []string{"files"}, true},
		{"passwd:     files systemd", "passwd", []string{"files", "systemd"}, true},
		{"group:\tfiles\tsss", "group", []string{"files", "sss"}, true},
		{"passwd: compat", "passwd", []string{"compat"}, true},
		{"passwd: files [NOTFOUND=return] ldap", "passwd", []string{"files", "ldap"}, true},
		{"passwd: files [ NOTFOUND=return SUCCESS=merge ] sss", "passwd", []string{"files", "sss"}, true},
		{"PASSWD: FILES", "passwd", []string{"files"}, true},
		{"passwd: files # local only", "passwd", []string{"files"}, true},
		// A colon with nothing after it disables the database. That is legal
		// and is not the same as a database the file never mentions, so it
		// parses rather than being discarded.
		{"aliases:", "aliases", nil, true},

		{"", "", nil, false},
		{"# passwd: files", "", nil, false},
		{"   ", "", nil, false},
		{"no colon here", "", nil, false},
		{": files", "", nil, false},
		{"two words: files", "", nil, false},
	}

	for _, c := range cases {
		db, sources, ok := fact.ParseNSSwitchLine(c.line)
		if ok != c.ok {
			t.Errorf("ParseNSSwitchLine(%q) ok = %v, want %v", c.line, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if db != c.db {
			t.Errorf("ParseNSSwitchLine(%q) db = %q, want %q", c.line, db, c.db)
		}
		if len(sources) != len(c.sources) || (len(sources) > 0 && !reflect.DeepEqual(sources, c.sources)) {
			t.Errorf("ParseNSSwitchLine(%q) sources = %v, want %v", c.line, sources, c.sources)
		}
	}
}

// TestLocalFilesAuthoritative is the predicate every "this identity does not
// exist" claim in the catalog has to pass through, so its false cases matter
// more than its true one.
func TestLocalFilesAuthoritative(t *testing.T) {
	present := func(sources ...string) fact.NSSwitch {
		return fact.NSSwitch{
			State:     fact.FilePresent,
			Path:      "/etc/nsswitch.conf",
			Databases: []fact.NSSwitchDB{{Name: fact.NSSDBPasswd, Sources: sources, Line: 1}},
		}
	}

	cases := []struct {
		name string
		nss  fact.NSSwitch
		want bool
	}{
		{"files alone", present("files"), true},

		// "compat" reads the file *and* whatever its "+" lines import.
		{"compat", present("compat"), false},
		// systemd resolves DynamicUser= allocations and systemd-homed records,
		// none of which is in /etc/passwd — and it is on the default line of
		// every current systemd distribution, which is exactly why it must not
		// be waved through as harmless.
		{"files systemd", present("files", "systemd"), false},
		{"files sss", present("files", "sss"), false},
		{"files ldap", present("files", "ldap"), false},
		{"files winbind", present("files", "winbind"), false},

		// A database the file never mentions falls through to a glibc
		// compiled-in default this scan cannot read.
		{"database not configured", fact.NSSwitch{State: fact.FilePresent}, false},
		// And a file we never read leaves the policy unknown, not "files".
		{"file absent", fact.NSSwitch{State: fact.FileAbsent}, false},
		{"file denied", fact.NSSwitch{State: fact.FileDenied}, false},
		{"read error", fact.NSSwitch{State: fact.FileError}, false},
	}

	for _, c := range cases {
		if got := c.nss.LocalFilesAuthoritative(fact.NSSDBPasswd); got != c.want {
			t.Errorf("%s: LocalFilesAuthoritative = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCollectNSSwitch(t *testing.T) {
	facts := collectFixture(t, "filesys-unowned-directory")

	n, ferr, ok := fact.Get[fact.NSSwitch](facts, fact.NSSwitchID)
	if !ok {
		t.Fatalf("users.nsswitch missing (err=%v)", ferr)
	}
	if n.State != fact.FilePresent {
		t.Fatalf("state = %q, want present", n.State)
	}
	src, found := n.Sources(fact.NSSDBPasswd)
	if !found {
		t.Fatal("no passwd line parsed")
	}
	if !reflect.DeepEqual(src, []string{"files", "sss"}) {
		t.Errorf("passwd sources = %v, want [files sss]", src)
	}
	if got := n.NonFileSources(fact.NSSDBPasswd); !reflect.DeepEqual(got, []string{"sss"}) {
		t.Errorf("NonFileSources = %v, want [sss]", got)
	}
	if n.Digest == "" {
		t.Error("no digest recorded; the finding could not cite evidence an auditor can verify")
	}
	if n.LocalFilesAuthoritative(fact.NSSDBPasswd) {
		t.Error("a host routing passwd to SSSD reports its local files as authoritative")
	}
}

// TestAMissingNSSwitchIsAStateNotAnError. glibc falls back to a compiled-in
// default when the file is absent, so "absent" is a real observation about the
// host — it simply is not the same observation as "configured to files", and a
// check that conflated them would report directory accounts as unowned on
// every host that never wrote the file.
func TestAMissingNSSwitchIsAStateNotAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "_plumbline"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "_plumbline", "fixture.json"),
		[]byte(`{"description":"no /etc at all"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sys, err := fake.New(root)
	if err != nil {
		t.Fatal(err)
	}

	facts := fact.NewSet()
	if err := collector.New().Collect(context.Background(), sys, facts); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	n, ferr, ok := fact.Get[fact.NSSwitch](facts, fact.NSSwitchID)
	if !ok {
		t.Fatalf("users.nsswitch was recorded as a fact error rather than a state (err=%v)", ferr)
	}
	if n.State != fact.FileAbsent {
		t.Errorf("state = %q, want absent", n.State)
	}
	if n.LocalFilesAuthoritative(fact.NSSDBPasswd) {
		t.Error("a host with no nsswitch.conf reports its local files as authoritative; that is a guess about the libc build")
	}
}

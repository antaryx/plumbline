package fact

import "strings"

// NSSwitchID is the fact for /etc/nsswitch.conf.
const NSSwitchID ID = "users.nsswitch"

// NSSwitchDB is one database line from nsswitch.conf: the databases's name and
// the name-service modules glibc consults for it, in order.
//
// The action brackets — "[NOTFOUND=return]", "[SUCCESS=merge]" — are dropped.
// They govern what happens *between* two sources, and no check in this project
// asks about them; what every caller wants is the set of places an identity
// could come from. Recording them and never reading them would be output
// surface bought for nothing (CLAUDE.md §7).
type NSSwitchDB struct {
	Name string `json:"name"`
	// Sources are the service names in the order glibc consults them:
	// "files", "systemd", "sss", "ldap", "compat", "nis", "winbind", "mymachines".
	Sources []string `json:"sources"`
	Line    int      `json:"line"`
}

// NSSwitch is the parsed /etc/nsswitch.conf: which name services answer for
// which databases.
//
// It is collected alongside the account databases because it is the thing that
// decides whether those databases are the whole story. /etc/passwd is a file;
// the *account database* is whatever nsswitch.conf says it is, and on a
// directory-joined host that is SSSD or LDAP, where an account exists that
// /etc/passwd has never heard of.
//
// The distinction matters to exactly one kind of claim: a claim that an
// identity does **not** exist. "This uid is not in /etc/passwd" is a fact
// about a file. "This uid belongs to nobody" is a fact about the host, and the
// two are the same statement only when the files are authoritative. See
// FILESYS-0010, and docs/checks/USERS-0006.md, which named this limitation
// before the fact existed.
type NSSwitch struct {
	Databases []NSSwitchDB `json:"databases,omitempty"`
	// State is what the collector was able to observe about the file itself.
	// Absent is not the same as empty: glibc falls back to a compiled-in
	// default when the file is missing, and that default is a property of the
	// libc build rather than of anything on disk, so a missing file leaves the
	// effective policy unknown rather than known to be "files".
	State FileState `json:"state"`
	Path  string    `json:"path"`
	// Malformed records lines that could not be parsed, with the line number.
	// A line we could not read might have been the one adding a directory
	// service.
	Malformed []int  `json:"malformed_lines,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

func (NSSwitch) FactID() ID       { return NSSwitchID }
func (NSSwitch) FactVersion() int { return 1 }

// Sources returns the name services configured for one database.
//
// The second return is whether the file said anything about that database at
// all, which is not the same as an empty source list: a database glibc has a
// compiled-in default for and the file never mentions is not a database with
// no sources.
func (n NSSwitch) Sources(db string) ([]string, bool) {
	for _, d := range n.Databases {
		if d.Name == db {
			return d.Sources, true
		}
	}
	return nil, false
}

// LocalFilesAuthoritative reports whether the local file is the complete
// database for db — that is, whether "absent from /etc/passwd" may be read as
// "does not exist".
//
// It is true only when the file was read and names exactly one source for this
// database, and that source is "files". Everything else is false, including
// the cases that look harmless:
//
//   - "compat" reads the file *and* whatever the "+" lines import;
//   - "systemd" resolves DynamicUser= allocations and systemd-homed records,
//     neither of which appears in /etc/passwd, and it is on the default line
//     of every current systemd distribution;
//   - a database the file never mentions falls through to a glibc compiled-in
//     default this scan cannot read.
//
// The conservative direction is deliberate and the asymmetry is the point: a
// false negative here costs an UNKNOWN, and a false positive here reports a
// legitimate directory account as belonging to nobody.
func (n NSSwitch) LocalFilesAuthoritative(db string) bool {
	if n.State != FilePresent {
		return false
	}
	src, ok := n.Sources(db)
	if !ok {
		return false
	}
	return len(src) == 1 && src[0] == "files"
}

// NonFileSources returns the sources for db other than "files", which is what
// a finding cites when it declines to conclude that an identity is unowned.
func (n NSSwitch) NonFileSources(db string) []string {
	src, _ := n.Sources(db)
	var out []string
	for _, s := range src {
		if s != "files" {
			out = append(out, s)
		}
	}
	return out
}

// The database names this project asks about.
const (
	NSSDBPasswd = "passwd"
	NSSDBGroup  = "group"
)

// ParseNSSwitchLine parses one nsswitch.conf line into a database name and its
// sources, dropping action brackets.
//
// It lives on the fact rather than in the collector because the grammar is the
// fact's own vocabulary, and a test can exercise every form — bracketed
// actions, comments, tabs, a database with no sources — without going near a
// filesystem.
//
// It reports ok=false for a line that is blank, a comment, or has no colon.
// A line with a colon and nothing after it is a database with no sources,
// which is legal and means the database is disabled; that returns ok=true with
// an empty slice, because "configured to nothing" and "not configured" lead a
// caller to different conclusions.
func ParseNSSwitchLine(line string) (db string, sources []string, ok bool) {
	if i := strings.IndexAny(line, "#"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil, false
	}
	name, rest, found := strings.Cut(line, ":")
	name = strings.TrimSpace(name)
	if !found || name == "" || strings.ContainsAny(name, " \t") {
		return "", nil, false
	}

	// Action brackets are dropped whole. Splitting on whitespace first would
	// break "[NOTFOUND=return]" into "[NOTFOUND=return]" — harmless — but
	// "[ NOTFOUND=return ]" is also legal and would become three tokens, one
	// of which is a "[" that no reader would recognise as an action.
	var out []string
	depth := 0
	var tok strings.Builder
	flush := func() {
		if tok.Len() > 0 {
			out = append(out, strings.ToLower(tok.String()))
			tok.Reset()
		}
	}
	for _, r := range rest {
		switch {
		case r == '[':
			flush()
			depth++
		case r == ']':
			if depth > 0 {
				depth--
			}
		case depth > 0:
			// Inside an action bracket; consumed and discarded.
		case r == ' ' || r == '\t':
			flush()
		default:
			tok.WriteRune(r)
		}
	}
	flush()
	return strings.ToLower(name), out, true
}

package fact

import (
	"sort"
	"strings"
)

// Fact IDs for the local account databases.
const (
	PasswdID ID = "users.passwd"
	ShadowID ID = "users.shadow"
	GroupID  ID = "users.group"
)

// PasswdEntry is one account from /etc/passwd.
//
// The GECOS field is deliberately absent. It is where distributions record a
// person's real name, office and telephone number, no check in this project
// asserts anything about it, and a bundle is an artifact that travels. A field
// nothing reads is a field that only creates exposure.
type PasswdEntry struct {
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
	// Line is 1-based, for evidence.
	Line int `json:"line"`
}

// Passwd is the parsed /etc/passwd.
type Passwd struct {
	Entries []PasswdEntry `json:"entries"`
	// CompatEntries are the NIS/LDAP compatibility lines — those whose first
	// field begins with "+" or "-". They are not accounts; they are
	// instructions to pull accounts from a directory service, and glibc still
	// honours them. A check counting accounts must not count them, and a check
	// asserting that no account has a property must not conclude anything at
	// all while one is present: the accounts they import are not in this file.
	CompatEntries []CompatEntry `json:"compat_entries,omitempty"`
	// Malformed records lines that could not be parsed into an entry, with the
	// line number. A file we could only partly read is not a file we may draw
	// negative conclusions from.
	Malformed []int  `json:"malformed_lines,omitempty"`
	Path      string `json:"path"`
	// Digest is the sha256 of the bytes parsed, so a finding can cite evidence
	// an auditor can verify against the bundle's evidence store (ADR-0009).
	Digest string `json:"digest,omitempty"`
}

// CompatEntry is one NIS/LDAP compatibility line.
type CompatEntry struct {
	// Spec is the raw first field: "+", "+@netgroup", "-user", "+user".
	Spec string `json:"spec"`
	Line int    `json:"line"`
}

func (Passwd) FactID() ID       { return PasswdID }
func (Passwd) FactVersion() int { return 1 }

// ByUID returns every account holding uid, in file order. More than one is a
// finding, not an error.
func (p Passwd) ByUID(uid uint32) []PasswdEntry {
	var out []PasswdEntry
	for _, e := range p.Entries {
		if e.UID == uid {
			out = append(out, e)
		}
	}
	return out
}

// DuplicateUIDs returns every uid held by more than one account, sorted.
func (p Passwd) DuplicateUIDs() []uint32 {
	count := map[uint32]int{}
	for _, e := range p.Entries {
		count[e.UID]++
	}
	var out []uint32
	for uid, n := range count {
		if n > 1 {
			out = append(out, uid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DuplicateNames returns every account name used more than once, sorted.
// glibc resolves the first match, so a duplicate silently shadows whatever
// came after it — including its uid, its shell and its group.
func (p Passwd) DuplicateNames() []string {
	count := map[string]int{}
	for _, e := range p.Entries {
		count[e.Name]++
	}
	var out []string
	for name, n := range count {
		if n > 1 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// HashAlgorithm names the scheme a crypt(3) password field uses.
type HashAlgorithm string

const (
	// HashNone means the field held no hash: it was empty, or a lock token.
	HashNone HashAlgorithm = ""
	// HashDES is the original 13-character crypt. Two-character salt, eight
	// significant password characters, brute-forceable in minutes.
	HashDES          HashAlgorithm = "des"
	HashMD5          HashAlgorithm = "md5"           // $1$
	HashBcryptA      HashAlgorithm = "bcrypt"        // $2a$ $2b$ $2y$
	HashSHA256       HashAlgorithm = "sha256"        // $5$
	HashSHA512       HashAlgorithm = "sha512"        // $6$
	HashScrypt       HashAlgorithm = "scrypt"        // $7$
	HashYescrypt     HashAlgorithm = "yescrypt"      // $y$
	HashGostYescrypt HashAlgorithm = "gost-yescrypt" // $gy$
	// HashUnknown means the field held something structured like a hash whose
	// scheme identifier this parser does not recognise. It is not "weak" and
	// it is not "strong"; it is unrecognised, and a check must say so rather
	// than assume either.
	HashUnknown HashAlgorithm = "unknown"
)

// ShadowEntry is one account's password state from /etc/shadow.
//
// **The hash is not here, and must never be.** Only its properties are
// recorded. A password hash is not a record of what happened on a host; it is
// the credential itself in a form an attacker can work on offline, and a
// bundle is an artifact designed to travel. Everything a check needs to judge
// password strength is derivable from the scheme identifier, which is the part
// before the salt. See docs/adr/0015-account-data-in-bundles.md.
//
// The password-aging fields are also absent. No check in this work package
// reads them, and a fact field is permanent output surface (CLAUDE.md §7); the
// cheap direction is to add them when a check needs them, as an optional field
// that does not bump the version.
type ShadowEntry struct {
	Name string `json:"name"`
	// Empty means the password field held nothing at all. Such an account
	// authenticates with no password wherever the PAM stack consults shadow.
	Empty bool `json:"empty"`
	// Locked means the field held a lock token — "!", "!!", "*", "!*" — or a
	// hash prefixed with "!". No password can produce a match, so the account
	// cannot authenticate by password. It says nothing about SSH keys.
	Locked bool `json:"locked"`
	// Algorithm is the crypt scheme, derived from the "$id$" prefix.
	Algorithm HashAlgorithm `json:"algorithm,omitempty"`
	// Line is 1-based, for evidence.
	Line int `json:"line"`
}

// Shadow is the parsed /etc/shadow.
//
// It carries no Digest. The bytes it was parsed from are never stored as
// evidence (see internal/collect.IsCredentialFile), so a digest here would be
// a pointer into an archive that deliberately does not contain the thing it
// points at.
type Shadow struct {
	Entries   []ShadowEntry `json:"entries"`
	Malformed []int         `json:"malformed_lines,omitempty"`
	Path      string        `json:"path"`
}

func (Shadow) FactID() ID       { return ShadowID }
func (Shadow) FactVersion() int { return 1 }

// Entry returns one account's password state.
func (s Shadow) Entry(name string) (ShadowEntry, bool) {
	for _, e := range s.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return ShadowEntry{}, false
}

// Strong reports whether this algorithm is one a modern system should be
// using. Anything not on the strong list is not automatically weak — see
// HashUnknown — so a check must distinguish "known and weak" from "not
// recognised" rather than treating Strong()==false as a failure.
func (a HashAlgorithm) Strong() bool {
	switch a {
	case HashSHA512, HashYescrypt, HashGostYescrypt, HashScrypt, HashBcryptA:
		return true
	default:
		return false
	}
}

// Weak reports whether this algorithm is known and known to be inadequate.
func (a HashAlgorithm) Weak() bool {
	switch a {
	case HashDES, HashMD5, HashSHA256:
		return true
	default:
		return false
	}
}

// GroupEntry is one group from /etc/group.
type GroupEntry struct {
	Name    string   `json:"name"`
	GID     uint32   `json:"gid"`
	Members []string `json:"members,omitempty"`
	Line    int      `json:"line"`
}

// Group is the parsed /etc/group.
type Group struct {
	Entries   []GroupEntry `json:"entries"`
	Malformed []int        `json:"malformed_lines,omitempty"`
	Path      string       `json:"path"`
	Digest    string       `json:"digest,omitempty"`
}

func (Group) FactID() ID       { return GroupID }
func (Group) FactVersion() int { return 1 }

// Named returns a group by name.
func (g Group) Named(name string) (GroupEntry, bool) {
	for _, e := range g.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return GroupEntry{}, false
}

// AlgorithmFor classifies a crypt(3) password field.
//
// The three return values are the scheme, whether the account is locked, and
// whether the field was empty. It is here rather than in the collector because
// the classification is the fact's own vocabulary, and a test can exercise
// every crypt format without going near the filesystem.
//
// A leading "!" is a lock applied over whatever follows, which is why the
// scheme is still reported for a locked account: an operator unlocking it gets
// the algorithm that was there all along.
func AlgorithmFor(field string) (alg HashAlgorithm, locked, empty bool) {
	if field == "" {
		return HashNone, false, true
	}

	rest := field
	for strings.HasPrefix(rest, "!") {
		locked = true
		rest = rest[1:]
	}
	// "*" is the conventional "no password will ever match" token. "*LK*" and
	// "*NP*" are the Solaris-derived spellings some tools still write.
	if rest == "" || strings.HasPrefix(rest, "*") {
		return HashNone, true, false
	}
	// "x" in shadow's password field is not a hash; it is what appears when a
	// system has been misconfigured by copying passwd's convention across.
	if rest == "x" {
		return HashUnknown, locked, false
	}

	if !strings.HasPrefix(rest, "$") {
		// No scheme prefix: the original DES crypt, whose output is a bare
		// 13-character string.
		return HashDES, locked, false
	}

	parts := strings.SplitN(rest, "$", 3)
	if len(parts) < 3 {
		return HashUnknown, locked, false
	}
	switch parts[1] {
	case "1":
		return HashMD5, locked, false
	case "2", "2a", "2b", "2x", "2y":
		return HashBcryptA, locked, false
	case "5":
		return HashSHA256, locked, false
	case "6":
		return HashSHA512, locked, false
	case "7":
		return HashScrypt, locked, false
	case "y":
		return HashYescrypt, locked, false
	case "gy":
		return HashGostYescrypt, locked, false
	default:
		return HashUnknown, locked, false
	}
}

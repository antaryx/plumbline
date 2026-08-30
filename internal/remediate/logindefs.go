package remediate

import (
	"github.com/antaryx/plumbline/internal/finding"
)

// loginDefsSetFunc sets a key in /etc/login.defs.
//
// **The rule login.defs follows is the reverse of sysctl.d's, and getting it
// wrong is the whole difficulty of this one.** shadow(3) reads the file
// top-to-bottom and takes the *first* definition of a key; every later one is
// dead. So the naive remediation — append `ENCRYPT_METHOD SHA512` to the end of
// the file — does nothing at all on the hosts that need it most, because those
// are exactly the hosts that already have an `ENCRYPT_METHOD MD5` line further
// up. The script would run cleanly, report nothing, and change nothing, which
// is the worst outcome available: a host an operator now believes is fixed.
//
// So: the first definition is rewritten in place, later ones are commented out
// rather than deleted, and only a file with no definition at all gets an
// append.
//
// **Commented rather than removed**, and that is the one place this differs
// from the sysctl merge. A duplicate in a plumbline-owned drop-in is noise to
// collapse; a second ENCRYPT_METHOD in /etc/login.defs is a line somebody
// wrote, on a distribution-shipped file full of documentation, and leaving a
// commented trace with the tool's name on it is how the next person to read it
// finds out what happened and why the value they set stopped applying.
//
// Running it twice is a no-op: the first definition already holds the wanted
// value, and the lines below it are already commented and no longer match.
const loginDefsSetFunc = `
# Set KEY to VALUE in /etc/login.defs, honouring the file's own rule that the
# FIRST definition wins. The first is rewritten in place; any later ones are
# commented out with a note, because appending to this file would be silently
# ineffective on exactly the hosts that already set the key wrongly.
plumbline_logindefs_set() {
	pl_key=$1 pl_val=$2 pl_file=${3:-/etc/login.defs}
	[ -f "$pl_file" ] || { echo "plumbline: $pl_file does not exist; nothing to set" >&2; return 1; }
	plumbline_backup "$pl_file"
	pl_tmp=$(mktemp)
	awk -v key="$pl_key" -v val="$pl_val" '
		{
			line = $0
			# A comment or a blank is passed through untouched.
			if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) { print; next }
			# The grammar is KEY<whitespace>VALUE. An "=" is not login.defs
			# syntax and a line using one is not a setting the shadow suite
			# reads, so it must not be treated as one.
			k = line
			sub(/^[ \t]+/, "", k)
			sub(/[ \t].*$/, "", k)
			if (k != key) { print; next }
			if (!done) { print key " " val; done = 1; next }
			print "# disabled by plumbline: login.defs takes the first match, so this line was never read"
			print "#" line
		}
		END { if (!done) print key " " val }
	' "$pl_file" > "$pl_tmp"
	cat "$pl_tmp" > "$pl_file"
	rm -f "$pl_tmp"
}
`

// loginDefsFix sets one key in /etc/login.defs.
type loginDefsFix struct {
	checkID string
	title   string
	key     string
	value   string
	notes   []string
}

func (l loginDefsFix) CheckID() string { return l.checkID }

func (l loginDefsFix) Build(f finding.Finding, _ Options) (Action, bool) {
	a := Action{CheckID: l.checkID, Title: titleOf(f, l.title)}
	for _, n := range l.notes {
		note(&a, n)
	}
	note(&a, "login.defs takes the FIRST definition of a key, so appending would be silently")
	note(&a, "ineffective on a host that already sets it. The helper rewrites the first line in")
	note(&a, "place and comments out any later ones. The file is copied to .bak first.")

	command(&a, "plumbline_logindefs_set", l.key, l.value, LoginDefsPath)
	return a, true
}

// LoginDefsPath is the file both of these fixes edit.
const LoginDefsPath = "/etc/login.defs"

func init() {
	register(loginDefsFix{
		checkID: "AUTH-0005",
		title:   "Passwords are hashed with a strong algorithm",
		key:     "ENCRYPT_METHOD",
		// SHA512 rather than YESCRYPT. yescrypt is the better hash and it is
		// not the safer script: a host whose libcrypt predates it — RHEL 8,
		// Ubuntu 20.04, anything with libxcrypt older than 4.4 — accepts the
		// setting and then cannot hash a password with it, which surfaces as
		// passwd(1) failing for every user at once. SHA512 works everywhere
		// this tool runs.
		value: "SHA512",
		notes: []string{
			"**This changes nothing about the passwords already in /etc/shadow.** The hash is",
			"chosen when a password is *set*, so every existing account keeps whatever it was",
			"hashed with until its password is next changed. Until then a stolen /etc/shadow is",
			"worth exactly what it was worth before this ran.",
			"To actually retire the old hashes, expire the passwords so each user is forced to",
			"set a new one at their next login:",
			"  awk -F: '($2 ~ /^\\$1\\$/) {print $1}' /etc/shadow   # accounts still on MD5",
			"  chage -d 0 <user>                                  # force a change at next login",
			"Do not do that to service accounts or to the account you are logged in as without",
			"a second way in: an expired password on an account with no interactive session is",
			"an account nobody can use.",
			"SHA512 rather than yescrypt, deliberately: yescrypt is the better hash and needs",
			"libxcrypt 4.4 or newer. A host without it accepts the setting and then cannot hash",
			"a password at all, which shows up as passwd(1) failing for every user at once.",
		},
	})
	register(loginDefsFix{
		checkID: "USERS-0012",
		title:   "The default minimum password age is at least one day",
		key:     "PASS_MIN_DAYS",
		value:   "1",
		notes: []string{
			"This is the default for accounts created from now on. Accounts that already exist",
			"keep whatever is in /etc/shadow's fifth field — 'chage --mindays 1 <user>' sets one,",
			"and USERS-0010 is the check that reports them.",
			"A minimum age stops a user changing their password again for a day, including",
			"straight after one they regret. Root can still reset it with 'passwd <user>', and",
			"that is the only escape hatch.",
		},
	})
}

package users

import (
	"errors"
	"strings"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// NSSwitchPath is the name-service routing table.
const NSSwitchPath = "/etc/nsswitch.conf"

// collectNSSwitch reads /etc/nsswitch.conf.
//
// It belongs to this collector rather than to one of its own because it is not
// a fourth account database — it is the statement of which databases count.
// /etc/passwd is a file; the account database is whatever this file routes
// "passwd" to, and on a directory-joined host that is SSSD or LDAP, holding
// accounts /etc/passwd has never heard of. A check that concludes an identity
// does not exist is wrong on every such host unless it reads this first.
//
// Unlike the three databases, a missing file is recorded as a *state* rather
// than as a fact error. glibc falls back to a compiled-in default when the
// file is absent, so "absent" is a real and answerable observation about the
// host — it just is not the same observation as "configured to files", and the
// fact keeps the two apart.
func collectNSSwitch(s system.System, fs *fact.Set) {
	n := fact.NSSwitch{Path: NSSwitchPath, State: fact.FilePresent}

	res, err := s.ReadFile(NSSwitchPath, maxRead)
	switch {
	case err == nil:
	case errors.Is(err, system.ErrNotExist):
		n.State = fact.FileAbsent
		fs.Put(n)
		return
	case errors.Is(err, system.ErrPermission):
		n.State = fact.FileDenied
		fs.Put(n)
		return
	default:
		n.State = fact.FileError
		fs.Put(n)
		return
	}
	if res.Truncated {
		// A partly-read routing table is worse than none: the line naming the
		// directory service is as likely to be past the cap as before it.
		n.State = fact.FileError
		fs.Put(n)
		return
	}
	if why := collect.NotText(res.Data); why != "" {
		// Recorded as a state rather than a fact error, for the reason an
		// absent file is: the routing table is only ever consulted to decide
		// whether the local files are authoritative, and "we could not read
		// the policy" already answers that with "no". A fact error here would
		// take out FILESYS-0010 entirely instead of degrading its FAIL branch.
		n.State = fact.FileError
		n.Malformed = nil
		n.Databases = nil
		fs.Put(n)
		return
	}

	n.Digest = res.SHA256
	for i, raw := range splitLines(string(res.Data)) {
		line := strings.TrimSuffix(raw, "\r")
		if skippable(line) {
			continue
		}
		db, sources, ok := fact.ParseNSSwitchLine(line)
		if !ok {
			n.Malformed = append(n.Malformed, i+1)
			continue
		}
		n.Databases = append(n.Databases, fact.NSSwitchDB{Name: db, Sources: sources, Line: i + 1})
	}
	fs.Put(n)
}

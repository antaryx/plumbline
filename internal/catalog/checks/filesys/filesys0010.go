package filesys

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	collector "github.com/antaryx/plumbline/internal/collect/collectors/filesys"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0010 tests that every uid and gid owning something on this filesystem
// resolves to an account or a group.
var Check0010 = catalog.Check{
	ID:     "FILESYS-0010",
	Module: "FILESYS",
	Title:  "Every uid and gid owning a file resolves to a local account or group",
	Description: `Ownership on a Unix filesystem is a number. The name is a
lookup, performed at display time, against a database that can change without
the filesystem knowing. Delete an account and its files do not become
ownerless — they keep the number, and 'ls -l' starts printing the number
because there is no longer a name for it.

That gap matters for one specific and entirely mundane reason: **uids are
reused.** Every distribution's useradd allocates the lowest free uid above
UID_MIN. So the next account created on this host inherits the number, and with
it every file the departed account left behind — its home directory, its
crontabs, anything it wrote into a shared area, anything it owned in a backup
that is later restored. Nobody grants that access and nobody sees it happen.
The new user simply has it, and an audit of "who can read this" that consults
the account database gets the wrong answer.

The same reasoning applies to groups, one level wider: a reused gid hands the
new group whatever the old one could reach.

Unowned files are also a durable trace of things that happened. A build that
ran in a container and wrote into a bind mount, a tarball unpacked with
--same-owner from a machine with different accounts, a service that was removed
without --remove-home, or an intrusion whose artefacts were written by a uid
that never had an account on this host at all.

**What this check will not do is guess.** A uid absent from /etc/passwd means
"unowned" only if /etc/passwd is the whole account database, and on a host
joined to LDAP, SSSD, Active Directory or systemd-homed it is not. The check
reads /etc/nsswitch.conf to find out which, and where the answer is that
identities can come from somewhere this offline scan cannot ask, it returns
UNKNOWN rather than reporting a legitimate directory account as belonging to
nobody.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"filesys", "ownership", "accounts", "hygiene"},
	Requires: []fact.ID{
		fact.FSTallyFactID(collector.TallyOwnerUID),
		fact.FSTallyFactID(collector.TallyOwnerGID),
		fact.PasswdID,
		fact.GroupID,
		fact.NSSwitchID,
	},
	SinceCatalog: 12,

	Eval: func(fs *fact.Set) catalog.Outcome {
		uids := tally(fs, collector.TallyOwnerUID)
		gids := tally(fs, collector.TallyOwnerGID)
		passwd, _, _ := fact.Get[fact.Passwd](fs, fact.PasswdID)
		group, _, _ := fact.Get[fact.Group](fs, fact.GroupID)
		nss, _, _ := fact.Get[fact.NSSwitch](fs, fact.NSSwitchID)

		known := map[uint32]bool{}
		for _, e := range passwd.Entries {
			known[e.UID] = true
		}
		knownGroups := map[uint32]bool{}
		for _, e := range group.Entries {
			knownGroups[e.GID] = true
		}

		strayUID := unresolved("uid", uids, known)
		strayGID := unresolved("gid", gids, knownGroups)

		// PASS first, and it does **not** consult nsswitch.conf. A name
		// service can only ever add identities that resolve; it can never
		// remove one that /etc/passwd already resolves. So "every owner
		// resolves locally" implies "every owner resolves", on any host,
		// whatever it is joined to. The routing table matters only when
		// something failed to resolve, which is the branch below.
		if len(strayUID) == 0 && len(strayGID) == 0 {
			return mustBeCompleteTally(catalog.Outcome{
				Result: finding.Pass,
				Detail: fmt.Sprintf(
					"Every owner on this filesystem resolves: %d distinct uid%s and %d distinct gid%s across %d inode(s) examined, and each one is present in %s or %s. No file is waiting to be inherited by the next account that takes its number.",
					len(uids.Buckets), plural(len(uids.Buckets), "", "s"),
					len(gids.Buckets), plural(len(gids.Buckets), "", "s"),
					uids.InodesVisited, passwd.Path, group.Path),
			}, uids, gids)
		}

		// Something did not resolve locally. Before that may be called a
		// finding, the local files have to be the whole database — otherwise
		// this is an AD user's home directory and the "finding" is an
		// accusation against a perfectly ordinary host.
		if why := notAuthoritative(nss, passwd, group, strayUID, strayGID); why != "" {
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       nss.Path,
				Detail: fmt.Sprintf(
					"%d owner%s on this filesystem %s not resolve in the local files — %s — but the local files are not this host's whole account database: %s. An identity absent from /etc/passwd may still be a real account served from somewhere this scan cannot ask, because Plumbline never opens a network socket. Reporting these as unowned would accuse a correctly configured host of a problem it does not have.",
					len(strayUID)+len(strayGID), plural(len(strayUID)+len(strayGID), "", "s"),
					plural(len(strayUID)+len(strayGID), "does", "do"),
					describeStray(strayUID, strayGID), why),
				Evidence: append(strayEvidence(strayUID, strayGID), nsswitchEvidence(nss)),
			}
		}

		return catalog.Outcome{
			Result:  finding.Fail,
			Subject: firstSubject(strayUID, strayGID),
			Detail: fmt.Sprintf(
				"%s. %s routes %s to the local files alone, so these numbers belong to nobody on this host — and the next account or group created here takes the lowest free number, inherits every one of those files, and nothing records that it happened.",
				describeStray(strayUID, strayGID), nss.Path, verifiedDatabases(strayUID, strayGID)),
			Evidence: strayEvidence(strayUID, strayGID),
		}
	},

	Remediation: &finding.Remediation{
		Summary: "Find out what wrote them, then either reassign the files to an account that should own them or delete them. Do not create an account to match the number.",
		Effort:  "MEDIUM",
		Steps: []string{
			"List them before changing anything: 'find / -xdev \\( -nouser -o -nogroup \\) -ls'. The -xdev matters — without it the search walks network filesystems whose account databases are not this host's, and every file on them looks unowned.",
			"Establish what the number used to be. 'lastlog', '/var/log/auth.log' and the package manager's log usually name the account that was removed; a uid above UID_MIN was a person or a build, and a uid below it was almost always a package's service account that outlived its package.",
			"If the files still matter, chown them to the account that should own them now. If they do not, delete them — an unowned tree kept 'just in case' is one that will be inherited silently.",
			"Do not create an account with the old uid to make the finding go away. That grants a live account everything the dead one could reach, which is the outcome this check exists to prevent, arrived at deliberately.",
			"Where the cause was a container or a tar archive, fix the cause: bind mounts need matching uid ranges or a userns mapping, and 'tar --same-owner' should not be used to unpack an archive from a host with different accounts.",
			"Where a service account was orphaned by a package removal, remove the leftovers with it — 'apt purge' rather than 'apt remove', or 'userdel -r' at the time the account goes.",
		},
		Commands: []string{
			"find / -xdev \\( -nouser -o -nogroup \\) -ls",
			"getent passwd <uid>",
			"chown <user>:<group> <path>",
		},
		Caution: "Never chown a tree recursively without looking at it first. A single 'chown -R' across a directory that legitimately holds several owners flattens all of them, and the previous ownership is not recorded anywhere you can get it back from. Confirm this host is not joined to a directory service before treating any of this as a finding: 'getent passwd <uid>' resolving a name that /etc/passwd does not contain means the account is real and this check should have returned UNKNOWN.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-2"},
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "CM-6"},
	},

	References: []finding.Reference{
		{Title: "find(1) — -nouser and -nogroup", URL: "https://man7.org/linux/man-pages/man1/find.1.html"},
		{Title: "nsswitch.conf(5)", URL: "https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html"},
	},
}

// stray is one identity that owns something and resolves to nothing.
type stray struct {
	kind   string // "uid" or "gid"
	id     uint64
	count  int
	sample fact.FSRow
}

// unresolved returns the tally's keys that are absent from known, in key
// order. The tally's buckets are already sorted, so the result is too.
//
// kind is passed in rather than derived from t.Tally: the tally name is a
// registration detail of another package, and a check that read a verdict's
// vocabulary out of it would start printing "owner_gid 12345" the day somebody
// renamed the interest.
func unresolved(kind string, t fact.FSTally, known map[uint32]bool) []stray {
	var out []stray
	for _, b := range t.Buckets {
		// A key wider than uint32 cannot have come from a FileInfo, whose uid
		// and gid are uint32. Treating one as unresolved would be a finding
		// manufactured by a type conversion, so it is skipped: there is no
		// such owner to report.
		if b.Key > 0xFFFF_FFFF {
			continue
		}
		if known[uint32(b.Key)] {
			continue
		}
		out = append(out, stray{kind: kind, id: b.Key, count: b.Count, sample: b.Example})
	}
	return out
}

// notAuthoritative returns why the local files cannot settle the question, or
// "" when they can.
//
// Each clause is a distinct way the files can be incomplete, and each is
// tested only against the identity kind it affects: an unreadable group
// routing table has nothing to say about a stray uid.
func notAuthoritative(nss fact.NSSwitch, passwd fact.Passwd, group fact.Group, strayUID, strayGID []stray) string {
	var why []string

	if len(strayUID) > 0 {
		why = append(why, authorityFor(nss, fact.NSSDBPasswd, passwd.Path, len(passwd.CompatEntries), passwd.Malformed)...)
	}
	if len(strayGID) > 0 {
		why = append(why, authorityFor(nss, fact.NSSDBGroup, group.Path, len(group.CompatEntries), group.Malformed)...)
	}
	return strings.Join(why, "; ")
}

// authorityFor examines one database: its routing, its compatibility lines and
// its unparseable lines.
func authorityFor(nss fact.NSSwitch, db, path string, compat int, malformed []int) []string {
	var why []string

	switch {
	case nss.State != fact.FilePresent:
		// A missing nsswitch.conf leaves glibc's compiled-in default in
		// force, and that default is a property of the libc build rather than
		// of anything on this host. Reading it as "files" would be a guess in
		// exactly the place this check refuses to make one.
		why = append(why, fmt.Sprintf("%s is %s, so the effective name-service policy is glibc's compiled-in default rather than anything on disk", nss.Path, nss.State))
	case !nss.LocalFilesAuthoritative(db):
		if src, ok := nss.Sources(db); ok {
			why = append(why, fmt.Sprintf("%s routes %q to %s", nss.Path, db, strings.Join(src, ", ")))
		} else {
			why = append(why, fmt.Sprintf("%s names no sources for %q, so that database falls through to glibc's compiled-in default", nss.Path, db))
		}
	}

	if compat > 0 {
		why = append(why, fmt.Sprintf("%s carries %d NIS/LDAP compatibility line%s, which import identities that are not in the file", path, compat, plural(compat, "", "s")))
	}
	if len(malformed) > 0 {
		why = append(why, fmt.Sprintf("%d line%s in %s could not be parsed, and an unparsed line may have been the entry that resolves this", len(malformed), plural(len(malformed), "", "s"), path))
	}
	return why
}

// verifiedDatabases names the databases whose routing was actually examined.
//
// notAuthoritative only asks about a database when something in it failed to
// resolve, so a FAIL over a stray uid alone has said nothing about how "group"
// is routed. Writing "passwd and group" into that finding would be a correct
// verdict with a false explanation, which is its own class of bug.
func verifiedDatabases(strayUID, strayGID []stray) string {
	switch {
	case len(strayUID) > 0 && len(strayGID) > 0:
		return fact.NSSDBPasswd + " and " + fact.NSSDBGroup
	case len(strayGID) > 0:
		return fact.NSSDBGroup
	default:
		return fact.NSSDBPasswd
	}
}

// describeStray renders the unresolved identities for a detail string, capped
// the way row lists are.
func describeStray(strayUID, strayGID []stray) string {
	all := append(append([]stray(nil), strayUID...), strayGID...)
	sort.SliceStable(all, func(a, b int) bool { return all[a].count > all[b].count })

	n := len(all)
	if n > maxEvidenceRows {
		n = maxEvidenceRows
	}
	parts := make([]string, 0, n)
	for _, s := range all[:n] {
		parts = append(parts, fmt.Sprintf("%s %s owns %d inode%s (for example %s)",
			s.kind, strconv.FormatUint(s.id, 10), s.count, plural(s.count, "", "s"), s.sample.Path))
	}
	out := strings.Join(parts, "; ")
	if len(all) > n {
		out += fmt.Sprintf("; and %d more", len(all)-n)
	}
	return out
}

// strayEvidence cites the exemplar inode for each unresolved identity.
func strayEvidence(strayUID, strayGID []stray) []finding.Evidence {
	all := append(append([]stray(nil), strayUID...), strayGID...)
	sort.SliceStable(all, func(a, b int) bool { return all[a].count > all[b].count })

	n := len(all)
	if n > maxEvidenceRows {
		n = maxEvidenceRows
	}
	ev := make([]finding.Evidence, 0, n+1)
	for _, s := range all[:n] {
		ev = append(ev, finding.NewEvidence(s.sample.Path, 0,
			fmt.Sprintf("%s %d resolves to no local account and owns %d inode(s); this one is mode %s, uid %d, gid %d",
				s.kind, s.id, s.count, renderPerm(s.sample.Mode), s.sample.UID, s.sample.GID), ""))
	}
	if len(all) > n {
		ev = append(ev, finding.NewEvidence("", 0,
			fmt.Sprintf("… and %d more unresolved identit%s; the count in the detail is the full total", len(all)-n, plural(len(all)-n, "y", "ies")), ""))
	}
	return ev
}

// nsswitchEvidence cites the routing table that made the answer unknown.
func nsswitchEvidence(nss fact.NSSwitch) finding.Evidence {
	if nss.State != fact.FilePresent {
		return finding.NewEvidence(nss.Path, 0, fmt.Sprintf("name-service routing table is %s", nss.State), nss.Digest)
	}
	var parts []string
	for _, db := range []string{fact.NSSDBPasswd, fact.NSSDBGroup} {
		if src, ok := nss.Sources(db); ok {
			parts = append(parts, fmt.Sprintf("%s: %s", db, strings.Join(src, " ")))
			continue
		}
		parts = append(parts, db+": (not configured)")
	}
	return finding.NewEvidence(nss.Path, 0, strings.Join(parts, "; "), nss.Digest)
}

// firstSubject names the finding's subject: the exemplar path of the identity
// owning the most inodes, which is the one an operator should look at first.
func firstSubject(strayUID, strayGID []stray) string {
	all := append(append([]stray(nil), strayUID...), strayGID...)
	if len(all) == 0 {
		return ""
	}
	best := all[0]
	for _, s := range all[1:] {
		if s.count > best.count {
			best = s
		}
	}
	return best.sample.Path
}

// Package cron holds the CRON module's checks.
//
// Every check here is about **who may write the schedule**, not about what the
// schedule says. That is the whole threat model of system cron: a file or a
// drop-in directory that a non-root account can write is arbitrary code
// execution as root, on a timer, with no exploit and no authentication step.
// It is one of the oldest local privilege escalations there is and it is still
// one of the most common, because it is produced by ordinary accidents — a
// deployment script that chowns a directory to its service account, an
// installer that leaves a package directory group-writable, an administrator
// who ran chmod -R.
//
// The module reads file metadata only. No crontab's contents reach a fact, for
// the reason set out in the collector: command lines and their arguments are
// operator data, frequently including credentials, and no check here looks at
// them.
package cron

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// cronFact reads the module's fact. The runner's required-fact gate guarantees
// it is present and typed before Eval is entered.
func cronFact(fs *fact.Set) fact.Cron {
	c, _, _ := fact.Get[fact.Cron](fs, fact.CronID)
	return c
}

// notInstalled is the verdict when the host has no system cron at all.
//
// NOT_APPLICABLE and not PASS: a host with no cron has not satisfied "the
// crontab is owned by root", it has removed the subject of the sentence.
// Scoring treats the two very differently (docs/SCORING.md).
func notInstalled() catalog.Outcome {
	return catalog.Outcome{
		Result: finding.NotApplicable,
		Detail: "None of the standard cron paths exists on this host; no system cron is installed.",
	}
}

// renderPerm formats permission bits the way an operator reads them out of
// `stat -c %a`, which is the form they will type into chmod.
func renderPerm(m fs.FileMode) string { return fmt.Sprintf("%04o", m.Perm()) }

// describe renders one path's observed state for a detail string.
func describe(p fact.CronPath) string {
	return fmt.Sprintf("%s (mode %s, uid %d, gid %d)", p.Path, renderPerm(p.Mode), p.UID, p.GID)
}

// evidenceFor cites one path's metadata.
//
// There is deliberately no digest. Nothing in this module reads a file, so
// there are no bytes in the evidence store for a digest to point at, and one
// here would be a reference into an archive that does not contain the thing it
// references. Line is 0 for the same reason: the finding is about the inode,
// not about anything inside it.
func evidenceFor(p fact.CronPath) finding.Evidence {
	switch p.State {
	case fact.CronObserved:
		kind := "file"
		switch {
		case p.IsSymlink:
			kind = "symlink"
		case p.IsDir:
			kind = "directory"
		}
		return finding.NewEvidence(p.Path, 0,
			fmt.Sprintf("%s: mode %s, uid %d, gid %d", kind, renderPerm(p.Mode), p.UID, p.GID), "")
	case fact.CronAbsent:
		return finding.NewEvidence(p.Path, 0, "does not exist", "")
	default:
		return finding.NewEvidence(p.Path, 0, string(p.State)+": "+p.Msg, "")
	}
}

// observed filters records down to the ones whose metadata was actually read.
// Only these carry meaningful UID, GID and Mode — see ADR-0016.
func observed(ps []fact.CronPath) []fact.CronPath {
	var out []fact.CronPath
	for _, p := range ps {
		if p.State == fact.CronObserved {
			out = append(out, p)
		}
	}
	return out
}

// unknownIfUnreadable converts a would-be PASS into UNKNOWN when any path the
// check depends on could not be stat'ed.
//
// It is a helper rather than a convention because every check in this module
// needs it and the failure mode of forgetting is silent: a PASS meaning "the
// paths we could see are fine", which is exactly the false assurance CLAUDE.md
// rule 3 exists to prevent. The same shape as the USERS module's
// unknownIfIncomplete, arrived at for the same reason.
func unknownIfUnreadable(c fact.Cron, considered []fact.CronPath, pass catalog.Outcome) catalog.Outcome {
	// Only a PASS is at risk. A FAIL was drawn from a path we did read, and
	// reading more cannot unmake it.
	if pass.Result != finding.Pass {
		return pass
	}
	bad := c.Unreadable(considered...)
	if len(bad) == 0 {
		return pass
	}

	reason := finding.ReasonPermission
	names := make([]string, 0, len(bad))
	ev := make([]finding.Evidence, 0, len(bad))
	for _, p := range bad {
		if p.State == fact.CronError {
			reason = finding.ReasonAmbiguousState
		}
		names = append(names, p.Path)
		ev = append(ev, evidenceFor(p))
	}

	return catalog.Outcome{
		Result:        finding.Unknown,
		UnknownReason: reason,
		Subject:       pass.Subject,
		Detail: fmt.Sprintf(
			"No violation was found among the paths that could be examined, but the metadata of %d of them could not be read (%s). A path whose owner and mode are unknown could be the one violating this rule, so the result cannot be confirmed.",
			len(bad), strings.Join(names, ", ")),
		Evidence: ev,
	}
}

// faults describes what is wrong with one path, as clauses that complete
// "<path> is …". An empty result means the path satisfies the rule.
//
// Ownership and writability are reported together because they are the same
// exposure reached two ways: a file owned by an unprivileged account is one
// that account can chmod at will, so "root-owned but group-writable" and
// "owned by deploy" both mean the same thing — somebody other than root
// decides what cron runs.
func faults(p fact.CronPath) []string {
	var out []string
	if !p.RootOwned() {
		out = append(out, fmt.Sprintf("owned by uid %d / gid %d rather than root, so that account can change its contents and its mode at will",
			p.UID, p.GID))
	}
	if p.GroupOrOtherWritable() {
		out = append(out, fmt.Sprintf("mode %s, which is writable by group or other, so an unprivileged account can change what cron runs as root",
			renderPerm(p.Mode)))
	}
	return out
}

// joinPaths renders a path list for a detail string.
func joinPaths(ps []fact.CronPath) string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Path)
	}
	return strings.Join(names, ", ")
}

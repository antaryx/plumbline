package kernel

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// corePatternKey is the parameter under test.
const corePatternKey = "kernel.core_pattern"

// sharedDirs are directories a core dump must never be written into. They are
// world-writable on every Linux system by definition, so a core landing there
// is readable by whoever is watching for it.
//
// This is the check's one heuristic, and it is deliberately a short list of
// directories whose permissions are fixed by convention rather than an attempt
// to reason about arbitrary paths. The check cannot stat anything — it is a
// pure function over facts — so a path outside this list is reported as a
// location the reader should verify, not guessed at.
var sharedDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// Check0014 tests where the kernel writes core dumps.
var Check0014 = catalog.Check{
	ID:     "KERNEL-0014",
	Module: "KERNEL",
	Title:  "Core dumps are not written to an attacker-influenced location",
	Description: `A core dump is a copy of a process's memory. Where it lands is
decided entirely by kernel.core_pattern, and the kernel's own default is the
bare word "core" — a relative path, which means the dump is written into the
crashing process's current working directory.

That is the dangerous case. A daemon's working directory is not always a place
the operator has thought about, and a process that can be induced to chdir
somewhere writable will drop its memory — session tokens, decrypted
configuration, private keys — into a directory an attacker is watching. Writing
cores into /tmp is the same failure stated explicitly.

A pattern beginning with "|" pipes the dump to a program instead of writing it
to a path, which is what systemd-coredump and apport do and what this check
expects. An absolute path is also acceptable: the location is fixed and the
operator can set its permissions.

KERNEL-0005 covers the related and separate question of whether setuid programs
dump at all.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "credential-theft", "information-disclosure"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 3,

	Eval: func(fs *fact.Set) catalog.Outcome {
		sc := sysctlFact(fs)

		r, out, ok := runningFor(sc, corePatternKey)
		if !ok {
			return out
		}

		pattern := strings.TrimSpace(r.Value)
		ev := []finding.Evidence{evidenceFor(r)}
		note, driftEv := driftNote(sc, corePatternKey, r.Value)
		ev = append(ev, driftEv...)

		fail := func(detail string) catalog.Outcome {
			return catalog.Outcome{
				Result:   finding.Fail,
				Subject:  corePatternKey,
				Detail:   detail + note,
				Evidence: ev,
			}
		}
		pass := func(detail string) catalog.Outcome {
			return catalog.Outcome{
				Result:   finding.Pass,
				Subject:  corePatternKey,
				Detail:   detail + note,
				Evidence: ev,
			}
		}

		if pattern == "" {
			// An empty core_pattern is not a documented configuration and what
			// the kernel does with it has varied. Guessing in either direction
			// would be a verdict about behaviour nobody specified.
			return catalog.Outcome{
				Result:        finding.Unknown,
				UnknownReason: finding.ReasonAmbiguousState,
				Subject:       corePatternKey,
				Detail:        "kernel.core_pattern is empty. That is not a documented configuration and where the kernel writes a core dump in this state is not specified, so no statement can be made about it.",
				Evidence:      ev,
			}
		}

		if strings.HasPrefix(pattern, "|") {
			handler := handlerPath(pattern)
			if !strings.HasPrefix(handler, "/") {
				// The kernel requires an absolute path for a pipe handler and
				// silently discards the dump when it cannot execute one. No
				// memory reaches the disk, so this is not the exposure the
				// check is about — but the operator's crash collection is not
				// working and nothing else will tell them.
				return pass(fmt.Sprintf(
					"kernel.core_pattern pipes core dumps to %q, so no dump is written to the filesystem. The handler path is relative, and the kernel requires an absolute path for a core-dump handler, so dumps are being discarded rather than collected.",
					handler))
			}
			return pass(fmt.Sprintf(
				"kernel.core_pattern pipes core dumps to %s, so no dump is written to a path a process could influence.",
				handler))
		}

		if !strings.HasPrefix(pattern, "/") {
			return fail(fmt.Sprintf(
				"kernel.core_pattern is %q, which is a relative path, so a core dump is written into the crashing process's current working directory. A process that can be induced to run in a writable directory will drop its memory — including credentials and keys — where another user can read it.",
				pattern))
		}

		if dir := sharedDirOf(pattern); dir != "" {
			return fail(fmt.Sprintf(
				"kernel.core_pattern is %q, which writes core dumps into %s. That directory is world-writable, so process memory — including credentials and keys — lands where any local user can read it.",
				pattern, strings.TrimSuffix(dir, "/")))
		}

		return pass(fmt.Sprintf(
			"kernel.core_pattern is %q, an absolute path, so core dumps land in one known location rather than wherever the crashing process happened to be. Confirm that directory is not readable by unprivileged users; this check cannot inspect its permissions.",
			pattern))
	},

	Remediation: &finding.Remediation{
		Summary: "Pipe core dumps to an absolute-path handler, or write them to a directory only root can read.",
		Effort:  "LOW",
		Steps: []string{
			"Where the distribution ships a crash handler, use it: systemd hosts set 'kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h'.",
			"Where crash dumps are not wanted at all, disable them with a handler that discards: 'kernel.core_pattern = |/bin/false'.",
			"Where dumps must be written to disk, use an absolute path in a directory owned by root and mode 0700, and set a retention policy — a core dump is a copy of process memory and is as sensitive as the process was.",
			"Persist the choice in /etc/sysctl.d/, then verify: sysctl kernel.core_pattern",
		},
		Commands: []string{
			"sysctl kernel.core_pattern",
			"sysctl -w kernel.core_pattern='|/bin/false'",
		},
		Caution: "Changing core_pattern away from a crash handler removes the crash reports an operator may be relying on to diagnose production failures. Confirm what consumes them before switching to a discarding handler.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-11"},
	},

	References: []finding.Reference{
		{Title: "core(5) — naming of core dump files", URL: "https://man7.org/linux/man-pages/man5/core.5.html"},
	},
}

// handlerPath returns the program a piped core_pattern invokes: everything
// after the "|" up to the first space. The remainder is argv, which this check
// does not judge.
func handlerPath(pattern string) string {
	rest := strings.TrimPrefix(pattern, "|")
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// sharedDirOf returns the world-writable directory a pattern writes into, or
// "" if it is not one this check recognises.
func sharedDirOf(pattern string) string {
	for _, dir := range sharedDirs {
		if strings.HasPrefix(pattern, dir) {
			return dir
		}
	}
	return ""
}

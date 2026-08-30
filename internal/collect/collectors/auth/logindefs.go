package auth

import (
	"errors"
	"strings"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// LoginDefsPath is the shadow suite's configuration.
const LoginDefsPath = "/etc/login.defs"

// maxLoginDefsRead bounds the read. login.defs is a few kilobytes of key-value
// lines on every distribution that ships it; anything approaching this cap is
// not that file and must not be held in memory by a root process.
const maxLoginDefsRead = 1 << 20 // 1 MiB

// readLoginDefs records /etc/login.defs.
//
// **It is collected here rather than in the users collector because of what
// reads it.** AUTH-0005 asks how a password is hashed and has to fall back to
// ENCRYPT_METHOD when the PAM line names no algorithm; this collector already
// owns the other two files that decide how a password is accepted and stored.
// USERS-0012 reads the aging defaults out of the same fact, which is one file
// read once rather than twice.
//
// The whole file is parsed rather than the two keys the checks want. The lines
// are `KEY value` pairs and nothing else — no paths, no credentials, no host
// topology — so there is nothing here that a bundle should not carry, and a
// fact holding only what today's checks read is a fact the next check has to
// re-collect.
func readLoginDefs(s system.System) fact.LoginDefs {
	l := fact.LoginDefs{Path: LoginDefsPath}

	res, err := s.ReadFile(LoginDefsPath, maxLoginDefsRead)
	switch {
	case errors.Is(err, system.ErrNotExist):
		// Not every host has one. Alpine's busybox shadow tools do not read
		// it, and a container image frequently has no shadow suite at all —
		// which is NOT_APPLICABLE in the checks, not a failure.
		l.State = fact.SourceAbsent
		return l
	case errors.Is(err, system.ErrPermission):
		l.State = fact.SourceDenied
		l.Msg = "permission denied"
		return l
	case err != nil:
		l.State = fact.SourceError
		l.Msg = err.Error()
		return l
	case collect.NotText(res.Data) != "":
		l.State = fact.SourceError
		l.Msg = collect.NotText(res.Data)
		return l
	}

	l.State = fact.SourcePresent
	l.Digest = res.SHA256

	for i, raw := range strings.Split(string(res.Data), "\n") {
		key, value, ok := parseLoginDefsLine(raw)
		if !ok {
			continue
		}
		l.Settings = append(l.Settings, fact.LoginDefsSetting{
			Key: key, Value: value, Line: i + 1,
		})
	}
	return l
}

// parseLoginDefsLine reads one `KEY value` line.
//
// The grammar is whitespace-separated: a key, then the rest of the line as the
// value with surrounding space trimmed. Comments start with # and there is no
// `=` — a line written `PASS_MIN_DAYS=1`, which people do write, is not a
// setting shadow(3) reads, and this must not report it as one or the check
// would pass a host whose password minimum is not set.
func parseLoginDefsLine(raw string) (string, string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	key, rest, found := strings.Cut(line, " ")
	if !found {
		// Try a tab, which the shipped files use as often as a space.
		key, rest, found = strings.Cut(line, "\t")
		if !found {
			return "", "", false
		}
	}
	if strings.ContainsAny(key, "=") {
		return "", "", false
	}

	value := strings.TrimSpace(rest)
	if value == "" {
		return "", "", false
	}
	// A trailing comment is not part of the value. `UMASK 022 # the default`
	// appears in shipped files.
	if i := strings.Index(value, "#"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if value == "" {
		return "", "", false
	}
	return key, value, true
}

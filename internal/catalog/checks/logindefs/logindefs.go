// Package logindefs holds what two check modules need to say about
// /etc/login.defs.
//
// **It exists so that AUTH and USERS do not import each other.** AUTH-0005
// falls back to ENCRYPT_METHOD and USERS-0012 reads PASS_MIN_DAYS, both out of
// the same fact, and both have to cite a line the same way and describe a
// shadowed definition the same way — two renderings of one file would be two of
// them in one report. The alternative was a module-to-module import, which
// would make the USERS package unreadable without the AUTH one and would put a
// cycle one edit away.
//
// It is pure in the sense every check is: fact and finding, nothing else.
package logindefs

import (
	"fmt"
	"strings"

	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Evidence cites one setting, with the file's digest so an auditor can verify
// the quoted line against the bundle's evidence store.
func Evidence(l fact.LoginDefs, s fact.LoginDefsSetting) finding.Evidence {
	return finding.NewEvidence(l.Path, s.Line, s.Key+" "+s.Value, l.Digest)
}

// ShadowedNote names later definitions of a key that are never read.
//
// **login.defs takes the first match**, which is the reverse of most
// configuration this project reads — sysctl.d, PAM includes and systemd
// drop-ins all let a later file win. So a second ENCRYPT_METHOD lower in the
// file has no effect at all, and an operator who edited that line believes the
// setting is applied. That is worse than never having written it, and it is
// invisible unless a finding says so.
func ShadowedNote(l fact.LoginDefs, key string) string {
	dead := l.Shadowed(key)
	if len(dead) == 0 {
		return ""
	}
	where := make([]string, 0, len(dead))
	for _, s := range dead {
		where = append(where, fmt.Sprintf("line %d (%s)", s.Line, s.Value))
	}
	lead := "One further definition"
	if len(dead) > 1 {
		lead = "Further definitions"
	}
	return fmt.Sprintf(" %s of %s appear below it and %s never read — login.defs takes the first match: %s.",
		lead, key, plural(len(dead), "is", "are"), strings.Join(where, ", "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

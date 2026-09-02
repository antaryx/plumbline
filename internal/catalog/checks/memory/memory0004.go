package memory

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0004 tests whether the probed binaries use the fortified libc entry
// points.
var Check0004 = catalog.Check{
	ID:     "MEMORY-0004",
	Module: "MEMORY",
	Title:  "Privileged binaries are built with _FORTIFY_SOURCE",

	Description: `_FORTIFY_SOURCE substitutes a checked variant for libc calls
whose destination size the compiler can work out, memcpy becomes __memcpy_chk,
sprintf becomes __sprintf_chk, and so on. The checked variant knows how large
the buffer is and aborts instead of writing past it. It costs almost nothing at
run time and turns a class of buffer overflow into a clean abort.

Unlike a stack canary, this is not one symbol but a family: the presence of any
_chk entry point proves the option was in effect for the translation unit that
produced the call.

Absence is the harder half, because two very different binaries produce it. One
was compiled without the option. The other was compiled with it and calls
nothing the macro could substitute, a program that never formats a string or
copies a buffer has nothing to fortify, and looks identical from outside.

The check separates them by counting the unfortified originals. A binary that
references memcpy and sprintf and carries no __memcpy_chk was not fortified.
A binary that references neither is NOT_APPLICABLE: there is no call for the
option to have changed, so reporting it as unfortified would be a finding about
a header macro drawn from a program that would look the same either way.

A binary from a memory-safe language reaches that same NOT_APPLICABLE only if it
calls no fortifiable libc function; one that links against libc for string and
memory work will report FAIL, which reflects what its symbol table says rather
than how it manages memory.`,

	// Low, below the other three. FORTIFY is the weakest of the four
	// mitigations, it is a per-call-site property rather than a whole-binary
	// one, and its absence carries the most benign explanations. Rating it
	// alongside PIE would put the noisiest check in the module at the same
	// level as the clearest.
	BaseSeverity: finding.Low,
	Tags:         []string{"memory", "exploit-mitigation", "fortify-source", "setuid"},
	Requires:     []fact.ID{fact.ELFHardeningID},
	SinceCatalog: 15,

	Eval: func(fs *fact.Set) catalog.Outcome {
		return evaluate(fs, property{
			decide: func(b fact.ELFBinary) verdict {
				if !b.SymbolsRead() {
					return undetermined
				}
				if b.HasFortify {
					return holds
				}
				if b.FortifyCandidates == 0 {
					// Nothing the option could have substituted. Not a pass to
					// celebrate and not a failure to report: the question does
					// not arise for this binary.
					return inapplicable
				}
				return violated
			},
			// No pronoun: the clause is embedded after both "1 probed binary
			// is not" and "3 probed binaries are not", and anything agreeing
			// with number reads wrong in one of the two.
			violationClause:    "built with _FORTIFY_SOURCE, calling fortifiable libc functions with no _chk variant linked",
			passClause:         "reference the fortified _chk libc entry points",
			inapplicableClause: "calls a libc function that _FORTIFY_SOURCE could have substituted, so the option would make no difference to any of them",
			undeterminedClause: "the image carries no symbol table",
			excerpt: func(b fact.ELFBinary) string {
				if b.Symbols != fact.ELFSymbolsRead {
					return symbolNote(b)
				}
				return fmt.Sprintf("%d fortifiable call(s), no _chk variant; %s",
					b.FortifyCandidates, symbolNote(b))
			},
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Rebuild the binary with _FORTIFY_SOURCE, or obtain a build that has it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Confirm the finding independently: readelf -sW <path> | grep '_chk', no output means no fortified entry point was linked.",
			"Check which unfortified calls the binary does make: readelf -sW <path> | grep -E 'memcpy|sprintf|strcpy|printf'. Those are what the option would have covered.",
			"Identify what owns the file: dpkg -S <path> or rpm -qf <path>.",
			"If it was built locally, rebuild with -D_FORTIFY_SOURCE=3 (or =2 on older toolchains) and an optimisation level of at least -O1, which the macro requires to work at all.",
			"Re-check with readelf after rebuilding: a build that silently dropped the flag looks exactly like one that never had it.",
		},
		Commands: []string{
			"readelf -sW /usr/bin/sudo | grep _chk",
			"dpkg -S /usr/bin/sudo || rpm -qf /usr/bin/sudo",
		},
		Caution: "Replacing a setuid-root binary can leave you unable to escalate privileges. Verify a second route to root in a separate session before swapping sudo or su, and keep the original file until the replacement is confirmed working.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "feature_test_macros(7), _FORTIFY_SOURCE", URL: "https://man7.org/linux/man-pages/man7/feature_test_macros.7.html"},
	},
}

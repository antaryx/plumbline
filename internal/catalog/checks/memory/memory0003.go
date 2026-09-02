package memory

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0003 tests whether the probed binaries carry stack-canary
// instrumentation.
var Check0003 = catalog.Check{
	ID:     "MEMORY-0003",
	Module: "MEMORY",
	Title:  "Privileged binaries are built with stack protection",

	Description: `A stack protector places a random value between a function's
local buffers and its saved return address, and checks that the value is intact
before returning. A linear overflow that reaches the return address has to pass
through the canary first, so the corruption is detected and the process aborts
rather than returning to an address the attacker chose. The evidence is a
reference to __stack_chk_fail, the function the compiler-inserted check calls
when the value has changed.

Two limits on what a missing symbol proves, and both matter before acting on a
failure here:

The distribution default, -fstack-protector-strong, instruments only functions
that have local arrays or take the address of a local. A small utility can be
compiled with it correctly and contain no instrumented function at all, and
will then carry no __stack_chk_fail. On a stock Debian host /usr/bin/newgrp is
exactly this case.

A binary from a memory-safe language does not use this mechanism and will not
have the symbol. sudo-rs, which several distributions now ship as /usr/bin/sudo,
gets its memory safety from the language and reports here as though it had none.
That is a limitation of what a symbol table can tell you, not a finding about
the binary.

So this check reports what the symbols say, no more. Confirm what produced the
binary before treating a failure as a defect.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"memory", "exploit-mitigation", "stack-protector", "setuid"},
	Requires:     []fact.ID{fact.ELFHardeningID},
	SinceCatalog: 15,

	Eval: func(fs *fact.Set) catalog.Outcome {
		return evaluate(fs, property{
			decide: func(b fact.ELFBinary) verdict {
				// A stripped image has no symbol table to be absent from.
				// Reading that as "no canary" would report a hardened binary
				// as unhardened on the strength of having found nothing to
				// look at, which is the failure rule 3 exists to prevent.
				if !b.SymbolsRead() {
					return undetermined
				}
				if b.HasCanary {
					return holds
				}
				return violated
			},
			violationClause:    "built with stack protection (no reference to __stack_chk_fail)",
			passClause:         "reference __stack_chk_fail, so their stack frames carry a canary",
			inapplicableClause: "is an installed ELF executable on this host, so there is nothing to report stack protection for",
			undeterminedClause: "the image carries no symbol table",
			excerpt:            symbolNote,
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Confirm what built the binary, then rebuild with a stack protector if it is C or C++.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Rule out the two known false positives first. A binary from a memory-safe language (Rust, Go) does not use this mechanism, and a small C program with no local arrays legitimately has no instrumented function.",
			"Confirm the finding independently: readelf -sW <path> | grep __stack_chk_fail, no output means no reference.",
			"Check the binary is not merely stripped of the table you are reading: a fully stripped static binary reports UNKNOWN here rather than FAIL, so a FAIL means a table was read and the symbol was not in it.",
			"Identify what owns the file: dpkg -S <path> or rpm -qf <path>.",
			"If it was built locally as C or C++, rebuild with -fstack-protector-strong in CFLAGS and confirm with readelf before installing.",
			"If a vendor supplies it, raise it with them, quoting the missing symbol.",
		},
		Commands: []string{
			"readelf -sW /usr/bin/sudo | grep __stack_chk_fail",
			"dpkg -S /usr/bin/sudo || rpm -qf /usr/bin/sudo",
		},
		Caution: "Replacing a setuid-root binary can leave you unable to escalate privileges. Verify a second route to root in a separate session before swapping sudo or su, and keep the original file until the replacement is confirmed working.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "gcc(1), -fstack-protector-strong", URL: "https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html"},
	},
}

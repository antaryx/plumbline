package memory

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0002 tests whether the probed binaries have full RELRO.
var Check0002 = catalog.Check{
	ID:     "MEMORY-0002",
	Module: "MEMORY",
	Title:  "Privileged binaries use full RELRO",

	Description: `RELRO maps a dynamically linked program's relocation data
read-only once the dynamic linker has finished with it. Partial RELRO covers
the sections resolved at startup and stops short of the PLT's global offset
table, because lazy binding writes an address into that table the first time
each imported function is called — so the table has to stay writable for the
life of the process.

That writable table is a well-worn target. An attacker with an arbitrary write
overwrites one entry and takes control at the next call to the function it
belongs to, without needing to defeat any of the other mitigations. Full RELRO
closes it by telling the linker to resolve every relocation before main runs
(BIND_NOW), after which the whole table can be mapped read-only.

The cost is startup time on programs with very large import tables, which is
why it is not universally the default. On a setuid-root utility it is the
right trade.

This check reports FAIL only when the relocation table is actually left
writable. A statically linked binary resolves nothing at run time and is
NOT_APPLICABLE rather than a failure: it has no lazy binding to close.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"memory", "exploit-mitigation", "relro", "setuid"},
	Requires:     []fact.ID{fact.ELFHardeningID},
	SinceCatalog: 15,

	Eval: func(fs *fact.Set) catalog.Outcome {
		return evaluate(fs, property{
			decide: func(b fact.ELFBinary) verdict {
				full, known := b.FullRELRO()
				switch {
				case !known:
					// Statically linked. No dynamic relocations exist, so the
					// property is not one this file can have or lack.
					return inapplicable
				case full:
					return holds
				default:
					return violated
				}
			},
			violationClause:    "protected by full RELRO (the relocation table stays writable at run time)",
			passClause:         "use full RELRO, so their relocation tables are resolved and mapped read-only before the program starts",
			inapplicableClause: "is dynamically linked, so none of them has a relocation table to protect",
			undeterminedClause: "the dynamic section could not be read",
			excerpt: func(b fact.ELFBinary) string {
				return fmt.Sprintf("PT_GNU_RELRO=%v BIND_NOW=%v", b.RELRO, b.BindNow)
			},
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Rebuild the binary with full RELRO, or obtain a build that has it.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Confirm the finding independently: readelf -d <path> | grep -E 'BIND_NOW|FLAGS' — full RELRO needs a GNU_RELRO segment plus BIND_NOW, DF_BIND_NOW or DF_1_NOW.",
			"Check the GNU_RELRO segment is present too: readelf -l <path> | grep GNU_RELRO. A binary with neither needs both flags, not just one.",
			"Identify what owns the file: dpkg -S <path> or rpm -qf <path>.",
			"If a package owns it, check whether the distribution ships a hardened build; most enable this by default and a missing flag suggests the file was replaced locally.",
			"If it was built locally, rebuild with -Wl,-z,relro,-z,now in LDFLAGS and confirm with readelf before installing.",
			"Expect a small startup cost on programs with large import tables; measure it before rejecting the change on that basis.",
		},
		Commands: []string{
			"readelf -d /usr/bin/sudo | grep -E 'BIND_NOW|FLAGS'",
			"readelf -l /usr/bin/sudo | grep GNU_RELRO",
		},
		Caution: "Replacing a setuid-root binary can leave you unable to escalate privileges. Verify a second route to root in a separate session before swapping sudo or su, and keep the original file until the replacement is confirmed working.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "ld(1) — -z relro and -z now", URL: "https://man7.org/linux/man-pages/man1/ld.1.html"},
	},
}

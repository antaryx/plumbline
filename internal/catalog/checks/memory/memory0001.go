package memory

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0001 tests whether the probed binaries are position-independent.
var Check0001 = catalog.Check{
	ID:     "MEMORY-0001",
	Module: "MEMORY",
	Title:  "Privileged binaries are position-independent executables",

	Description: `A position-independent executable can be loaded at a
different base address on every execution, which is what lets ASLR randomise
its code. A binary linked at a fixed address (ELF type ET_EXEC) cannot be
moved, so its instruction addresses are identical on every host running that
build — and an attacker who needs a gadget in it does not have to leak an
address first.

The exposure is worth attention specifically on setuid-root utilities and the
daemons that authenticate: on those, a memory-corruption bug is a local root
escalation rather than a crash, and the missing randomisation is what turns an
unreliable exploit into a repeatable one.

Every mainstream distribution has built these binaries as PIE for years, so a
failure here usually means a locally compiled or vendor-supplied replacement
rather than a distribution default.`,

	// Medium, not High. This is a missing mitigation rather than a
	// vulnerability: it makes exploiting some other defect cheaper, and on its
	// own it grants nobody anything. Rating it High would put it alongside
	// findings that are themselves an exposure, and a severity scale that does
	// not distinguish those is a scale operators stop sorting by.
	BaseSeverity: finding.Medium,
	Tags:         []string{"memory", "exploit-mitigation", "aslr", "setuid"},
	Requires:     []fact.ID{fact.ELFHardeningID},
	SinceCatalog: 14,

	Eval: func(fs *fact.Set) catalog.Outcome {
		return evaluate(fs, property{
			decide: func(b fact.ELFBinary) verdict {
				// PIE is determined by the ELF type, which every parsed image
				// has. There is no undetermined case and no inapplicable one.
				if b.PIE {
					return holds
				}
				return violated
			},
			violationClause:    "position-independent (ET_EXEC, a fixed load address)",
			passClause:         "are position-independent (ET_DYN), so ASLR can randomise their load addresses",
			inapplicableClause: "is an installed ELF executable on this host, so there is nothing to report position-independence for",
			undeterminedClause: "the ELF type could not be read",
			excerpt:            func(b fact.ELFBinary) string { return "ELF type " + b.Type },
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Replace the binary with a position-independent build.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Confirm the finding independently: readelf -h <path> | grep Type — ET_DYN is a PIE, ET_EXEC is not.",
			"Identify what owns the file: dpkg -S <path> or rpm -qf <path>. A file no package owns was installed outside the package manager and is the likely cause.",
			"If a package owns it, reinstall from the distribution: every mainstream distribution has shipped these as PIE for years, so a fixed-address build usually means the file was replaced locally.",
			"If it was built locally, rebuild with -fPIE in CFLAGS and -pie in LDFLAGS, then confirm with readelf before installing.",
			"If a vendor supplies it, raise it with them: this is a build-flag change on their side, not a configuration option on yours.",
		},
		Commands: []string{
			"readelf -h /usr/bin/sudo | grep Type",
			"dpkg -S /usr/bin/sudo || rpm -qf /usr/bin/sudo",
		},
		Caution: "Replacing a setuid-root binary can leave you unable to escalate privileges. Verify a second route to root in a separate session before swapping sudo or su, and keep the original file until the replacement is confirmed working.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SI-16"},
	},

	References: []finding.Reference{
		{Title: "elf(5) — ELF header types", URL: "https://man7.org/linux/man-pages/man5/elf.5.html"},
	},
}

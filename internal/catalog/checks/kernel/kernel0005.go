package kernel

import (
	"fmt"

	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0005 tests that setuid programs do not produce core dumps.
var Check0005 = catalog.Check{
	ID:     "KERNEL-0005",
	Module: "KERNEL",
	Title:  "Setuid programs do not write core dumps",
	Description: `A core dump is a copy of a process's memory written to disk. When
a setuid program dumps core, that memory belongs to the privileged identity the
program assumed — it can hold password hashes, private keys, decrypted secrets
and the contents of files the invoking user cannot read — and the dump lands
somewhere the invoking user often can.

fs.suid_dumpable takes three values. 0 means setuid programs never dump, which
is the safe setting. 1 means they dump like any other program, and is a
straightforward way to read privileged memory. 2 — "suidsafe" — means they dump
but only root may read the result.

0 and 2 both pass. 2 is what systemd-coredump needs to capture a setuid crash at
all, and on a host that collects crash reports it is a deliberate choice rather
than an oversight. It is not equivalent to 0 and the verdict says so: the
privileged memory still reaches the disk, where it outlives the process, is
picked up by backups and is readable by anything that reaches root.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"kernel", "credential-theft", "information-disclosure"},
	Requires:     []fact.ID{fact.SysctlID},
	SinceCatalog: 2,

	Eval: intCheck(
		"fs.suid_dumpable",
		// 0 and 2 both pass. 2 — "suidsafe" — writes the dump but leaves it
		// readable only by root, which is what systemd-coredump needs to
		// capture a setuid crash at all, and is the state a modern host
		// deliberately chooses. This check failed it until catalog 32, which
		// put it in direct contradiction with KERNEL-0029 on the same value.
		func(n int) bool { return n == 0 || n == 2 },
		nil,
		func(n int, ok bool) string {
			switch {
			case ok && n == 0:
				return "fs.suid_dumpable is 0; setuid and setgid programs do not produce core dumps."
			case ok:
				return "fs.suid_dumpable is 2; setuid programs write core dumps that only root may read, which is what systemd-coredump needs to capture such a crash at all. It is not equivalent to 0: the privileged memory still reaches the disk, where it outlives the process and may be captured by backups."
			case n == 1:
				return "fs.suid_dumpable is 1; setuid programs dump core like any other process, so an unprivileged user can obtain a copy of privileged process memory by crashing one."
			default:
				return fmt.Sprintf("fs.suid_dumpable is %d, which is not one of the documented values 0, 1 or 2.", n)
			}
		},
	),

	Remediation: &finding.Remediation{
		Summary: "Set fs.suid_dumpable to 0 and persist it in /etc/sysctl.d/.",
		Effort:  "LOW",
		Steps: []string{
			"Apply immediately: sysctl -w fs.suid_dumpable=0",
			"Persist it: write 'fs.suid_dumpable = 0' to /etc/sysctl.d/60-hardening.conf",
			"Verify the running value: sysctl fs.suid_dumpable",
			"If a setuid service genuinely needs crash dumps, collect them in a controlled directory rather than lowering this globally.",
		},
		Commands: []string{
			"sysctl -w fs.suid_dumpable=0",
			"sysctl fs.suid_dumpable",
		},
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-4"},
		{Framework: "nist-800-53-r5", Control: "SI-11"},
	},

	References: []finding.Reference{
		{Title: "proc(5) — /proc/sys/fs/suid_dumpable", URL: "https://man7.org/linux/man-pages/man5/proc.5.html"},
	},
}

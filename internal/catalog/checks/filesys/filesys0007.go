package filesys

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0007 tests that /tmp is a separate mount with nodev, nosuid and noexec.
var Check0007 = catalog.Check{
	ID:     "FILESYS-0007",
	Module: "FILESYS",
	Title:  "/tmp is a separate mount with nodev, nosuid and noexec",
	Description: `/tmp is the one directory on the host that every account can
write to, which makes it the first place anything an attacker brings with them
lands. A downloaded payload, an extracted archive, a compiled exploit — all of
it arrives in /tmp because /tmp is where an unprivileged account is allowed to
put things.

Three mount options remove three different capabilities from that ground:

- **noexec** — nothing written here can be executed directly. This is the one
  that matters most, because it breaks the step immediately after "download the
  payload" for the ordinary case.
- **nosuid** — a setuid binary here does not run with its owner's privileges.
  Without it, /tmp is a place to park a setuid root shell.
- **nodev** — a device node here does not reach the hardware it names. Without
  it, /tmp is a place to park a reader for the raw disk.

Being a **separate filesystem** is what makes the options possible at all —
they are per-mount properties, so a /tmp that is merely a directory on the root
filesystem cannot carry them. It is also a availability control in its own
right: a runaway process filling /tmp fills the root filesystem, and a host
with no space on / stops being able to log, to rotate, and in some cases to
boot.

None of the three is a strong boundary on its own. noexec is bypassable by
invoking the interpreter directly — 'sh /tmp/x' rather than '/tmp/x', or
'ld.so /tmp/binary' — and anyone who says otherwise has not tried it. What they
do is remove the easy path, which is the path automated tooling and most
opportunistic attacks actually take.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"filesys", "mount", "hardening", "attack-surface"},
	Requires:     []fact.ID{fact.MountsID},
	SinceCatalog: 11,

	Eval: func(set *fact.Set) catalog.Outcome {
		return evalMount(set, mountRule{
			Point:    "/tmp",
			Required: []string{"nodev", "nosuid", "noexec"},
			Why:      "/tmp is where anything an unprivileged account brings to the host lands, so it is the one filesystem where removing the ability to execute, to escalate through setuid and to reach a device is worth the inconvenience",
		})
	},

	Remediation: &finding.Remediation{
		Summary: "Make /tmp a separate filesystem — tmpfs is the simplest — and mount it nodev,nosuid,noexec.",
		Effort:  "MEDIUM",
		Steps: []string{
			"On a systemd host the easiest route is the unit that already exists: 'systemctl unmask tmp.mount' then 'systemctl enable --now tmp.mount'. It mounts a tmpfs on /tmp with the hardening options already set.",
			"To size it or to use a disk-backed filesystem instead, add an fstab entry: 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0'.",
			"Check what is in /tmp before switching to tmpfs. A tmpfs starts empty and does not survive a reboot, so anything a service is currently keeping there is gone — which is correct for /tmp and occasionally a surprise for software that misuses it.",
			"Apply and verify: 'mount -o remount /tmp' for an existing mount, then 'findmnt /tmp' to confirm the options are actually in force rather than merely written in fstab.",
			"Test that noexec does not break anything you depend on. Some package installers and a few Java and Node tools extract executables to /tmp and run them; the usual fix is to point them elsewhere with TMPDIR rather than to give up the option.",
		},
		Commands: []string{
			"findmnt /tmp",
			"systemctl enable --now tmp.mount",
			"mount -o remount,nodev,nosuid,noexec /tmp",
		},
		Caution: "noexec on /tmp breaks software that extracts and runs helpers there — some installers, some JVM native libraries, some Node modules — and the failure is usually an obscure permission error rather than a clear one. Test the workloads on the host before making it permanent, and set TMPDIR for the offenders rather than dropping the option.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "CM-7"},
		{Framework: "nist-800-53-r5", Control: "SC-2"},
	},

	References: []finding.Reference{
		{Title: "mount(8) — filesystem-independent mount options", URL: "https://man7.org/linux/man-pages/man8/mount.8.html"},
	},
}

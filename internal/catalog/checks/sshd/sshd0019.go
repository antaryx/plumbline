package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0019 tests whether sshd checks the ownership and modes of the files it
// trusts before trusting them.
var Check0019 = catalog.Check{
	ID:     "SSHD-0019",
	Module: "SSHD",
	Title:  "sshd verifies ownership and permissions of user key files",
	Description: `Before accepting a public key, sshd checks that the user owns
their home directory, ~/.ssh and ~/.ssh/authorized_keys, and that none of them
is writable by group or other. StrictModes yes is what performs that check.

With StrictModes no, a world-writable home directory becomes a way in: anyone
who can write it can create ~/.ssh/authorized_keys, add their own public key,
and log in as that user. No credential is stolen and nothing is guessed — the
account simply starts trusting a new key. The same applies to a home directory
on a group-writable share, which is the more common accidental case.

The OpenSSH default is yes. The reason this setting gets turned off is almost
always a home directory on a network filesystem whose ownership does not survive
the mount, and the correct fix is to repair the mount rather than to stop
checking.`,

	BaseSeverity: finding.Medium,
	Tags:         []string{"ssh", "remote-access", "authentication", "file-permissions"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: boolSpec{
		Keyword: "StrictModes",
		Secure:  "yes",
		Default: defaultStrictModes,
		Base:    finding.Medium,
		Consequence: "sshd accepts an authorized_keys file regardless of who can write it, so anyone able " +
			"to write a user's home directory can add their own key and log in as that user",
		Assurance: "a key file that is writable by anyone other than its owner is refused rather than trusted",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set StrictModes yes and fix the permissions that made turning it off seem necessary.",
		Effort:  "LOW",
		Steps: []string{
			"Find what would now be rejected: 'find /home -maxdepth 1 -perm /022 -type d' lists group- or world-writable home directories.",
			"Repair them: 'chmod go-w /home/<user>', 'chmod 700 /home/<user>/.ssh', 'chmod 600 /home/<user>/.ssh/authorized_keys', and confirm ownership with 'chown -R <user>: /home/<user>/.ssh'.",
			"Where home directories are on NFS, the usual cause is an ownership mismatch across the mount rather than a genuine permission problem — fix the export or the idmap rather than the sshd setting.",
			"Set 'StrictModes yes' in /etc/ssh/sshd_config — the OpenSSH default, so the line may be removed.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i strictmodes",
			"find /home -maxdepth 1 -perm /022 -type d",
		},
		Caution: "Turning this back on will refuse key authentication for any user whose permissions are currently wrong, and the failure is silent from the client's side — it simply falls through to the next method or is rejected. Audit and repair the directories in the same maintenance window as the change.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "AC-3"},
		{Framework: "nist-800-53-r5", Control: "AC-6"},
		{Framework: "nist-800-53-r5", Control: "IA-5"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — StrictModes", URL: "https://man.openbsd.org/sshd_config#StrictModes"},
	},
}

package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0011 tests the message authentication codes the server will negotiate.
var Check0011 = catalog.Check{
	ID:     "SSHD-0011",
	Module: "SSHD",
	Title:  "No deprecated or truncated MAC is offered",
	Description: `The MAC is what stops an attacker on the path from modifying a
session rather than merely reading it. Encryption without integrity is not a
weaker guarantee, it is a different one — and SSH's own history is a series of
attacks that exploited exactly that gap.

Four categories fail:

- **MD5** in any form. Collision-broken since 2004 and unsuitable for
  authentication for as long as that has been known.
- **SHA-1** in any form. Collision-broken in practice since SHAttered (2017),
  and RFC 9142 deprecates it for SSH.
- **Truncated tags** (-96 variants). Cutting the tag to 96 bits reduces forgery
  resistance for a saving of four bytes per packet.
- **umac-64**. A 64-bit tag is short enough to attack with feasible work.

A related point this check does not fail on: MACs whose names end -etm@openssh.com
apply the MAC to the ciphertext (encrypt-then-MAC), which is the construction
with the sound security proof, while the plain forms MAC the plaintext. Both
appear in OpenSSH's defaults and neither is broken, so preferring the ETM forms
is a recommendation in the remediation rather than a verdict here.

When MACs is absent this check returns UNKNOWN rather than PASS, for the reason
set out in algorithms.go: the effective list is compiled into the binary and
cannot be read from the configuration.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "cryptography", "remote-access"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: algSpec{
		Keyword: "MACs",
		Noun:    "MAC",
		Weak:    weakMAC,
		Base:    finding.High,
		Consequence: "a client that offers one of these will be given it, so the integrity of the " +
			"session rests on a construction that is either broken or deliberately truncated — " +
			"and a session an attacker can modify is not protected by having been encrypted",
		Assurance: "every session this host will agree to carry is protected by a MAC with no known practical forgery",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set an explicit MACs list containing only full-length SHA-2 and UMAC-128 constructions, preferring the ETM forms.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Set an explicit list in /etc/ssh/sshd_config: 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com'.",
			"Note that the AEAD ciphers — chacha20-poly1305 and the -gcm modes — carry their own integrity and ignore this list entirely. On a host whose Ciphers list is AEAD-only, the MACs list only governs the fallback, but leaving a broken entry there is still a negotiable path.",
			"Prefer the absolute form over 'MACs -hmac-sha1*'; the relative form leaves the remainder at the binary's built-in default, which Plumbline reports as UNKNOWN because it cannot be read from configuration.",
			"On RHEL 8+ and Fedora, check 'update-crypto-policies --show' — the system policy can override what sshd_config says.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i '^macs'",
			"ssh -Q mac",
		},
		Caution: "The same compatibility warning as SSHD-0010 applies: older embedded clients frequently offer only hmac-sha1, and restricting this list will disconnect them with 'no matching MAC found'. Check management controllers and appliances before changing a host they reach.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-8"},
		{Framework: "nist-800-53-r5", Control: "SC-8(1)"},
		{Framework: "nist-800-53-r5", Control: "SC-13"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — MACs", URL: "https://man.openbsd.org/sshd_config#MACs"},
		{Title: "RFC 9142 — Key Exchange (KEX) Method Updates for SSH", URL: "https://www.rfc-editor.org/rfc/rfc9142"},
	},
}

package sshd

import (
	"github.com/antaryx/plumbline/internal/catalog"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/finding"
)

// Check0010 tests the symmetric ciphers the server will negotiate.
var Check0010 = catalog.Check{
	ID:     "SSHD-0010",
	Module: "SSHD",
	Title:  "No deprecated or broken cipher is offered",
	Description: `The Ciphers list is what the server will agree to encrypt a
session with. A client chooses from it, so the weakest entry is the weakest
session this host will ever carry — and a client that prefers a weak cipher,
whether through age or through an attacker's influence over the negotiation, is
not exotic.

Three families fail this check:

- **CBC modes** (anything ending -cbc). SSH's use of CBC lets an attacker who
  can inject ciphertext recover 32 bits of plaintext with probability 2^-18 per
  attempt (CVE-2008-5161). OpenSSH removed CBC from its default list in 7.6.
- **64-bit block ciphers** — 3DES, Blowfish, CAST-128. Sweet32 (CVE-2016-2183)
  recovers plaintext from a long-lived connection carrying enough data, and a
  persistent SSH tunnel is exactly the shape that attack wants.
- **RC4** (arcfour). Biased keystream, prohibited for TLS by RFC 7465, removed
  from OpenSSH's defaults in 6.7.

'none' fails for the obvious reason.

When Ciphers is absent this check returns UNKNOWN rather than PASS. The
effective list is compiled into the sshd binary, differs by release, and is
rewritten by Red Hat's crypto-policies; asserting it without reading the binary
would be a guess. See algorithms.go.`,

	BaseSeverity: finding.High,
	Tags:         []string{"ssh", "cryptography", "remote-access"},
	Requires:     []fact.ID{fact.SSHDConfigID},
	SinceCatalog: 6,

	Eval: algSpec{
		Keyword: "Ciphers",
		Noun:    "cipher",
		Weak:    weakCipher,
		Base:    finding.High,
		Consequence: "a client that offers one of these will be given it, so the confidentiality of " +
			"the session rests on the weakest entry in the list rather than the strongest",
		Assurance: "every session this host will agree to carry uses a cipher with no known practical attack",
	}.eval,

	Remediation: &finding.Remediation{
		Summary: "Set an explicit Ciphers list containing only AEAD and CTR modes.",
		Effort:  "MEDIUM",
		Steps: []string{
			"Find out what actually connects before restricting anything. 'journalctl -u sshd | grep -i \"cipher\"' at LogLevel VERBOSE, or a packet capture of a few negotiations, will show which ciphers clients are choosing.",
			"Set an explicit list in /etc/ssh/sshd_config: 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'.",
			"Prefer the absolute form over 'Ciphers -*-cbc'. The relative form leaves the rest of the list at whatever this binary was built with, which is both unauditable and version-dependent — Plumbline reports it as UNKNOWN for that reason.",
			"On RHEL 8+ and Fedora, sshd's list is governed by crypto-policies. Changing sshd_config alone may be overridden; 'update-crypto-policies --show' tells you which profile is active, and a policy submodule is the durable place to make the change.",
			"Validate and reload: 'sshd -t' then 'systemctl reload sshd'.",
		},
		Commands: []string{
			"sshd -T | grep -i '^ciphers'",
			"ssh -Q cipher",
		},
		Caution: "Clients older than roughly 2014 — embedded management controllers, network appliances, legacy Java SSH libraries — may support nothing on a modern list and will fail to connect with 'no matching cipher found'. Inventory what connects to this host before restricting it, especially on anything with out-of-band management.",
	},

	Mappings: []finding.ControlRef{
		{Framework: "nist-800-53-r5", Control: "SC-8"},
		{Framework: "nist-800-53-r5", Control: "SC-8(1)"},
		{Framework: "nist-800-53-r5", Control: "SC-13"},
	},

	References: []finding.Reference{
		{Title: "sshd_config(5) — Ciphers", URL: "https://man.openbsd.org/sshd_config#Ciphers"},
		{Title: "CVE-2008-5161 — SSH CBC plaintext recovery", URL: "https://nvd.nist.gov/vuln/detail/CVE-2008-5161"},
		{Title: "CVE-2016-2183 — Sweet32", URL: "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"},
	},
}

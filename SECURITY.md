# Security policy

This document covers vulnerabilities **in Plumbline itself**. For the threats
Plumbline is designed to withstand and how, see `docs/THREAT-MODEL.md`.

---

## Reporting

**Do not open a public issue.**

Use GitHub's private reporting:
<https://github.com/antaryx/plumbline/security/advisories/new>

Include what you have — a description, affected versions, reproduction steps,
and impact. A rough report sent promptly beats a polished one sent late.

---

## What to expect

Plumbline is maintained by one person. These commitments are set at a level
that can actually be met; over-promising a response time is its own kind of
security failure.

| Stage | Target |
|---|---|
| Acknowledgement | 5 working days |
| Initial assessment | 14 days |
| Fix or mitigation for critical issues | 30 days where feasible |
| Public disclosure | Coordinated with you, default 90 days |

If you have not heard back within the acknowledgement window, please chase —
an unanswered report usually means it went astray, not that it was ignored.

---

## What counts

Plumbline runs as root and parses attacker-influenceable input, so its own
vulnerabilities matter more than a typical CLI's.

**In scope:**

- Privilege escalation via a scanned filesystem — symlink or TOCTOU attacks
  against a privileged read, hostile paths, unsafe file-type handling
- Denial of service against a running scan — hangs, unbounded reads, resource
  exhaustion triggered by filesystem contents
- Terminal control-sequence injection reaching an operator's terminal, a log,
  or a CI console
- Sensitive data written insecurely: bundles or reports created with permissive
  modes, redaction that fails to redact
- Command injection anywhere in the collection or rendering path
- Malicious bundle handling: path traversal, decompression bombs, type
  confusion in `plumbline eval`
- Supply-chain issues: signing, provenance, reproducibility, the install script
- **A check that reports `PASS` for a genuinely insecure state.** This is a
  security issue, not merely a bug. It ends an investigation that should have
  continued, and it has no external symptom.

**Out of scope** (see `docs/THREAT-MODEL.md` §4):

- Attacks requiring root on the scanned host — at that point the attacker
  controls the answers, and Plumbline reports state rather than attesting to it
- A compromised kernel or rootkit lying to userspace
- False `FAIL` results — annoying, and a normal bug; use the false-positive
  issue template
- Third-party check packs or extensions (v3): an extension is code you chose to
  run, and a signature identifies the publisher, not the behaviour

---

## Supported versions

| Version | Security fixes |
|---|---|
| Current major | Yes |
| Previous major | 12 months after its successor's release |
| Pre-1.0 (`0.x`) | No — development releases, not for production |
| Older | No |

Full policy in `docs/VERSIONING.md` §10.

---

## Disclosure

- We will credit you unless you prefer otherwise.
- Fixes ship with a GitHub Security Advisory and a CVE where warranted.
- For a security-relevant *check correction* — a check that wrongly reported
  `PASS` — the release notes state the check ID, affected versions, and the
  conditions under which it was wrong, so users can determine whether they were
  affected and re-check. Anyone who acted on that `PASS` needs to be able to
  find out.
- Bad releases are marked and superseded, never deleted. Deleting artifacts
  breaks pinned pipelines and destroys the evidence.

---

## Verifying releases

Every release artifact is signed. Verification instructions are in
`docs/DEPLOYMENT.md` §3, and you should use them — a security tool you cannot
verify is a security tool you should not run as root.

If a release is unsigned, has a mismatched signature, or was not built by the
documented workflow identity, treat it as compromised and report it here.

# ADR-0015 — Password hashes never enter a bundle; `--redact` does not anonymise account names

**Status:** accepted · **Date:** 2026-08-19

## Context

the v0.2 work plan (WP-17) requires this decision before the USERS module
ships:

> **Redaction interacts here.** `--redact` currently drops the hostname; a user
> list is at least as identifying. Decide whether redaction extends to account
> names and write it down — this is a `--redact` semantics decision and needs an
> ADR, not a quiet choice inside a collector.

Building the module surfaced a second and more urgent question the runbook does
not name. Evidence recording is wired at the seam: `recordingSystem.ReadFile`
hands the bytes of **every** file a collector reads to the evidence store, by
design, so that a collector cannot produce a finding citing evidence the bundle
does not contain. Applied to `/etc/shadow` that design copies every password
hash on the host into the bundle.

A bundle is not an internal scratch file. `DATA-MODEL.md` §6 describes it as
the durable artifact the whole architecture exists for, `--redact` exists so it
can be **sent**, and the product's own documentation encourages attaching one
to an audit. A password hash is not a record of what happened on a host; it is
the credential itself, in a form an attacker can attack offline, indefinitely,
on hardware of their choosing. Shipping that inside a portable archive would
make Plumbline the most efficient credential-exfiltration tool on the system it
is auditing.

So there are two questions, and they have different answers.

## Decision

### 1. Credential material never enters a bundle. This is not a redaction option.

`internal/collect` holds an explicit set of paths whose bytes are never handed
to the evidence recorder: `/etc/shadow`, `/etc/gshadow`,
`/etc/security/opasswd`, `/etc/master.passwd`. The exclusion is enforced at the
seam, in `recordingSystem`, and not in the collector — a collector that had to
remember not to store credentials is a collector that will one day forget, and
the forgetting would be invisible until a bundle full of hashes had already
been emailed to somebody.

**There is deliberately no flag to disable it.** A setting that turns this off
has no legitimate use and one obvious illegitimate one.

The `users.shadow` fact carries no hash either. It records only what a check
needs to judge: whether the field was empty, whether the account is locked, and
which crypt scheme the hash uses. The hash and its salt are classified and
discarded inside the collector and exist nowhere else in the process.

Consequently a finding derived from `/etc/shadow` cites the path and the line
and carries **no digest**, because there is no stored blob to verify it
against. That is the honest representation of "we read this and refused to keep
it", and it is why ADR-0009 made the digest field optional.

### 2. `--redact` does not anonymise account names.

Account names stay as they are. Three reasons, in order of weight:

- **It would make the module useless.** "Account `<redacted>` has an empty
  password" is not a finding, it is a rumour. Every remediation step in USERS
  names the account; the operator cannot act on a report that will not say
  which one.
- **It would break every suppression baseline.** `Fingerprint(checkID,
  subject)` is derived from the subject, and the subject of a USERS finding is
  the account name. Redacting it changes the fingerprint, which silently
  invalidates suppressions written last quarter and breaks SARIF deduplication.
  `DATA-MODEL.md` §5.4 classes that as a breaking schema change.
- **Pseudonymisation is a different feature.** A stable per-bundle pseudonym
  would preserve internal consistency while withholding the real name, but it
  touches the renderer, the fingerprint derivation and the bundle format, and
  it needs its own work package. Doing a third of it inside a collector would
  produce the worst of both.

What `--redact` covers is therefore stated precisely rather than implied: it
removes the **hostname**. It is not an anonymiser, and `CLI-SPEC.md` must say
so where the flag is documented rather than leaving a reader to infer a
guarantee that is not offered.

The GECOS field is not collected at all. It is where distributions record a
person's real name, office and telephone number; no check asserts anything
about it, and a field nothing reads is a field that only creates exposure.
Evidence citing a `/etc/passwd` line is reconstructed from the parsed fields
rather than quoting the raw line, for the same reason.

## Consequences

- A bundle can be sent to an auditor without sending the host's password
  hashes, which is the difference between a portable artifact and a liability
- A bundle still contains the account list, and that list is identifying.
  Operators must treat bundles as sensitive — they are written `0600` and
  `DATA-MODEL.md` §6.1 already says so — and `--redact` must not be described
  anywhere as making one safe to publish
- `/etc/passwd` **is** stored as evidence, so a finding about a shell or a uid
  can cite a verifiable source. The two files are treated differently because
  they are different: one is a directory, the other is a credential store
- Findings derived from `/etc/shadow` cannot be verified against the bundle by
  re-hashing. An auditor who needs that must go back to the host, which is the
  correct place for a password hash to live
- The exclusion list is a list, and a future collector reading a credential
  file not on it would store its bytes. `collect.IsCredentialFile` is exported
  so a collector's own tests can assert the exclusion applies to what it reads,
  rather than trusting it silently

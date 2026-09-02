# FAQ

### How is this different from Lynis?

Lynis is mature, has far more checks, and covers platforms Plumbline does not.
The differences that matter are structural:

- Plumbline never guesses. A check that cannot read what it needs returns
  `UNKNOWN` with a reason code instead of a documented default. Posture is never
  printed without coverage beside it.
- Findings come from a portable evidence bundle. A scan stays re-evaluable
  months later against a newer catalog, and analysis can happen on a different
  machine from collection.
- Checks are pure functions, testable from fixtures. All 112 checks are covered
  by a fixture corpus and six recorded distributions rather than by manual runs.
- The output is a schema. `findings/v1` is validated in CI and is the API.

Where Lynis is ahead: breadth, platform coverage, and years of field use.

### Why is there no compliance score?

Control text for CIS, PCI-DSS, ISO 27001 and SOC 2 is copyrighted and cannot be
redistributed. And a number a tool invents is not compliance. An auditor decides
that. Plumbline ships mappings to NIST SP 800-53 r5 and DISA STIG as bare
control identifiers, which are US Government works. See
[`COMPLIANCE-DATA-POLICY.md`](COMPLIANCE-DATA-POLICY.md) and
[`../LEGAL-DISCLAIMER.md`](../LEGAL-DISCLAIMER.md).

The `cis-l1` profile is this project's reading of Level 1 themes. It says so in
its own description. Passing it is evidence of hardening, not of compliance.

### Why does it not fix anything?

`scan --fix` proposes a script and never runs it, which is what
[ADR-0006](adr/) actually decided. What it rules out is Plumbline applying one.
A tool that both judges and modifies a host produces judgements nobody can
audit, and remediation on a production host is a decision for someone with the
surrounding context. Plumbline prints the exact commands and the cautions that
go with them. `plumbline explain CHECK-ID` gives the full procedure.

### Can I run it unprivileged?

Yes, and the report says what it cost. Checks that could not read what they
needed report `UNKNOWN` instead of passing, so coverage falls. Use
`--strict-privileges` to exit 10 rather than produce a report that covers half
the host.

### Why is my coverage only 60%?

Coverage is evaluated checks over applicable checks. It falls for two reasons.
Permissions: run as root. Or genuine ambiguity: `/etc/nsswitch.conf` says
accounts come from LDAP, so the local files are not the whole picture and an
unresolvable uid cannot be called stray.

`NOT_APPLICABLE` does not reduce coverage. A host with no sshd is not a poorly
covered host.

### Does it phone home?

No. No telemetry, no update check, no network call of any kind. The offline CI
job runs a full scan inside `unshare -n` and asserts a byte-identical document.
See [`PRIVACY.md`](PRIVACY.md) and T-13 in [`THREAT-MODEL.md`](THREAT-MODEL.md).

### Why so few dependencies?

The binary runs as root, and every import is attack surface. `go.mod`
declares four: cobra, pflag, klauspost/compress and a JSON-schema validator. The
shipped binary links three, because the schema validator is used only by the
tests. A terminal styling library went in during the release candidates and came
out before GA, because it cost thirteen transitive modules for a box border. The
SBOM published with every release makes the count checkable.

### Can I write my own checks?

Not in 2.0.0. Declarative check packs and a subprocess extension protocol are
later work in [`ROADMAP.md`](ROADMAP.md), deferred until there is enough field
use to know what shape the extension point should be. Profiles select from the
catalog and cannot add to it, because a finding that exists only under one
profile cannot be reproduced by anyone else.

### Does it support macOS or BSD?

No. Linux only, glibc and musl. macOS is later work and will be announced only
once it is in CI with golden bundles.

### What does UNKNOWN actually mean?

The check ran, could not obtain what it needed, and did not guess. Every
`UNKNOWN` carries a machine-readable reason: permission denied, unparseable,
truncated, ambiguous, or a fact that was never collected. Treat it as a finding
until it is resolved. It is not a pass.

### Is the terminal output stable?

No, and nothing should parse it. `findings/v1` is the stable API and is
schema-validated in CI. The terminal layout can change in a patch release, which
is why there are two renderers rather than one with a flag.

### Why is FAIL shown as WARNING?

Because the word beside a check should say what to do about it. The result is
`FAIL` in the JSON, in the exit code and in the score.

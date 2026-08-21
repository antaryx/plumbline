# FAQ

### How is this different from Lynis?

Lynis is mature, has far more checks, and covers platforms Plumbline does not.
The differences that matter are structural:

- **Plumbline never guesses.** A check that cannot read what it needs returns
  `UNKNOWN` with a reason code rather than a documented default. Posture is
  never printed without coverage beside it.
- **Findings are derived from a portable evidence bundle**, so a scan is
  re-evaluable months later against a newer catalog, and analysis can happen on
  a different machine from collection.
- **Checks are pure functions**, testable from fixtures. 79 checks are covered
  by a fixture corpus and six recorded distributions rather than by manual runs.
- **The output is a schema.** `findings/v1` is validated in CI and is the API.

Where Lynis is ahead: breadth, platform coverage, and years of field use.

### Why is there no compliance score?

Because control text for CIS, PCI-DSS, ISO 27001 and SOC 2 is copyrighted and
cannot be redistributed, and because a number a tool invents is not compliance —
an auditor decides that. Plumbline ships mappings to NIST SP 800-53 r5 and DISA
STIG as **bare control identifiers**, which are US Government works. See
[`COMPLIANCE-DATA-POLICY.md`](COMPLIANCE-DATA-POLICY.md) and
[`../LEGAL-DISCLAIMER.md`](../LEGAL-DISCLAIMER.md).

The `cis-l1` profile is this project's reading of Level 1 *themes*. It says so
in its own description, and passing it is evidence of sensible hardening, not of
compliance.

### Why does it not fix anything?

There is no `--fix` flag and there never will be ([ADR-0006](adr/)). A tool that
both judges and modifies a host is a tool whose judgements you cannot audit, and
remediation on a production host is a decision with blast radius that belongs to
a human with context. Plumbline prints the exact commands and the cautions that
go with them — `plumbline explain CHECK-ID` gives you the full procedure.

### Can I run it unprivileged?

Yes, and it will tell you what that cost. Checks that could not read what they
needed report `UNKNOWN` rather than passing, so coverage falls visibly. Use
`--strict-privileges` to exit 10 rather than reporting a confident-looking scan
of half a host.

### Why is my coverage only 60%?

Coverage is evaluated checks over *applicable* checks. It falls for two reasons:

- **Permissions** — run as root.
- **Genuine ambiguity** — for example `/etc/nsswitch.conf` says accounts come
  from LDAP, so the local files are not the whole picture and an unresolvable
  uid cannot be called stray.

`NOT_APPLICABLE` does **not** reduce coverage: a host with no sshd is not a
poorly covered host.

### Does it phone home?

No. No telemetry, no update check, no network call of any kind. The offline CI
job runs a full scan inside `unshare -n` and asserts a byte-identical document.
See [`PRIVACY.md`](PRIVACY.md) and T-13 in [`THREAT-MODEL.md`](THREAT-MODEL.md).

### Why only four dependencies?

Because the binary runs as root and every import is attack surface. A terminal
styling library was added during the release candidates and removed before GA
when it turned out to cost thirteen transitive modules for a box border. The
SBOM published with every release makes the claim checkable.

### Can I write my own checks?

Not at v1.0.0. Declarative check packs and a subprocess extension protocol are
v2 and v3 work in [`ROADMAP.md`](ROADMAP.md), deliberately after enough field
use to know what shape the extension point should be. Profiles let you *select*
from the catalog today; they cannot add to it, because a finding that exists
only under one profile is one nobody else can reproduce.

### Does it support macOS or BSD?

No. Linux only, glibc and musl. macOS is v2 work and will be announced only once
it is in CI with golden bundles.

### What does UNKNOWN actually mean?

The check ran, could not obtain what it needed, and declined to guess. Every
`UNKNOWN` carries a machine-readable reason: permission denied, unparseable,
truncated, ambiguous, or a fact that was never collected. **Treat it as a
finding until resolved** — it is not a pass.

### Is the terminal output stable?

No, and nothing should parse it. `findings/v1` is the stable API and is
schema-validated in CI. The terminal layout may change in a patch release; that
is why there are two renderers rather than one with a flag.

### Why is FAIL shown as WARNING?

Because the word beside a check should say what to do about it. The result is
`FAIL` everywhere it matters: the JSON, the exit code and the score.

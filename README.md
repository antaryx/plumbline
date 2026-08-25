<p align="center">
  <img src="docs/assets/logo.png" alt="Plumbline" width="600">
</p>

<p align="center">
  <a href="https://github.com/antaryx/plumbline/releases/latest"><img src="https://img.shields.io/github/v/release/antaryx/plumbline?include_prereleases&label=release&color=22C55E" alt="Latest release"></a>
  <a href="https://github.com/antaryx/plumbline/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/antaryx/plumbline/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.24%2B-00ADD8" alt="Go 1.24+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="Apache-2.0"></a>
  <img src="https://img.shields.io/badge/dependencies-4-22C55E" alt="4 dependencies">
  <img src="https://img.shields.io/badge/network%20calls-0-22C55E" alt="Zero network calls">
</p>

<h3 align="center">A deterministic, offline, evidence-first Linux security auditor.</h3>

<p align="center">
  <b>79 checks · 9 modules · catalog 13</b><br>
  Every check has PASS and FAIL fixtures enforced in CI, and every scan says
  plainly what it could <em>not</em> determine.
</p>

---

> **Status: `v1.0.0`, released.** `findings/v1`, flag names, exit codes and
> check IDs are contracts from here (see [`docs/VERSIONING.md`](docs/VERSIONING.md)).
> Everything in Go stays `internal/` and may change without notice
> ([ADR-0007](docs/adr/0007-json-schema-is-the-api.md)). Known gaps are recorded
> rather than reclassified; see [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Table of contents

- [Why Plumbline](#why-plumbline)
- [What it checks](#what-it-checks)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [In a pipeline](#in-a-pipeline)
- [Offline by construction](#offline-by-construction)
- [How it works](#how-it-works)
- [Documentation](#documentation)
- [Development](#development)
- [Licence](#licence)

## Why Plumbline

### It never guesses

A check that cannot read what it needs returns `UNKNOWN` with a reason code. It
does not return `PASS`.

Asked about `pam_pwquality`'s minimum password length on a stock Fedora,
Plumbline reports `UNKNOWN`. The parameter is set nowhere on that host, so the
effective value comes from libpwquality's compiled-in default, which is a
property of a binary rather than of any file the scan can read. Reporting an
unread setting as a pass produces false assurance the operator has no way to
detect.

Posture is never printed without coverage beside it, for the same reason. A
score of 86 over 17% coverage describes a host that was mostly not examined.

### No network calls

Plumbline opens no network socket and does not use dbus, `systemctl` or
`nft list ruleset`. The offline test suite runs a full scan inside `unshare -n`
and asserts the document is byte-identical to one produced with the network up.
There is no telemetry and no update check.

### Deterministic, re-evaluable evidence

A scan writes a portable `.plb` evidence bundle holding the facts observed, not
the verdicts drawn from them. The same bundle and the same catalog always
produce byte-identical findings, so a bundle collected on a production host can
be analysed somewhere safer, and one collected last quarter can be re-evaluated
against today's checks.

Six golden bundles recorded from real distributions (Ubuntu 24.04 stock and
hardened, Debian 13, Fedora 44, Rocky 9, Alpine 3.20) are committed and
re-evaluated on every build. A catalog change that moves a verdict on a real
host therefore shows up as a diff in review.

### Supply chain

Four dependencies: cobra, pflag, klauspost/compress and a JSON-schema validator.
The binary runs as root, so every import is attack surface. A terminal dashboard
library was added for the summary output and then removed again for that reason;
the reversal is recorded in the [CHANGELOG](CHANGELOG.md).

Every release artifact is signed with keyless [cosign](https://docs.sigstore.dev/)
and ships an SPDX SBOM, so the dependency count can be checked against the
artifact instead of taken from this file.

### No auto-remediation

Plumbline generates fix instructions with the exact commands and the cautions
that go with them. It does not apply them. There is no `--fix` flag, and
[ADR-0006](docs/adr/) records the decision not to add one.

## What it checks

| Module | Checks | Reads |
|---|---:|---|
| SSHD | 19 | `sshd_config` and its includes, `Match` block scoping |
| KERNEL | 16 | `/proc/sys` and the `sysctl.d` files, separately |
| USERS | 10 | `passwd`, `shadow`, `group`, `nsswitch.conf`: four facts, four readabilities |
| FILESYS | 10 | one shared traversal: setuid, world-writable, device nodes, unowned files, mount options |
| AUTH | 6 | the PAM stack as a graph, `pwquality.conf`, `faillock.conf` |
| CRON | 5 | who may write the schedule; metadata only, never a crontab |
| LOGGING | 5 | rsyslog in all three of its syntaxes, journald with drop-ins |
| SERVICES | 5 | systemd enablement recovered from symlinks |
| NETWORK | 3 | nftables, iptables, ufw, firewalld, as configured rather than as loaded |

Full detail is in [`docs/CHECK-REFERENCE.md`](docs/CHECK-REFERENCE.md), which is
generated from the catalog and not hand-maintained.

## Installation

### Signed packages (recommended)

Download from the [releases page](https://github.com/antaryx/plumbline/releases/latest).
Every release carries `.deb`, `.rpm` and `.tar.gz` for `linux/amd64` and
`linux/arm64`, each with an SPDX SBOM, plus a signed checksum file.

```bash
VERSION=1.0.0
BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION

curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
curl -fsSLO $BASE/checksums.txt
curl -fsSLO $BASE/checksums.txt.sig
curl -fsSLO $BASE/checksums.txt.pem
```

Verify the download before installing it. The binary runs as root on the host
being audited.

```bash
# 1. The signature is genuine, and came from this repository's release workflow.
cosign verify-blob checksums.txt \
  --signature   checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/antaryx/plumbline/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. The file you downloaded is the file that was signed.
sha256sum -c --ignore-missing checksums.txt

# 3. Install.
sudo tar -xzf plumbline_${VERSION}_linux_amd64.tar.gz -C /usr/local/bin plumbline
```

Signing is keyless. There is no private key to leak or rotate, and the
certificate records the workflow, repository and commit that produced the
artifact.

For `.deb` or `.rpm`, verify the checksum the same way, then:

```bash
sudo dpkg -i plumbline_${VERSION}_linux_amd64.deb     # Debian, Ubuntu
sudo rpm -i  plumbline_${VERSION}_linux_amd64.rpm     # RHEL, Rocky, Fedora
```

Both packages declare no dependencies. The binary is statically linked, so the
same build runs on glibc and musl systems, including inside a rescue shell.

Each artifact has an SBOM beside it:

```bash
curl -fsSL $BASE/plumbline_${VERSION}_linux_amd64.tar.gz.sbom.spdx.json \
  | jq -r '.packages[].name'
```

### From source

```bash
git clone https://github.com/antaryx/plumbline
cd plumbline
make build          # → dist/plumbline
```

`go.mod` states a floor of Go 1.24. Releases are built with 1.25, because Go
supports only its two newest majors and 1.24 no longer receives stdlib security
fixes. No other tooling is needed.

## Quickstart

### Audit this host

```bash
sudo plumbline scan
```

Root is not required, but an unprivileged scan cannot read `/etc/shadow` or most
of `/etc/ssh`, and it reports those checks as `UNKNOWN` rather than passing
them. A transient progress indicator runs on stderr while the collectors work,
then erases itself before the report starts.

The report groups checks by module, then summarises:

```
[+] CRON  · 5 checks, 1 failing
  - The system crontab is owned by root and writable only by root       [ OK ]
  - Access to crontab is restricted by an allow list               [ WARNING ]

[=] Scan summary
──────────────────────────────────────────────────────────────────────────────

  ╭──────────────────────────────────────────────────────────────────────────╮
  │ posture   93.4   coverage 100.0% of applicable checks                    │
  │ ███████████████████████████████████████████████████████████████████░░░░░ │
  ╰──────────────────────────────────────────────────────────────────────────╯

  ╭────────────────╮ ╭────────────────╮ ╭────────────────╮ ╭────────────────╮
  │ PASS           │ │ FAIL           │ │ UNKNOWN        │ │ SKIPPED        │
  │ 74             │ │ 5              │ │ 0              │ │ 0              │
  ╰────────────────╯ ╰────────────────╯ ╰────────────────╯ ╰────────────────╯

  79 checks evaluated · catalog 13
```

The dashboard is drawn on a fixed 78-column grid rather than from `$COLUMNS`, so
two scans of an unchanged host are byte-identical. Colour is suppressed by
`--no-color`, by `NO_COLOR`, when stdout is not a terminal, and always when
writing to `--output`. The boxes are still drawn in each case.

### Score against a baseline

```bash
plumbline profiles                    # what this binary carries
sudo plumbline scan --profile cis-l1  # score against that baseline only
sudo plumbline scan --profile ./mine.json
```

A profile declares which checks apply to a class of host. Checks outside it are
reported as `SKIPPED` rather than omitted, and they leave the posture
denominator, so a thirty-check baseline reports coverage against thirty checks.

`cis-l1` is a Level 1 hardening baseline and not a CIS benchmark. No check here
carries a CIS mapping, so the selection is this project's reading of the themes.
Passing it is evidence of hardening, not of compliance.

### Read the catalog from your terminal

```bash
plumbline explain SSHD-0004
```

Prints what the check tests and why, which facts it reads, what each result
state means for it, and the full remediation with every step, command and
caution, which the scan report only summarises. It needs no host, bundle,
privileges or network access. The ID is case-insensitive.

### Keep the evidence

```bash
sudo plumbline scan --save-bundle host.plb   # scan and keep what it saw
sudo plumbline collect -o host.plb           # collect only; evaluate elsewhere
plumbline eval host.plb                      # re-evaluate against today's catalog
```

A `.plb` file is an evidence bundle: the facts observed. A findings document
(`--json > out.json`) holds verdicts already drawn from those facts and cannot
be re-evaluated or diffed. Passing one to `eval` or `diff` produces an error
that names the flag which writes the file those commands expect.

## In a pipeline

### Gate a build

```bash
plumbline scan --json --fail-on high --min-coverage 90
```

Exit codes are a contract: `0` clean · `2` findings at or above `--fail-on` ·
`3` posture below `--threshold` · `4` degraded, meaning a collector failed or
coverage fell short · `10` missing privileges · `11` timeout · `70` internal ·
`130` interrupted. `4` takes precedence over `2`, because a pipeline that treats
an incomplete scan as a passing one reports green while part of the host went
unread.

### GitHub Advanced Security

```bash
plumbline scan --format sarif -o plumbline.sarif
```

SARIF 2.1.0. `UNKNOWN` maps to `warning` rather than to an informational `none`,
because a check that could not determine an answer did not pass. Accepted risks
are emitted as native SARIF suppressions carrying the written justification.
`PASS` and `NOT_APPLICABLE` are counted in the run's invocation rather than
emitted as results, which keeps the results list to findings that need
attention. The full mapping is in
[`docs/adr/0018-sarif-mapping.md`](docs/adr/0018-sarif-mapping.md).

### Diff two points in time

```bash
plumbline diff march.plb today.plb
```

Findings are sorted into four buckets and unchanged findings are not printed:
RESOLVED, NEW FAILURE, NEWLY SUPPRESSED, and REGRESSED. The last of these covers
a suppression that has lapsed.

### Accept a risk without hiding it

```bash
plumbline scan --suppress accepted.json
```

A suppressed finding becomes `SKIPPED`, keeps its severity, detail and evidence,
records the result it would otherwise have reported, and appears under
`[=] Accepted risks` with the justification. Rules carry an optional expiry,
measured against the scan's own start time rather than the wall clock, so an
archived bundle re-evaluates identically.

There is no auto-discovered filename. The file has to be named explicitly with
`--suppress <file>`, which keeps a scan's inputs visible in the command that ran
it.

> `findings/v1` is the public API and is schema-validated in CI. The terminal
> report is not. Its layout may change in a patch release, so nothing should
> parse it. The two renderers are separate for this reason.

## Offline by construction

Plumbline talks to no daemon. It opens no dbus connection and does not run
`systemctl`, `nft list ruleset` or `iptables -S`.

The constraint is what makes the following possible:

- Service enablement is recovered from the filesystem. `systemctl enable`
  creates a symlink in `<target>.wants/` and nothing else, so reading those
  directories recovers exactly what `systemctl is-enabled` would report, without
  a running init system.
- A mounted image audits like a live host. `--root /mnt` works because nothing
  asks the kernel about itself.
- A bundle collected months ago re-evaluates today. There is no live state to
  have gone stale.

The cost is that Plumbline reports what is configured, not what is loaded. A
host with a correct `nftables.conf` and a disabled `nftables.service` has no
running firewall. The two halves are reported by separate modules, neither of
which claims the other's result.

## How it works

Auditing splits in two. Collectors touch the OS and produce typed facts; checks
are pure functions from facts to findings. A scan captures a portable fact
bundle, and every finding is derived from it.

The split is what makes 79 checks testable from fixtures rather than from
virtual machines, and it is enforced mechanically rather than by convention.
`make verify` fails if anything outside `internal/system` touches the OS, or if
a check imports a clock, a network or randomness.

Reading files as root on a host that may already be compromised has its own
threat model. Every privileged read uses `O_NOFOLLOW` and `O_NONBLOCK`, so a
symlink planted at a config path cannot redirect the reader into `/etc/shadow`
and a FIFO cannot hang the scan. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Documentation

| Using it | |
|---|---|
| [`docs/QUICKSTART.md`](docs/QUICKSTART.md) | Zero to a useful scan, one page |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Verified install, packages, air-gap, uninstall |
| [`docs/USAGE.md`](docs/USAGE.md) | Every command, with realistic examples |
| [`docs/CI-INTEGRATION.md`](docs/CI-INTEGRATION.md) | GitHub Actions, GitLab, Jenkins, and what to gate on |
| [`docs/FALSE-POSITIVES.md`](docs/FALSE-POSITIVES.md) | Why they happen, the known ones, how to report one |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Permissions, slow scans, container and distro quirks |
| [`docs/FAQ.md`](docs/FAQ.md) | How it differs from Lynis, why no compliance score, why no `--fix` |

| Start here | |
|---|---|
| [`docs/CHECK-REFERENCE.md`](docs/CHECK-REFERENCE.md) | Every check in full; generated from the catalog |
| [`docs/MODULE-CATALOG.md`](docs/MODULE-CATALOG.md) | Modules, counts and severities; generated |
| [`docs/CLI-SPEC.md`](docs/CLI-SPEC.md) | Commands, flags, precedence, exit codes, streams |
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | Vocabulary used across the documentation |

| Design | |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, the OS seam, collection, evaluation, safety |
| [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md) | Facts, findings, bundles; normative |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Plumbline's own attack surface |
| [`docs/PRIVACY.md`](docs/PRIVACY.md) | Exactly what a bundle contains, and the no-telemetry commitment |
| [`docs/SUPPLY-CHAIN.md`](docs/SUPPLY-CHAIN.md) | Dependencies, signing, SBOMs, independent verification |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | Measured budgets, and why the sweep is disk-bound |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Build, sign, publish, install, upgrade, rollback |
| [`docs/adr/`](docs/adr/) | Decisions that would be expensive to reverse |
| [`schema/findings-v1.schema.json`](schema/findings-v1.schema.json) | The public API |

| Contributing | |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | The working agreement; read before any change |
| [`docs/CHECK-AUTHORING.md`](docs/CHECK-AUTHORING.md) | How to add a check, end to end |
| [`docs/FIXTURES.md`](docs/FIXTURES.md) | Fixture format, the test corpus, golden bundles |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | Four version numbers and their contracts |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Three stable majors, and the rejected ideas |
| [`SUPPORT.md`](SUPPORT.md) | Where to ask, and what is and is not supported |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) · [`MAINTAINERS.md`](MAINTAINERS.md) | Conduct, and who decides |

**Background**

| Document | Purpose |
|---|---|
| [`docs/PROJECT-BRIEF.md`](docs/PROJECT-BRIEF.md) | Identity, scope, non-goals, differentiation |
| [`docs/DOCUMENT-MAP.md`](docs/DOCUMENT-MAP.md) | Which documents exist, which are missing, and why |
| [`docs/audit/argus-design-audit.md`](docs/audit/argus-design-audit.md) | The audit of the predecessor design that produced this project, and context for several of its decisions |

## Development

```bash
make verify        # fmt, vet, tests, architectural invariants — the gate
make test-race
make golden-diff   # did a catalog change move a verdict on any real distro?
make docs          # regenerate the check reference from the catalog
```

`make verify` is what CI runs and what a pull request has to pass. It blocks on
more than tests: the OS seam, check purity, the PASS and FAIL fixture rule for
every check, and whether the generated documentation still matches the catalog.

`internal/collect/collectors/sshd/sshd.go` and
`internal/catalog/checks/sshd/sshd0002.go` are the reference implementations.
They carry more comments than normal; use them as templates.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

**Plumbline produces evidence, not compliance conclusions.** See
[`LEGAL-DISCLAIMER.md`](LEGAL-DISCLAIMER.md) and
[`docs/COMPLIANCE-DATA-POLICY.md`](docs/COMPLIANCE-DATA-POLICY.md).

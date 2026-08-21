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
<p align="center"><em>Hang a line. See what's true.</em></p>

<p align="center">
  <b>79 checks · 9 modules · catalog 13</b><br>
  Every check has PASS and FAIL fixtures enforced in CI, and every scan says
  plainly what it could <em>not</em> determine.
</p>

---

> **Status: `v1.0.0-rc1` — release candidate.** `findings/v1`, flag names, exit
> codes and check IDs are contracts from here. Everything in Go stays
> `internal/` and may change without notice (ADR-0007). What remains before
> `v1.0.0` is documentation and a measured performance baseline; see
> [`docs/ROADMAP.md`](docs/ROADMAP.md).

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

This is the whole argument. A check that cannot read what it needs returns
`UNKNOWN` with a reason code — never `PASS`.

A lesser tool asked about `pam_pwquality`'s minimum password length on a stock
Fedora reports the documented default and calls it a pass. Plumbline reports
`UNKNOWN`, because the parameter is set nowhere on that host and the effective
value comes from libpwquality's compiled-in default — a property of a binary,
not of any file it can read. **Turning ignorance into false assurance is the
single worst thing an auditor can do**, and it is undetectable from the outside.

Posture is never printed without coverage beside it, for the same reason: a
score of 86 over 17% coverage is not a host that is mostly fine, it is a host
that was mostly not examined.

### 100% offline — zero network calls

No dbus, no `systemctl`, no `nft list ruleset`, no network socket of any kind.
The offline suite runs a full scan inside `unshare -n` and asserts it produces a
byte-identical document to an online one. There is no telemetry, no update
check, and nothing to opt out of.

### Deterministic, re-evaluable evidence

A scan writes a portable `.plb` **evidence bundle** — the facts observed, not
the verdicts drawn from them. The same bundle and the same catalog produce
byte-identical findings, forever, so a bundle collected on a production host can
be analysed somewhere safer, and one collected last quarter can be re-evaluated
against today's checks.

Six **golden bundles** recorded from real distributions — Ubuntu 24.04 stock and
hardened, Debian 13, Fedora 44, Rocky 9, Alpine 3.20 — are committed and
re-evaluated on every build, so a catalog change that moves a verdict on a real
host shows up as a diff in review rather than as a surprise in production.

### Supply-chain security you can check

**Four dependencies.** Not four hundred: cobra, pflag, klauspost/compress and a
JSON-schema validator. This binary runs as root, so every import is attack
surface, and a terminal dashboard is not worth thirteen transitive modules — a
judgement this project made, reversed itself on, and then made again in public
([CHANGELOG](CHANGELOG.md)).

Every release artifact is signed with keyless [cosign](https://docs.sigstore.dev/)
and ships an SPDX SBOM, so the dependency claim above is machine-checkable
rather than a sentence in a README.

### No auto-remediation, ever

Plumbline generates fix instructions with the exact commands and the cautions
that go with them. It never applies them. There is no `--fix` flag and there
never will be ([ADR-0006](docs/adr/)).

## What it checks

| Module | Checks | Reads |
|---|---:|---|
| **SSHD** | 19 | `sshd_config` and its includes, `Match` block scoping |
| **KERNEL** | 16 | `/proc/sys` and the `sysctl.d` files, separately |
| **USERS** | 10 | `passwd`, `shadow`, `group`, `nsswitch.conf` — four facts, four readabilities |
| **FILESYS** | 10 | one shared traversal: setuid, world-writable, device nodes, unowned files, mount options |
| **AUTH** | 6 | the PAM stack as a graph, `pwquality.conf`, `faillock.conf` |
| **CRON** | 5 | who may write the schedule — metadata only, never a crontab |
| **LOGGING** | 5 | rsyslog in all three of its syntaxes, journald with drop-ins |
| **SERVICES** | 5 | systemd enablement recovered from symlinks |
| **NETWORK** | 3 | nftables, iptables, ufw, firewalld — configured, not loaded |

Full detail: [`docs/CHECK-REFERENCE.md`](docs/CHECK-REFERENCE.md) — generated
from the catalog, never hand-maintained.

## Installation

### Signed packages — the recommended route

Download from the [releases page](https://github.com/antaryx/plumbline/releases/latest).
Every release carries `.deb`, `.rpm` and `.tar.gz` for `linux/amd64` and
`linux/arm64`, each with an SPDX SBOM, plus a signed checksum file.

```bash
VERSION=1.0.0-rc1
BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION

curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
curl -fsSLO $BASE/checksums.txt
curl -fsSLO $BASE/checksums.txt.sig
curl -fsSLO $BASE/checksums.txt.pem
```

**Verify before you install it.** This binary is going to run as root on the
host you are auditing; taking it on trust is the one step that undoes every
other guarantee here.

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

Signing is **keyless**: there is no private key to leak, rotate or lose, and the
certificate records the workflow, repository and commit that produced the
artifact — a stronger statement than *"somebody with the key signed this"*.

For `.deb` or `.rpm`, verify the checksum the same way, then:

```bash
sudo dpkg -i plumbline_${VERSION}_linux_amd64.deb     # Debian, Ubuntu
sudo rpm -i  plumbline_${VERSION}_linux_amd64.rpm     # RHEL, Rocky, Fedora
```

Both packages are dependency-free — the binary is statically linked, so the same
one runs on glibc and musl alike, including inside a rescue shell.

Want to see what is inside before installing? Each artifact has an SBOM beside
it:

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

Go 1.24 is the floor `go.mod` states; releases are built with 1.25, because Go
supports only its two newest majors and a binary that runs as root is the last
one to build with an unmaintained toolchain. No other tooling is needed.

## Quickstart

### Audit this host

```bash
sudo plumbline scan
```

Root is not required, but it is what makes the answer complete — an unprivileged
scan cannot read `/etc/shadow` or half of `/etc/ssh`, and it says so rather than
passing those checks. A transient indicator runs on **stderr** while the
collectors work, then erases itself before the report starts.

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

The dashboard is drawn on a fixed 78-column grid, never from `$COLUMNS`, so two
scans of an unchanged host are byte-identical and a nightly diff shows nothing.
Colour is suppressed by `--no-color`, by `NO_COLOR`, when stdout is not a
terminal, and always when writing to `--output`; the boxes still draw.

### Score against a baseline

```bash
plumbline profiles                    # what this binary carries
sudo plumbline scan --profile cis-l1  # score against that baseline only
sudo plumbline scan --profile ./mine.json
```

A profile declares which checks apply to this class of host. Checks outside it
are reported as `SKIPPED` — never omitted — and **leave the posture
denominator**, so a thirty-check baseline reports coverage against thirty checks
rather than looking like a poorly covered scan.

`cis-l1` is a Level 1 hardening baseline and **not a CIS benchmark**: no check
here carries a CIS mapping, so the selection is this project's reading of the
themes. Passing it is evidence of sensible hardening, not of compliance.

### Read the catalog from your terminal

```bash
plumbline explain SSHD-0004
```

Prints what the check tests and why, which facts it reads, what each result
state means for it, and the remediation with every step, command and caution —
the procedure the scan report deliberately summarises. No host, no bundle, no
privileges, no network. The ID is case-insensitive.

### Keep the evidence

```bash
sudo plumbline scan --save-bundle host.plb   # scan and keep what it saw
sudo plumbline collect -o host.plb           # collect only; evaluate elsewhere
plumbline eval host.plb                      # re-evaluate against today's catalog
```

**`.plb` is an evidence bundle — the facts observed.** A findings document
(`--json > out.json`) holds verdicts already drawn from those facts and cannot
be re-evaluated or diffed. Hand one to `eval` or `diff` and it says so, and
names the flag that writes the file it wanted.

## In a pipeline

### Gate a build

```bash
plumbline scan --json --fail-on high --min-coverage 90
```

Exit codes are a contract: `0` clean · `2` findings at or above `--fail-on` ·
`3` posture below `--threshold` · `4` **degraded** — a collector failed or
coverage fell short · `10` missing privileges · `11` timeout · `70` internal ·
`130` interrupted. `4` outranks `2` deliberately: *"the scanner could not see
your host"* has to be louder than *"your host is misconfigured"*, or a pipeline
believes it is green while half the host went unread.

### GitHub Advanced Security

```bash
plumbline scan --format sarif -o plumbline.sarif
```

SARIF 2.1.0. `UNKNOWN` becomes a `warning` rather than an informational `none`
— a check that could not tell is not a check that passed, and a security tab
that says otherwise is worse than no security tab. Accepted risks arrive as
native SARIF suppressions carrying the justification a human wrote. `PASS` and
`NOT_APPLICABLE` are counted in the run's invocation rather than emitted as
results, because seventy-four passing checks bury the three that matter. Full
mapping: [`docs/adr/0018-sarif-mapping.md`](docs/adr/0018-sarif-mapping.md).

### Diff two points in time

```bash
plumbline diff march.plb today.plb
```

Four buckets, and unchanged findings are not printed: **RESOLVED**, **NEW
FAILURE**, **NEWLY SUPPRESSED**, and **REGRESSED** — a suppression that lapsed,
which is the one nobody remembers to look for.

### Accept a risk without hiding it

```bash
plumbline scan --suppress accepted.json
```

A suppressed finding becomes `SKIPPED`, keeps its severity, detail and evidence,
records what it *would* have said, and appears under `[=] Accepted risks` with
the justification. Rules carry an optional expiry, measured against the **scan's
own start time** rather than the wall clock, so an archived bundle re-evaluates
identically forever.

There is no auto-discovered filename. An explicit `--suppress <file>` is the
deterministic choice for a tool that decides whether a host is safe.

> `findings/v1` is the public API and is schema-validated in CI. **The terminal
> report is not** — its layout may change in a patch release, so nothing should
> parse it. That is the whole reason there are two renderers rather than one
> with a flag.

## Offline by construction

Plumbline talks to no daemon. There is no dbus connection, no `systemctl`, no
`nft list ruleset`, no `iptables -S`, and no network call of any kind.

That is not asceticism; it is what makes the other properties possible:

- **Service enablement is recovered from the filesystem.** `systemctl enable`
  creates a symlink in `<target>.wants/` and nothing else — so reading those
  directories recovers exactly what `systemctl is-enabled` would report, without
  a running init system.
- **A mounted image audits like a live host.** `--root /mnt` works because
  nothing asks the kernel about itself.
- **A bundle collected months ago re-evaluates today.** There is no live state
  to have gone stale.

The cost is stated rather than hidden: this reports what is **configured**, not
what is loaded. A host with a perfect `nftables.conf` and a disabled
`nftables.service` has no firewall, and the two halves are reported by two
modules that each decline to claim the other's.

## How it works

Auditing splits in two. **Collectors** touch the OS and produce typed **facts**;
**checks** are pure functions from facts to **findings**. A scan captures a
portable fact bundle, and every finding is derived from it.

That split is what makes 79 checks testable from fixtures instead of from a
thousand virtual machines, and it is enforced mechanically rather than by
convention — `make verify` fails if anything outside `internal/system` touches
the OS, or if a check imports a clock, a network or randomness.

Reading files on a host you do not trust, as root, is its own threat model:
every privileged read is `O_NOFOLLOW` and `O_NONBLOCK`, so a symlink planted at
a config path cannot redirect the reader into `/etc/shadow` and a FIFO cannot
hang the scan. See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Documentation

| Start here | |
|---|---|
| [`docs/CHECK-REFERENCE.md`](docs/CHECK-REFERENCE.md) | Every check in full — *generated from the catalog* |
| [`docs/MODULE-CATALOG.md`](docs/MODULE-CATALOG.md) | Modules, counts and severities — *generated* |
| [`docs/CLI-SPEC.md`](docs/CLI-SPEC.md) | Commands, flags, precedence, exit codes, streams |
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | Vocabulary — small, disproportionately useful |

| Design | |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, the OS seam, collection, evaluation, safety |
| [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md) | Facts, findings, bundles — normative |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Plumbline's own attack surface — gates running as root |
| [`docs/adr/`](docs/adr/) | Decisions that would be expensive to reverse |
| [`schema/findings-v1.schema.json`](schema/findings-v1.schema.json) | The public API |

| Contributing | |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | The working agreement — read before any change |
| [`docs/CHECK-AUTHORING.md`](docs/CHECK-AUTHORING.md) | How to add a check, end to end |
| [`docs/FIXTURES.md`](docs/FIXTURES.md) | Fixture format, the test corpus, golden bundles |
| [`docs/VERSIONING.md`](docs/VERSIONING.md) | Four version numbers and their contracts |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Three stable majors, and the graveyard of rejected ideas |

## Development

```bash
make verify        # fmt, vet, tests, architectural invariants — the gate
make test-race
make golden-diff   # did a catalog change move a verdict on any real distro?
make docs          # regenerate the check reference from the catalog
```

`make verify` is what CI runs and what a pull request faces. It blocks on more
than tests: the OS seam, check purity, the PASS+FAIL fixture rule for every
check, and whether the generated documentation still matches the catalog.

Reference implementation: `internal/collect/collectors/sshd/sshd.go` and
`internal/catalog/checks/sshd/sshd0002.go`, deliberately over-commented. Copy
their shape.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

**Plumbline produces evidence, not compliance conclusions.** See
[`LEGAL-DISCLAIMER.md`](LEGAL-DISCLAIMER.md) and
[`docs/COMPLIANCE-DATA-POLICY.md`](docs/COMPLIANCE-DATA-POLICY.md).

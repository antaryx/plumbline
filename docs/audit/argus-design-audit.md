# Audit — `argus-project-design.md` v0.1

**Auditor:** design review, pre-build
**Subject:** ARGUS — Security Intelligence Platform, Complete Project Design Document v0.1 (1,529 lines)
**Date:** 2026-08-18

---

## 1. Verdict

**Do not build this as written.**

The document is a good *feature wishlist* and a poor *engineering design*. It is strong on breadth (20 modules, 253 checks, 8 frameworks, 8 output formats) and near-silent on the four things that actually determine whether a tool like this ever ships and stays correct:

1. how system state is **collected** (once) versus how checks are **evaluated** (many times),
2. how a check is **tested** without a VM,
3. what the **output contract** is and how it survives version changes,
4. what may **legally** be shipped in the compliance data files.

It also self-describes as "DESIGN COMPLETE" while containing zero acceptance criteria, zero error handling, zero threat model for the tool itself, and a data model that is only implied.

Roughly **60% of the content is reusable** — the check catalog, the CLI surface, the severity model, the differentiation instinct. The architecture and the scope need to be rebuilt. That is what the rest of this document set does.

**Headline numbers:**

| Metric | Assessment |
|---|---|
| Findings raised | 34 (6 blocker, 17 major, 11 minor) |
| Realistic build effort as specified | ~3–5 engineer-years |
| Realistic build effort for the rescoped v1 | ~4–6 months solo, part-time |
| Sections needing full rewrite | §4 Architecture, §5.1 Module interface, §7 Scoring, §8 Compliance, §11 Plugins, §14 CVE DB, §17 Roadmap |
| Sections reusable close to as-is | §5.2 check catalog (content), §6 check schema (shape), §9 CLI, §10 config, §13 report sections |
| Sections missing entirely | data model, error model, testing strategy, threat model, licensing policy, acceptance criteria, performance budgets |

---

## 2. Finding index

Severity meanings:

- **BLOCKER** — the project fails, becomes illegal, or produces wrong results if built as written.
- **MAJOR** — significant rework, credibility damage, or user harm; must be resolved before v1.0.0.
- **MINOR** — quality, polish, or honesty issue; fix opportunistically.

| ID | Sev | Area | One-line |
|---|---|---|---|
| A-01 | BLOCKER | Scope | Scope is 3–5 engineer-years with no shippable slice defined |
| A-02 | BLOCKER | Legal | Shipping CIS / PCI-DSS / ISO 27001 control data conflicts with those bodies' licences |
| A-03 | BLOCKER | Correctness | CVE matching by installed version against NVD is wrong for distro packages |
| A-04 | BLOCKER | Architecture | No fact-collection layer; N modules independently walk the whole filesystem |
| A-05 | BLOCKER | Testability | Module interface reads the live system directly — 253 checks become untestable |
| A-06 | BLOCKER | Extensibility | Go's `plugin` package cannot deliver the promised "stable plugin ABI" |
| A-07 | MAJOR | Legal | Compliance *percentages* misrepresent org-scope frameworks as host-testable |
| A-08 | MAJOR | Identity | "Argus" is heavily occupied in security tooling (confirmed) |
| A-09 | MAJOR | Architecture | No scan-root abstraction; the documented container usage scans the container |
| A-10 | MAJOR | Data | Output schema — the real public API — is undefined and unversioned |
| A-11 | MAJOR | Correctness | Scoring formula does not define SKIP / N-A handling; unprivileged runs score as failures |
| A-12 | MAJOR | Correctness | Scores are not comparable across versions; denominator moves every release |
| A-13 | MAJOR | Correctness | Risk Score modifiers are arbitrary and double-count the Hardening Index |
| A-14 | MAJOR | Security | "SHA-256 embedded in the report" is presented as a digital signature; it is not |
| A-15 | MAJOR | Security | Plugins as subprocesses are called "sandboxed"; the parent runs as root |
| A-16 | MAJOR | Security | No threat model for the tool's own attack surface (TOCTOU, hostile filenames, FIFOs) |
| A-17 | MAJOR | Security | Report files contain sensitive inventory; no file-permission or redaction policy |
| A-18 | MAJOR | Consistency | "No network during scan" contradicts CLOUD, MALWARE, CRYPTO and DNSSEC checks |
| A-19 | MAJOR | Engineering | No error model: no per-check timeout, no panic isolation, no `ERROR` result state |
| A-20 | MAJOR | Engineering | Exit-code scheme is ambiguous when multiple severities are present |
| A-21 | MAJOR | Data | Vulnerability DB shape (BadgerDB + NVD deltas) is the wrong delivery model |
| A-22 | MAJOR | Honesty | Platform matrix over-promises: macOS "Full", 3 BSDs, 5 architectures, no test hardware |
| A-23 | MAJOR | Honesty | "300+ checks" claimed; 253 enumerated |
| A-24 | MINOR | Honesty | Scan-duration claims (~2 / 10–15 / 25 min) invented pre-build |
| A-25 | MINOR | Honesty | Privilege coverage figures (40% / 85% / 100%) invented |
| A-26 | MINOR | Correctness | `sudo -l` needs a tty/password; will hang or fail non-interactively |
| A-27 | MINOR | Correctness | Rootkit signature matching and "/proc hiding" detection are unreliable by construction |
| A-28 | MINOR | Build | PDF via chromedp reintroduces a browser dependency, killing "single binary" |
| A-29 | MINOR | Distribution | `curl \| bash` installer for a security tool; distro inclusion promised as deliverable |
| A-30 | MINOR | Security | Config precedence trusts `./argus.yaml` from the current directory, as root |
| A-31 | MINOR | Correctness | Parsing command output without forcing `LC_ALL=C` is locale-fragile |
| A-32 | MINOR | UX | Severity encoded by colour and emoji only; no `NO_COLOR` / non-TTY / width handling |
| A-33 | MINOR | Scope | v1.1 roadmap (daemon, web UI, gRPC, multi-host) reintroduces the declared non-goals |
| A-34 | MINOR | Process | No acceptance criteria or definition of done for any milestone |

---

## 3. Blockers in detail

### A-01 — Scope is unbuildable as specified

**Where:** §2.1, §5.2, §8.1, §13.1, §17.2.

The document commits to, in one product: 20 modules / 253 checks, 8 compliance frameworks, 8 output formats, 7 operating systems, 5 CPU architectures, an embedded CVE database with an update pipeline, a signed plugin registry with hosted infrastructure, a remediation engine emitting Bash *and* Ansible *and* (per `--remediate-format`) Puppet and Chef, rootkit detection, and a threat-intelligence feed.

For calibration: Lynis covers a comparable check surface, is backed by a company, and has been developed since 2007. Trivy's vulnerability database alone is a full-time team's product. The plugin registry is a hosted service with key management, and it is listed as a v0.5.0 feature.

The roadmap compounds this: eight 0.x milestones before v1.0.0, each of which is itself a substantial project, with no statement of what "done" means for any of them.

**Resolution:** cut to a v1 that one person can ship and then defend. See `docs/ROADMAP.md`. The rule applied there: **v1 ships one platform, one collection model, zero hosted infrastructure, and zero third-party licensed data.**

---

### A-02 — Compliance data files are a licensing violation waiting to happen

**Where:** §8.1, §16 (`compliance/cis-ubuntu-22.yaml`, `pci-dss-v4.yaml`, `hipaa-security-rule.yaml`, `iso27001-2022.yaml`, `soc2.yaml`), §6 (`compliance:` block with control IDs), and the Apache-2.0 licence declared in §1.

The design ships data files named after, and containing mappings into, standards with very different legal status:

| Framework | Status | Can you ship control text / a derived mapping file? |
|---|---|---|
| NIST SP 800-53 Rev 5 | US Government work | Yes |
| DISA STIG | US Government work | Yes |
| CIS Benchmarks | Copyright CIS, distributed under their own terms; derivative/redistribution restricted | No, not without agreeing to their terms |
| PCI-DSS v4.0 | Copyright PCI SSC, licensed for use, redistribution restricted | No |
| ISO/IEC 27001:2022 | Copyright ISO/IEC, sold per-copy | No — this one is unambiguous |
| HIPAA Security Rule | US regulation (CFR text is public) | Text yes; a "HIPAA compliance product" claim is a separate risk |
| SOC 2 TSC | Copyright AICPA | No |

Publishing an Apache-2.0 repository that contains a file called `iso27001-2022.yaml` with Annex A control descriptions is a straightforward copyright problem, and it is the kind of problem that gets a repository taken down rather than politely emailed about. Bare control *identifiers* ("A.5.17") used as cross-references are a much weaker claim and are generally how open-source tools handle it — but you cannot reproduce the control text, and you should not imply endorsement.

**Resolution:** `COMPLIANCE-DATA-POLICY.md` becomes a required document. v1 ships mappings only to public-domain frameworks (NIST 800-53, STIG). For everything else, the tool supports *user-supplied* mapping packs: the user brings their licensed copy of the benchmark, the tool consumes it. This is also better product design — it works for internal corporate frameworks too.

---

### A-03 — The CVE correlation design produces mass false positives

**Where:** §14.1, §14.2, `SOFTWARE-0003`, `SOFTWARE-0006`.

The stated process is: enumerate installed packages via rpm/dpkg/brew/pkg → match name and version against NVD → emit a finding severity-mapped from CVSS.

This is the single most common way vulnerability scanners get a bad reputation, because Debian, Ubuntu, RHEL and SUSE **backport security fixes without changing the upstream version number**. `openssl 3.0.2-0ubuntu1.15` is not vulnerable to what NVD says `openssl 3.0.2` is vulnerable to. A naive matcher reports it anyway. On a normal Ubuntu LTS server this design will emit hundreds of false criticals, and every one of them destroys trust in the other 250 checks.

The secondary problem is CPE matching itself: NVD's CPE data for OS packages is inconsistent, version-range logic is subtle, and there is no reliable package-name → CPE mapping.

**Resolution:** never match OS packages against NVD directly. Use vendor security data, which encodes "fixed in this distro version": Debian Security Tracker / DSA, Ubuntu USN + OVAL, Red Hat OVAL and VEX, SUSE OVAL, Alpine `secdb`, and OSV as the aggregation layer for language ecosystems. This is a v2 feature precisely because doing it correctly is a project in itself.

---

### A-04 — There is no fact-collection layer

**Where:** §4.1, §4.2 step 4, §5.1.

Modules are defined as `Run(ctx) ([]Finding, error)` and are executed in parallel goroutines. Each module independently reaches for system state.

Now count the checks that need a full filesystem traversal: `FILESYSTEM-0005` (SUID inventory), `-0006` (SGID), `-0007` (world-writable files), `-0008` (world-writable dirs without sticky bit), `-0009` (unowned files), `PENTEST-0001`, `-0002`, `-0005`, `MALWARE-0002`, `-0012`, `INTEGRITY-0004`. Under the design as written, that is up to a dozen independent `find /` equivalents running **concurrently**, competing for the same disk, thrashing the page cache, each re-stat'ing millions of inodes.

On a server with a large `/var` or a mounted NAS this does not finish. Parallelism actively makes it worse, because these are IO-bound, not CPU-bound.

The same duplication applies to cheaper state: `/etc/passwd` gets parsed by AUTH, USERS, FILESYSTEM and PENTEST; `sysctl -a` by KERNEL, NETWORK and MEMORY; the package list by SOFTWARE, INTEGRITY and CRYPTO.

**Resolution:** split the engine in two. **Collectors** gather typed facts, exactly once, with explicit dependencies and a single filesystem walk that all consumers subscribe to. **Checks** are pure functions from facts to findings. This is the central architectural change in `docs/ARCHITECTURE.md`, and it is what makes A-05 solvable at the same time.

---

### A-05 — 253 checks cannot be tested under this interface

**Where:** §5.1, §16 (`tests/fixtures/`).

`Run(ctx Context) ([]Finding, error)` reads the real machine. To test "does SSH-0009 correctly flag `arcfour` in `Ciphers`", you need a machine configured that way. The design acknowledges this with `tests/integration/ (needs test VM)` and then quietly hopes.

With 253 checks × ~4 outcomes each (pass / fail / not-applicable / skipped) you need roughly a thousand system states. Nobody builds a thousand VMs. What actually happens is that checks ship untested, a distro-specific config format shifts, and the tool silently reports PASS on a broken system — which for a security auditor is the worst possible failure mode, worse than crashing.

**Resolution:** checks never touch the OS. They receive facts. Facts come from a `System` interface (`fs.FS` + exec + procfs + sysctl + clock) that has a real implementation and a fixture implementation. A test becomes: load `testdata/ubuntu-22.04-hardened/`, run the catalog, assert on findings. Golden-file tests over recorded fact bundles from real machines then give you regression coverage across distros for free.

This single change is the difference between a maintainable 250-check catalog and an abandoned one.

---

### A-06 — "Stable plugin ABI" is not achievable in Go

**Where:** §11, §17.2 (v1.0.0 milestone: "stable plugin ABI"), §16 (`internal/plugin/sandbox.go`).

Go's `plugin` package requires the plugin and host to be built with the **identical Go toolchain version and identical versions of every shared dependency**, does not work on Windows, is fragile on macOS, and forces dynamic linking — which breaks the "single static binary, no interpreter" property listed as the primary differentiator against Lynis in §18.

You cannot ship "stable plugin ABI" as a v1.0.0 milestone. Every Go patch release breaks every plugin.

**Resolution:** three viable extension mechanisms, none of which is `plugin`:
1. **Declarative check packs** (YAML: read this file, apply this predicate) — covers ~70% of real checks, is safe, and is testable. This is what v3 should lead with.
2. **Subprocess protocol** — plugin is any executable, speaks JSON over stdio, receives facts and returns findings. No ABI, any language.
3. **WASM** (`wazero`, no CGO) — real sandboxing, deterministic, but a heavier lift.

---

## 4. Selected majors in detail

### A-07 — Compliance percentages are a liability, not a feature

`ComplianceScore[framework] = (PassedControls / TotalApplicableControls) × 100` produces a sentence like "This host is 87% PCI-DSS compliant."

That sentence is meaningless and someone will paste it into an audit response. PCI-DSS v4.0 covers policy, physical security, personnel, third-party management, and network segmentation — the majority of it cannot be assessed by a process running on one host. The denominator "TotalApplicableControls" quietly excludes everything untestable, so the percentage is computed against a subset the reader cannot see.

**Resolution:** never emit a compliance percentage. Emit *coverage*, explicitly framed: "Of PCI-DSS v4.0, this tool tests 34 requirements at host level; 29 pass, 5 fail. This covers approximately 11% of the standard and is not an assessment of compliance." Ship `LEGAL-DISCLAIMER.md`. The value delivered is **evidence collection**, which auditors genuinely want, not a score.

### A-09 — No scan-root breaks the documented container usage

§17.1 advertises `docker run --pid=host --privileged ghcr.io/argus/argus scan`. That container has its own `/etc`, its own `/etc/ssh/sshd_config`, its own package database. The scan reports on the container image, confidently, while the operator believes it reports on the host.

A `--root /host` prefix applied at the `System` layer fixes the container case, and simultaneously enables offline scanning of a mounted disk image, forensic analysis of a snapshot, and the entire fixture-based test strategy from A-05.

### A-11 / A-12 / A-13 — The scoring model does not survive contact

Three separate defects:

1. `HardeningIndex = Σ(Passed × Weight) / Σ(All × Weight)`. There are four result states (PASS/FAIL/N-A/SKIP) but only two appear in the formula. A user running unprivileged skips ~60% of checks by the document's own claim, so their score collapses to ~40 — the tool punishes them for not running as root. N-A checks (e.g. SSH checks on a host with no sshd) equally must leave the denominator.

2. Denominator stability. Add 20 checks in v1.1 and every user's score changes with no change to their system. Scores must be pinned to a **catalog version**, comparisons across catalog versions must be refused or explicitly caveated, and the catalog version must appear in every report.

3. The Risk Score modifiers (`+10 if any CRITICAL`, `+5 if no firewall`, `−5 if SELinux enforcing`) are unjustified magic numbers that double-count: "no firewall detected" is already a failed NETWORK check inside the Hardening Index, so it is counted twice, at an arbitrary weight. Either derive risk from exposure context (is this host internet-facing? multi-user?) or drop the second score entirely. A single honest number beats two numbers where one is invented.

### A-14 — A hash is not a signature

§8.3 lists "Digital signature of report file (SHA-256)" and §19 lists "Report integrity: SHA-256 hash embedded in every report."

A hash computed over a document and stored inside that document proves nothing to anyone — an attacker who edits the report recomputes the hash. This matters here because §8.3 sells it as audit evidence.

**Resolution:** detached signatures (minisign or cosign), keys documented in `SUPPLY-CHAIN.md`, plus optional RFC 3161 timestamping if you want "this report existed on this date" to hold up. Alternatively: state plainly that reports are not authenticated and let the user's own signing pipeline handle it. Either is fine. Calling a hash a signature is not.

### A-16 / A-17 — The tool's own attack surface is unexamined

This binary runs as root and reads attacker-influenced input: filenames in world-writable directories, home directories of unprivileged users, cron files, `.netrc` contents. §19 lists nine desirable properties and no threats. Missing at minimum:

- **TOCTOU / symlink attacks** — the classic: check stats `/tmp/foo`, attacker swaps it for a symlink to `/etc/shadow` before the read. Requires `openat2(RESOLVE_NO_SYMLINKS)` or equivalent discipline on every privileged read.
- **FIFOs and device nodes** — a `find`-driven walk that opens an unprivileged user's named pipe blocks forever, as root. Trivial local DoS of your scanner.
- **Hostile filenames** — newlines, ANSI escape sequences and terminal control codes in filenames land in a terminal report and in a log; ANSI injection into an operator's terminal is a real technique.
- **Shell interpolation** — every `sed -i 's/.../.../'` string in the remediation output (§12.1) is a command constructed by string concatenation.
- **Resource exhaustion** — recursive walks over `/proc`, over network mounts, over cyclic bind mounts.
- **Report confidentiality (A-17)** — the report contains the user list, open ports, package inventory, and file paths. `~/.argus/reports/` has no stated permissions. That file is a reconnaissance gift; it must be `0600`, and evidence capture must be redactable.

**Resolution:** `THREAT-MODEL.md` is a v1-gating document, not a nice-to-have.

### A-19 / A-20 — No error model, ambiguous exit codes

The result vocabulary is PASS / FAIL / N/A / SKIP. There is no `ERROR`. So when a check panics on a malformed config file, or hangs on a stale NFS mount, or hits a permission error the author did not anticipate, the design has nowhere to put that — and the likeliest implementations either crash the whole scan or silently report PASS.

Similarly, exit codes: `2 = CRITICAL found`, `3 = HIGH found`, `4 = MEDIUM found`, `5 = below threshold`. A scan with critical *and* high findings that is also below threshold matches three codes. Nothing defines precedence, and CI behaviour therefore depends on implementation accident.

**Resolution:** a fifth result state `ERROR` that is never silently a PASS; per-check timeouts with the check marked `ERROR(timeout)`; panic recovery per check; a documented exit-code precedence ladder; and a distinct exit code for "scan completed but degraded" so CI can distinguish "your system is bad" from "the scanner did not work".

### A-22 / A-23 — Honesty defects

- §3.1 marks macOS "✅ Full" while 12 of 20 modules are Linux-only, and marks three BSDs supported. There is no test infrastructure for any of them, and no maintainer with the hardware.
- §2.1 claims "300+ checks"; summing §5.2 gives **253**.
- §9.2 states scan durations for software that does not exist.
- §3.3 states privilege coverage percentages for a catalog that has not been implemented.

Individually small. Collectively they establish that numbers in this document are decorative, which is a bad property for a document that is meant to become a security tool's specification. Every number in the replacement docs is either measured, derived, or explicitly marked as an estimate.

---

## 5. What the document does well

Worth preserving deliberately:

- **The check catalog** (§5.2) is genuinely good domain work. The IDs, groupings and coverage are a solid foundation; roughly 110 of the 253 are v1 material.
- **The check schema** (§6) is the right shape: id, severity, platforms, compliance mapping, structured results, remediation with steps *and* commands *and* references. It needs a formal schema and an `ERROR` state, not a redesign.
- **The CLI surface** (§9) is well-considered and idiomatic. Trim the modes, define precedence, keep the rest.
- **The non-goals** (§2.4) are the strongest section in the document — clear, correct, and appropriately ruthless. They are then contradicted by the v1.1+ roadmap row, which is exactly the failure the non-goals were meant to prevent.
- **The differentiation table** (§18) shows the right instinct — know what you are not. It just needs to be honest about what is real in v1.
- **Report sections** (§13.2) map well onto what operators and auditors actually read.

---

## 6. What the document is missing entirely

Every item below is a document in `docs/DOCUMENT-MAP.md`:

| Gap | Consequence if left unaddressed |
|---|---|
| Data model (Finding, Fact, Bundle) | Output format drifts; integrations break silently |
| Output JSON Schema + versioning | The real public API is undefined |
| Error and timeout model | Failures masquerade as PASS |
| Testing strategy | 253 untested checks |
| Threat model | Root-privileged tool with an unexamined attack surface |
| Compliance data licensing policy | Takedown risk |
| Performance budgets | No definition of "too slow"; no regression detection |
| Acceptance criteria per release | "Done" is a feeling |
| Deprecation and stability policy | Every release silently breaks someone's pipeline |
| False-positive handling / suppressions | No way for users to live with imperfect checks |
| Privacy stance on report contents | Sensitive inventory written to disk unmanaged |

---

## 7. Disposition of the 20 modules

| Module | Verdict |
|---|---|
| BOOT, KERNEL, AUTH, USERS, SSH, NETWORK, SERVICES, FILESYSTEM, LOGGING, CRON | **Keep for v1.** Deterministic, file/sysctl-based, testable from fixtures. |
| STORAGE, CRYPTO, SOFTWARE (inventory only) | **v1 partial.** Drop TLS-endpoint probing and CVE correlation from v1. |
| CONTAINERS, CLOUD | **v2.** Both need network or socket access and a much larger fixture surface. |
| INTEGRITY | **v2.** Depends on baseline/bundle infrastructure that v1 builds. |
| MEMORY | **v2.** ELF parsing (RELRO/PIE/canaries) is self-contained and pleasant, but not v1-critical. |
| MACOSEC | **v3.** Requires a Mac to develop and test on; do not claim macOS support before then. |
| MALWARE | **Cut, or reduce drastically.** Signature-based rootkit detection from userspace is unreliable (A-27) and invites a false sense of security. Keep only high-confidence, explainable checks (`/etc/ld.so.preload` contents, LD_PRELOAD in environment, immutable attributes on system files) and label them as indicators, never as "clean". |
| PENTEST | **v2, renamed.** The checks are valuable (privesc surface mapping) but the framing invites misuse and distro-packaging objections. Rename to `PRIVESC`, gate behind an explicit flag, and ship an authorised-use statement. |

---

## 8. Recommended actions, in order

1. **Rename.** Confirmed conflicts for "Argus": openargus (network flow monitor, security domain, since 1984), PlaxidityX née Argus Cyber Security (acquired by Continental for $430M — they have trademark counsel), Salesforce/Argus, arguslab.org, and a 2024 USENIX tool named ARGUS that also analyses CI/CD security. See `docs/PROJECT-BRIEF.md` for the replacement.
2. **Rescope to a v1 one person can ship** — `docs/ROADMAP.md`.
3. **Rebuild the architecture around collect → evaluate** — `docs/ARCHITECTURE.md`.
4. **Define the output contract before writing check #1** — data model section of `docs/ARCHITECTURE.md`.
5. **Write the licensing policy before writing compliance mapping #1.**
6. **Write the threat model before running as root.**
7. **Then** start on modules, in the order given by the roadmap.

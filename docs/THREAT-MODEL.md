# Plumbline threat model

**Status:** normative. Gates running as root at all.

**Scope:** threats to Plumbline, not threats the tool detects.

**Review trigger:** any new collector, any new `System` method, any change to
the evidence or rendering path.

**Last full review against the implementation:** 2026-08-21, at `v1.0.0`
(WP-38). Re-checked for `v2.0.0` on 2026-09-02, covering the remediation
generator and the dependency count. No new threat class.

That first review was a v1.0.0 release criterion. It found two places where this
document claimed a mitigation the code does not have. Both are corrected below
rather than dropped, so a reader can plan around the gap.

Plumbline runs as root and reads input an unprivileged local attacker can
influence: filenames in world-writable directories, contents of user home
directories, cron files, package metadata. The predecessor design listed nine
desirable security properties and no threats. This document records the threats.

---

## 1. Assets

| Asset | Why an attacker wants it |
|---|---|
| Root privileges of the running process | Local privilege escalation |
| Report and bundle contents | User list, open ports, package inventory, file paths. A complete reconnaissance package |
| The operator's terminal | Control-sequence injection to forge output or execute on paste |
| Trust in the verdict | A false `PASS` is worse than a crash. It ends the investigation |
| Release artifacts | Supply-chain compromise reaches every user |

---

## 2. Trust boundaries

```
  ┌── UNTRUSTED ───────────────────────────────────────────────┐
  │ filesystem contents · filenames · config files · cron      │
  │ package metadata · command output · bundles from elsewhere │
  └──────────────────────┬─────────────────────────────────────┘
                         │  internal/system  ← the boundary
  ┌──────────────────────▼─────────────────────────────────────┐
  │ TRUSTED: typed facts · pure checks · findings              │
  └──────────────────────┬─────────────────────────────────────┘
                         │  renderers  ← second boundary: output
  ┌──────────────────────▼─────────────────────────────────────┐
  │ operator's terminal · files on disk · CI logs              │
  └────────────────────────────────────────────────────────────┘
```

There are two boundaries. Everything hostile enters through `internal/system`
and leaves through a renderer. That is why the seam is enforced by
`make check-system-seam` rather than by convention.

---

## 3. Threats and mitigations

### T-01: Symlink swap against a privileged read (TOCTOU)

An unprivileged user replaces a path between the check and the open, pointing at
`/etc/shadow` or a file they cannot otherwise read. The scanner reads it as root
and prints the contents as evidence.

**Mitigation:** `live.ReadFile` opens with `O_NOFOLLOW`, then calls `fstat` on
the already-open descriptor and rejects anything that is not a regular file.
Verifying after opening rather than before is what closes the window. `ELOOP`
maps to `ErrNotRegular`.

**Residual:** intermediate path components are not resolved atomically.
`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` on Linux 5.6+ closes this
properly.

This document once said that was "scheduled for v1.0". v1.0.0 shipped without
it. So did v2.0.0. The residual is open, two deadlines have passed, and the work
is not being restated with a third date.

Meanwhile the control is a rule rather than a mechanism: no collector may read a
path under a world-writable directory. That is item one of the review checklist
in §5, and it is why every collector reads only from `/etc`, `/proc/sys` and
`/usr/lib`. The protection on the terminal component, `O_NOFOLLOW` plus `fstat`
on the open descriptor, stops the direct attack. What is missing is atomicity
across intermediate components.

Accepted and tracked. It is the highest-priority residual risk in this document.

**Test:** hostile corpus, `symlink-to-shadow` fixture.

---

### T-02: FIFO or device node where a file is expected

An attacker places a named pipe at a path the scanner reads. `open()` blocks
indefinitely, the root process hangs, and repeated scans exhaust the process
table. The predecessor design never considered file type, so this was a local
denial of service against it.

**Mitigation:** `O_NONBLOCK` on open so the call returns, plus the regular-file
check on the descriptor. The filesystem walker never descends into or opens
anything that is not a regular file or a directory.

**Test:** hostile corpus, `fifo-as-config`. Acceptance requires the read to
return within milliseconds, which shows the guard fires.

---

### T-03: Terminal control-sequence injection via filenames

Filenames may contain arbitrary bytes including ESC. A filename such as
`\x1b[2J\x1b[H  All checks passed` lands in evidence, in the terminal report and
in CI logs. It can clear the screen, forge output, retitle the window, or stage
a command for the operator to run via bracketed-paste tricks.

**Mitigation:** every string derived from untrusted input is sanitised before it
reaches any renderer. C0 and C1 control characters other than tab become a
visible escape, and length is capped. Sanitisation happens once, in the evidence
constructor, rather than per renderer, so a new output format cannot omit it.

**Test:** hostile corpus, `ansi-filename`, asserted against terminal, JSON and
SARIF output.

---

### T-04: Resource exhaustion

A 4 GB `/etc/passwd`. A directory with ten million entries. A cyclic bind mount.
A symlink chain 40 deep. An `Include` that includes itself.

**Mitigation:** every read is capped at `DefaultMaxRead`, 8 MiB, and truncation
is recorded as a fact error rather than silently accepted. `Include` recursion
is bounded by `maxIncludeDepth` and cycles are caught by a seen-set. The walker
carries depth, inode-count and wall-clock budgets, and marks results `Truncated`
so no finding claims completeness it does not have.

**Test:** hostile corpus, `huge-file`, `cyclic-include`, `deep-symlink-chain`.

---

### T-05: Command injection

**Mitigation:** structural. `Exec` takes `argv []string`. There is no shell
anywhere in the collection path, no `sh -c`, and no command string construction.

Remediation is the place this could have gone wrong and did not. `scan --fix`
renders a shell script to stdout and stops. Nothing in `internal/remediate`
holds a `System`, so the generator cannot execute what it writes even by
mistake. The operator runs the script, or does not.

---

### T-06: Locale-dependent parsing

Command output parsed under an unexpected locale yields wrong values, and the
failure is silent. The check returns a wrong verdict with nothing to indicate
it.

**Mitigation:** `live.execEnv` pins `LC_ALL=C`, `LANG=C`, `TZ=UTC` and a minimal
`PATH` on every exec. The environment is replaced, not extended, so nothing
inherited from the operator's shell reaches a subprocess.

---

### T-07: Attacker-controlled configuration

A root-run scanner that honours `./plumbline.yaml` from the current working
directory can be steered by anyone able to write a file into a directory root
happens to `cd` into. They can disable the checks that would catch them, or
redirect the output.

**Mitigation:** configuration from the current working directory is ignored when
euid is 0, unless passed explicitly with `--config`. System and user config
paths are unaffected. Enforced in WP-12 and tested.

---

### T-08: Sensitive output written insecurely

Bundles and reports contain the user list, open ports, package inventory and
file paths. Written world-readable into a shared directory, they hand an
attacker a complete reconnaissance report.

**Mitigation:** all output files are created `0600` and directories `0700`, with
`O_EXCL` so nothing writes through a pre-planted symlink. `--redact` removes
hostname and non-loopback addresses at collection time, so a redacted bundle is
safe to send in a bug report. Nothing is written outside the documented paths,
and no log goes to `/var/log` unless `--log-file` is passed explicitly.

A script written by `--write-script` is created `0700`, owner-only and
executable. It is a root remediation plan for a specific host, so it gets the
same treatment as a bundle.

**Test:** WP-12 asserts the mode on every written artifact.

---

### T-09: Malicious bundle fed to `eval`

`plumbline eval` accepts a file from anywhere. A crafted bundle could attempt
decompression bombs, path traversal on extraction, or type confusion in fact
decoding.

**Mitigation:** bundles are streamed with a decompressed-size cap. Tar members
are read into memory by name and never extracted to disk, so path traversal has
no target. Fact decoding is by registered ID into a typed struct, and an
unregistered ID is preserved as opaque bytes rather than interpreted. Integrity
mismatch is a typed error, not a warning.

**Note:** integrity is not authenticity. A valid `integrity.json` proves the
bundle is internally consistent, not that it came from anyone in particular.
Only a detached signature does that. The renderer states the difference.
Conflating them was audit finding A-14.

---

### T-10: Supply-chain compromise of releases

**Mitigation, as shipped at v2.0.0:**

- Keyless signing with a workflow identity. `cosign sign-blob` over the checksum
  file, certificate published beside it. The identity is
  `https://github.com/antaryx/plumbline/*` at
  `token.actions.githubusercontent.com`. There is no private key to leak.
- SBOM per artifact, SPDX 2.3, generated by syft from what was built.
- Three runtime dependencies, plus one the tests use and the binary does not
  link. The dependency tree is itself a control, and the SBOM is what makes the
  count checkable. A terminal-styling library was added in a release candidate
  and removed before GA on this reasoning. See `CHANGELOG.md` v1.0.0-rc1.
- Deterministic builds. `CGO_ENABLED=0`, `-trimpath`, and a build timestamp
  taken from the commit rather than the clock, so two builds of one tag produce
  identical bytes.

This document once also claimed reproducible builds verified by double-build
comparison, SLSA provenance, and an installer that verifies before executing.
None of the three exists. The 2026-08-21 review found all three claims, and the
2026-09-02 re-check confirmed v2.0.0 shipped without any of them. The build is
deterministic by construction, but nothing verifies it by building twice and
comparing. There is no SLSA attestation in the release workflow. There is no
installer script, so `README.md` and `docs/INSTALLATION.md` give the
verification commands for a human to run, which is a weaker control than an
installer that refuses on a bad signature.

`docs/SUPPLY-CHAIN.md` carries the same list, checked against the workflow files
rather than remembered.

---

### T-11: False PASS

The most damaging failure this codebase can produce, and the only one with no
external symptom. The operator stops looking.

**Mitigation:** architectural rather than defensive.

- Five result states, with `UNKNOWN` as a first-class outcome
- The runner's required-fact gate, so a check never sees a missing fact
- Panics become `UNKNOWN(internal_error)`, never a skipped check that reads as a
  pass
- Fact errors propagate to `UNKNOWN` with a reason code
- Coverage is reported beside every posture score and no renderer may omit it
- Every check needs a `FAIL` fixture, so "always passes" is caught by CI
- Golden-bundle diffs surface any verdict change across the whole corpus

---

### T-12: A partial artifact read as a complete one

A scan interrupted part-way writes a bundle or a findings document containing
what it managed to collect. Nothing in the artifact says it is partial: the
manifest lists the facts that made it and is silent about the ones that did not.
Months later it re-evaluates to a posture score drawn from half a host, and the
operator reads it as an audit.

This is T-11 by a different route, and it is the one the operator creates by
pressing Ctrl-C.

**Mitigation:** `SIGINT` and `SIGTERM` cancel the collection context, and an
interrupted run produces no artifact. No findings document, no `--save-bundle`
output, no bundle from `collect`. Stderr names the file that was not written.
Exit code 130.

The cancellation carries its reason via `context.WithCancelCause`, which keeps
an interrupt distinct from an expired `--timeout`. The two arrive identically as
a cancelled context and mean different things. A `--timeout` keeps what it
collected, because a budget accepts whatever fits inside it. An interrupt is an
instruction to stop.

**Test:** `internal/cli/interrupt_test.go`, and `internal/system/signal_test.go`
for the signal-to-cause plumbing.

---

### T-13: Exfiltration or phone-home by the tool itself

A security tool is an attractive place to hide a beacon. It runs as root, reads
sensitive configuration, and nobody is surprised when it produces network
traffic.

**Mitigation:** Plumbline makes no network calls, and this is enforced rather
than asserted. No collector opens a socket. There is no dbus connection, no
`systemctl`, no `nft list ruleset`, no update check, no telemetry. The offline CI
job runs a full scan inside `unshare -n` and asserts it produces a document
byte-identical to an online run, so a beacon added to any code path fails that
job.

The architecture depends on this rather than merely permitting it. Service
enablement is recovered from `.wants/` symlinks because nothing may query a
running daemon, and that is also what makes `--root /mnt` and offline
re-evaluation of an old bundle possible.

**Residual:** a check cannot make a network call, because checks may not import
`net` and `make check-check-purity` enforces that. The equivalent guarantee for
collectors comes from review and from the offline job, not from a compile-time
gate.

---

### T-14: A generated remediation script that damages the host

`scan --fix` writes root-level shell. An operator who runs it without reading it
can lose access to the host, or break a daemon the host needs. This is a real
outcome, not a hypothetical: applying blanket `ProtectSystem=strict` drop-ins to
arbitrary system services took out `dbus` and `systemd-journald` during
development, which is why `SERVICES-0011` no longer generates one.

This threat is not fully mitigated and cannot be, because the operator is the
one who runs the script.

**Mitigation, such as it is:**

- Plumbline never executes the script. `internal/remediate` holds no `System`,
  so the boundary is structural rather than a policy someone could relax.
- Every generated action is preceded by a comment naming the finding it repairs,
  so a reviewer can map a command back to a reason.
- Actions rewrite in place and are idempotent, so a second run is not a second
  set of changes.
- A check whose fix is too dangerous to generate does not get one. It falls back
  to advisory text from the catalog and counts as unfixable in the `--fix`
  summary. `SERVICES-0011` is the worked example.
- The generated script is `#!/bin/sh` under `set -eu`, and every generated
  script is parsed by `sh -n` in CI.
- `README.md` and `LEGAL-DISCLAIMER.md` state the liability plainly, above the
  fold rather than in an appendix.

**Residual:** the firewall action sets a default-deny inbound policy and assumes
SSH is on port 22. On a host where it is not, running the script unread ends the
session. The action is generated with its commands visible and is not guarded
beyond that.

**Test:** `internal/remediate/script_internal_test.go` parses every registered
fix with `sh -n`. `nonsysctl_test.go` asserts `SERVICES-0011` generates nothing.

---

## 4. Explicit non-mitigations

Stated so nobody assumes protection that does not exist.

| Not defended | Why |
|---|---|
| A compromised kernel or rootkit lying to userspace | Unwinnable from userspace. Any malware-adjacent check is labelled an indicator, never an assurance. |
| An attacker who is already root on the scanned host | They control the answers. Plumbline reports state. It does not attest to it. |
| Physical or hypervisor-level attacks | Out of scope. |
| An operator who runs a generated script without reading it | See T-14. The tool can refuse to execute; it cannot refuse on the operator's behalf. |
| Third-party extensions | An extension is code the operator chose to run. A signature identifies the publisher. It does not make the code safe. This will be stated in `PACK-AUTHORING.md`. |

---

## 5. Review checklist for new collectors

Every collector added must answer these in its pull request:

- [ ] Does it read a path an unprivileged user can influence? If yes, T-01 applies; justify it.
- [ ] Can the path be a FIFO, socket, or device node?
- [ ] Is every read capped, and is truncation recorded rather than ignored?
- [ ] Does any untrusted string reach evidence without sanitisation?
- [ ] Does it exec? If so: argv only, pinned environment, timeout set.
- [ ] Can it loop, recurse, or follow a cycle?
- [ ] Does failure produce a typed `fact.Error`, or could it silently yield an empty fact a check reads as PASS?

## 6. Review checklist for new remediation actions

- [ ] Can this command lock the operator out of the host? If yes, say so in the generated comment.
- [ ] Is it idempotent? Run it twice on the same host and diff the result.
- [ ] Does it depend on a binary that may not be installed? Guard it with `command -v`.
- [ ] Does it restart or reload a unit? Restarts belong to the operator, not the script.
- [ ] Would a wrong guess here break a daemon? If the information needed is an enumeration the scan does not have, generate nothing and leave the advisory text.

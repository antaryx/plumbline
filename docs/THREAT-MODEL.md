# THREAT MODEL — Plumbline

**Status:** normative. Gates running as root at all.
**Scope:** threats *to Plumbline*, not threats the tool detects.
**Review trigger:** any new collector, any new `System` method, any change to
the evidence or rendering path.

Plumbline runs as root and reads input that an unprivileged local attacker can
influence: filenames in world-writable directories, contents of user home
directories, cron files, package metadata. The audited design listed nine
desirable security properties and zero threats. This document is the correction.

---

## 1. Assets

| Asset | Why an attacker wants it |
|---|---|
| Root privileges of the running process | Local privilege escalation |
| Report and bundle contents | User list, open ports, package inventory, file paths — a complete reconnaissance package |
| The operator's terminal | Control-sequence injection to forge output or execute on paste |
| Trust in the verdict | A false `PASS` is more damaging than a crash: it ends the investigation |
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

Two boundaries, both narrow by construction. Everything hostile enters through
`internal/system` and leaves through a renderer. That is why the seam is
enforced by `make check-system-seam` rather than by convention.

---

## 3. Threats and mitigations

### T-01 — Symlink swap against a privileged read (TOCTOU)

An unprivileged user replaces a path between the check and the open, pointing
at `/etc/shadow` or a file they cannot otherwise read. The scanner reads it as
root and prints the contents as evidence.

**Mitigation:** `live.ReadFile` opens with `O_NOFOLLOW`, then calls `fstat` on
the **already-open descriptor** and rejects anything that is not a regular
file. Verifying after opening, not before, is what closes the window.
`ELOOP` maps to `ErrNotRegular`.

**Residual:** intermediate path components are not yet resolved atomically.
`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` on Linux 5.6+ closes this
properly and is scheduled for v1.0. Until then, no collector may read a path
under a world-writable directory. **Accepted, tracked, and it is the highest-
priority residual risk in this document.**

**Test:** hostile corpus, `symlink-to-shadow` fixture.

---

### T-02 — FIFO or device node where a file is expected

An attacker places a named pipe at a path the scanner reads. `open()` blocks
forever. A root process is now hung, and repeated scans exhaust the process
table. This is a trivially exploitable local denial of service against the
audited design, which never considered file type.

**Mitigation:** `O_NONBLOCK` on open so the call returns, plus the regular-file
check on the descriptor. The filesystem walker (v0.2) never descends into or
opens anything that is not a regular file or directory.

**Test:** hostile corpus, `fifo-as-config`. Acceptance requires it to return
within milliseconds, proving the guard fires rather than being decorative.

---

### T-03 — Terminal control-sequence injection via filenames

Filenames may contain arbitrary bytes including ESC. A filename such as
`\x1b[2J\x1b[H  All checks passed` lands in evidence, in the terminal report,
and in CI logs. It can clear the screen, forge output, retitle the window, or —
with bracketed-paste tricks — stage a command for the operator to run.

**Mitigation:** every string derived from untrusted input is sanitised before
it reaches any renderer: C0/C1 control characters other than tab are replaced
with a visible escape, and length is capped. Sanitisation happens **once, in
the evidence constructor**, not per renderer, so a new output format cannot
forget it.

**Test:** hostile corpus, `ansi-filename`; asserted against terminal, JSON and
SARIF output.

---

### T-04 — Resource exhaustion

A 4 GB `/etc/passwd`; a directory with ten million entries; a cyclic bind
mount; a symlink chain 40 deep; an `Include` that includes itself.

**Mitigation:** every read is capped (`DefaultMaxRead`, 8 MiB) and truncation
is recorded as a fact error rather than silently accepted. `Include` recursion
is bounded (`maxIncludeDepth`) and cycles are detected by a seen-set. The
walker (v0.2) carries depth, inode-count and wall-clock budgets, and marks
results `Truncated` so no finding claims completeness it does not have.

**Test:** hostile corpus, `huge-file`, `cyclic-include`, `deep-symlink-chain`.

---

### T-05 — Command injection

**Mitigation:** structural. `Exec` takes `argv []string`. There is no shell
anywhere in the collection path, no `sh -c`, and no command string
construction. Remediation `Commands` are *emitted as text for human review* and
never executed — there is no `--fix` flag, by design and permanently.

---

### T-06 — Locale-dependent parsing

Command output parsed under an unexpected locale yields wrong values, and the
failure is silent: the check returns a confident, wrong verdict.

**Mitigation:** `live.execEnv` pins `LC_ALL=C`, `LANG=C`, `TZ=UTC` and a
minimal `PATH` on every exec. The environment is replaced, not extended, so
nothing inherited from the operator's shell reaches a subprocess.

---

### T-07 — Attacker-controlled configuration

A root-run scanner that honours `./plumbline.yaml` from the current working
directory can be steered by anyone who can write a file into a directory root
happens to `cd` into: disable the checks that would catch them, redirect output.

**Mitigation:** configuration from the current working directory is **ignored
when euid is 0** unless passed explicitly with `--config`. System and user
config paths are unaffected. Enforced in WP-12 and tested.

---

### T-08 — Sensitive output written insecurely

Bundles and reports contain the user list, open ports, package inventory and
file paths. Written world-readable into a shared directory, they hand an
attacker a finished reconnaissance report.

**Mitigation:** all output files are created `0600` and directories `0700`,
with `O_EXCL` to avoid writing through a pre-planted symlink. `--redact`
removes hostname and non-loopback addresses **at collection time**, so a
redacted bundle is safe to send in a bug report. Nothing is written outside the
documented paths, and no log is written to `/var/log` unless `--log-file` is
passed explicitly.

**Test:** WP-12 asserts the mode on every written artifact.

---

### T-09 — Malicious bundle fed to `eval`

`plumbline eval` accepts a file from anywhere. A crafted bundle could attempt
decompression bombs, path traversal on extraction, or type confusion in fact
decoding.

**Mitigation:** bundles are streamed with a decompressed-size cap; tar members
are read into memory by name, never extracted to disk, so path traversal has no
target; fact decoding is by registered ID into a typed struct, and an
unregistered ID is preserved as opaque bytes rather than being interpreted.
Integrity mismatch is a typed error, not a warning.

**Note:** integrity ≠ authenticity. A valid `integrity.json` proves the bundle
is internally consistent, not that it came from anyone in particular. Only a
detached signature does that. The renderer states the difference; conflating
them was audit finding A-14.

---

### T-10 — Supply-chain compromise of releases

**Mitigation:** reproducible builds verified by double-build comparison,
keyless signing with a documented workflow identity, SBOM per artifact, SLSA
provenance, and an installer that verifies before executing. Full detail in
`DEPLOYMENT.md` §3 and `SUPPLY-CHAIN.md`.

---

### T-11 — False PASS

The most damaging failure this codebase can produce, and the only one with no
external symptom. The operator stops looking.

**Mitigation:** architectural rather than defensive.
- Five result states with `UNKNOWN` as a first-class outcome
- The runner's required-fact gate: a check never sees a missing fact
- Panics become `UNKNOWN(internal_error)`, never a skipped check that reads as fine
- Fact errors propagate to `UNKNOWN` with a reason code
- Coverage is reported beside every posture score and no renderer may omit it
- Every check needs a `FAIL` fixture, so "always passes" is caught by CI
- Golden-bundle diffs surface any verdict change across the whole corpus

---

## 4. Explicit non-mitigations

Stated so nobody assumes protection that does not exist:

| Not defended | Why |
|---|---|
| A compromised kernel or rootkit lying to userspace | Unwinnable from userspace. Any malware-adjacent check is labelled an indicator, never an assurance. |
| An attacker who is already root on the scanned host | They control the answers. Plumbline reports state; it does not attest to it. |
| Physical or hypervisor-level attacks | Out of scope. |
| Third-party extensions (v3) | An extension is code you chose to run. A signature identifies the publisher; it does not make the code safe. This will be stated plainly in `PACK-AUTHORING.md`. |

---

## 5. Review checklist for new collectors

Every collector added must answer these in its pull request:

- [ ] Does it read a path an unprivileged user can influence? If yes, T-01 applies — justify it.
- [ ] Can the path be a FIFO, socket, or device node?
- [ ] Is every read capped, and is truncation recorded rather than ignored?
- [ ] Does any untrusted string reach evidence without sanitisation?
- [ ] Does it exec? If so: argv only, pinned environment, timeout set.
- [ ] Can it loop, recurse, or follow a cycle?
- [ ] Does failure produce a typed `fact.Error`, or could it silently yield an empty fact that a check reads as PASS?

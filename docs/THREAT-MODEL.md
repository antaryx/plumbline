# Plumbline threat model

**Status:** normative. Gates running as root at all.
**Scope:** threats *to Plumbline*, not threats the tool detects.
**Review trigger:** any new collector, any new `System` method, any change to
the evidence or rendering path.
**Last reviewed against the implementation:** 2026-08-21, at `v1.0.0` (WP-38).

That review is a v1.0.0 release criterion. It found two places where this
document claimed a mitigation the code does not have. Both are corrected below
rather than dropped, so a reader can plan around the gap.

Plumbline runs as root and reads input that an unprivileged local attacker can
influence: filenames in world-writable directories, contents of user home
directories, cron files, package metadata. The predecessor design listed nine
desirable security properties and no threats. This document records the threats.

---

## 1. Assets

| Asset | Why an attacker wants it |
|---|---|
| Root privileges of the running process | Local privilege escalation |
| Report and bundle contents | User list, open ports, package inventory, file paths: a complete reconnaissance package |
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

There are two boundaries. Everything hostile enters through `internal/system`
and leaves through a renderer, which is why the seam is enforced by
`make check-system-seam` rather than by convention.

---

## 3. Threats and mitigations

### T-01: Symlink swap against a privileged read (TOCTOU)

An unprivileged user replaces a path between the check and the open, pointing
at `/etc/shadow` or a file they cannot otherwise read. The scanner reads it as
root and prints the contents as evidence.

**Mitigation:** `live.ReadFile` opens with `O_NOFOLLOW`, then calls `fstat` on
the already-open descriptor and rejects anything that is not a regular file.
Verifying after opening rather than before is what closes the window. `ELOOP`
maps to `ErrNotRegular`.

**Residual:** intermediate path components are not resolved atomically.
`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` on Linux 5.6+ closes this
properly.

This document previously said that was "scheduled for v1.0". v1.0.0 shipped
without it. The 2026-08-21 review found the claim. The residual is open, the
deadline passed, and the work is deferred to v1.1 rather than restated with a
new date.

In the meantime the control is a rule rather than a mechanism: no collector may
read a path under a world-writable directory. That is item one of the review
checklist in §5, and it is why every collector reads only from `/etc`,
`/proc/sys` and `/usr/lib`. The protection on the terminal component
(`O_NOFOLLOW` plus `fstat` on the open descriptor) stops the direct attack. What
is missing is atomicity across intermediate components.

Accepted and tracked. It is the highest-priority residual risk in this
document.

**Test:** hostile corpus, `symlink-to-shadow` fixture.

---

### T-02: FIFO or device node where a file is expected

An attacker places a named pipe at a path the scanner reads. `open()` blocks
indefinitely, the root process hangs, and repeated scans exhaust the process
table. The predecessor design never considered file type, so this was a local
denial of service against it.

**Mitigation:** `O_NONBLOCK` on open so the call returns, plus the regular-file
check on the descriptor. The filesystem walker (v0.2) never descends into or
opens anything that is not a regular file or directory.

**Test:** hostile corpus, `fifo-as-config`. Acceptance requires the read to
return within milliseconds, which shows the guard fires.

---

### T-03: Terminal control-sequence injection via filenames

Filenames may contain arbitrary bytes including ESC. A filename such as
`\x1b[2J\x1b[H  All checks passed` lands in evidence, in the terminal report,
and in CI logs. It can clear the screen, forge output, retitle the window, or,
with bracketed-paste tricks, stage a command for the operator to run.

**Mitigation:** every string derived from untrusted input is sanitised before
it reaches any renderer: C0/C1 control characters other than tab are replaced
with a visible escape, and length is capped. Sanitisation happens once, in the
evidence constructor, rather than per renderer, so a new output format cannot
omit it.

**Test:** hostile corpus, `ansi-filename`; asserted against terminal, JSON and
SARIF output.

---

### T-04: Resource exhaustion

A 4 GB `/etc/passwd`; a directory with ten million entries; a cyclic bind
mount; a symlink chain 40 deep; an `Include` that includes itself.

**Mitigation:** every read is capped (`DefaultMaxRead`, 8 MiB) and truncation
is recorded as a fact error rather than silently accepted. `Include` recursion
is bounded (`maxIncludeDepth`) and cycles are detected by a seen-set. The
walker (v0.2) carries depth, inode-count and wall-clock budgets, and marks
results `Truncated` so no finding claims completeness it does not have.

**Test:** hostile corpus, `huge-file`, `cyclic-include`, `deep-symlink-chain`.

---

### T-05: Command injection

**Mitigation:** structural. `Exec` takes `argv []string`. There is no shell
anywhere in the collection path, no `sh -c`, and no command string
construction. Remediation `Commands` are emitted as text for human review and
never executed. There is no `--fix` flag.

---

### T-06: Locale-dependent parsing

Command output parsed under an unexpected locale yields wrong values, and the
failure is silent: the check returns a wrong verdict with nothing to indicate
it.

**Mitigation:** `live.execEnv` pins `LC_ALL=C`, `LANG=C`, `TZ=UTC` and a
minimal `PATH` on every exec. The environment is replaced, not extended, so
nothing inherited from the operator's shell reaches a subprocess.

---

### T-07: Attacker-controlled configuration

A root-run scanner that honours `./plumbline.yaml` from the current working
directory can be steered by anyone able to write a file into a directory root
happens to `cd` into. They can disable the checks that would catch them, or
redirect the output.

**Mitigation:** configuration from the current working directory is ignored
when euid is 0, unless passed explicitly with `--config`. System and user
config paths are unaffected. Enforced in WP-12 and tested.

---

### T-08: Sensitive output written insecurely

Bundles and reports contain the user list, open ports, package inventory and
file paths. Written world-readable into a shared directory, they give an
attacker a complete reconnaissance report.

**Mitigation:** all output files are created `0600` and directories `0700`,
with `O_EXCL` to avoid writing through a pre-planted symlink. `--redact`
removes hostname and non-loopback addresses at collection time, so a redacted
bundle is safe to send in a bug report. Nothing is written outside the
documented paths, and no log is written to `/var/log` unless `--log-file` is
passed explicitly.

**Test:** WP-12 asserts the mode on every written artifact.

---

### T-09: Malicious bundle fed to `eval`

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

### T-10: Supply-chain compromise of releases

**Mitigation, as shipped at v1.0.0:**

- Keyless signing with a workflow identity. `cosign sign-blob` over the
  checksum file, certificate published beside it; the identity is
  `https://github.com/antaryx/plumbline/*` at
  `token.actions.githubusercontent.com`. There is no private key to leak.
- SBOM per artifact, SPDX 2.3, generated by syft from what was built.
- Four dependencies. The dependency tree is itself a control, and the SBOM is
  what makes the count checkable. A terminal-styling library was added in a
  release candidate and removed before GA on this reasoning; see `CHANGELOG.md`
  v1.0.0-rc1.
- Deterministic builds. `CGO_ENABLED=0`, `-trimpath`, and a build timestamp
  taken from the commit rather than the clock, so two builds of one tag produce
  identical bytes.

This document previously also claimed "reproducible builds verified by
double-build comparison", "SLSA provenance", and "an installer that verifies
before executing". None of the three exists, and the 2026-08-21 review found
all three claims. The build is deterministic by construction, but nothing
verifies it by building twice and comparing. There is no SLSA attestation in
the release workflow. There is no installer script, so `README.md` gives the
verification commands for a human to run, which is a weaker control than an
installer that refuses on a bad signature.

All three are v1.1 work and are listed in `docs/ROADMAP.md`. Verification steps
a user can actually run today are in `README.md` and `docs/SUPPLY-CHAIN.md`.

---

### T-11: False PASS

The most damaging failure this codebase can produce, and the only one with no
external symptom: the operator stops looking.

**Mitigation:** architectural rather than defensive.
- Five result states with `UNKNOWN` as a first-class outcome
- The runner's required-fact gate: a check never sees a missing fact
- Panics become `UNKNOWN(internal_error)`, never a skipped check that reads as a pass
- Fact errors propagate to `UNKNOWN` with a reason code
- Coverage is reported beside every posture score and no renderer may omit it
- Every check needs a `FAIL` fixture, so "always passes" is caught by CI
- Golden-bundle diffs surface any verdict change across the whole corpus

---

### T-12: A partial artifact read as a complete one

A scan interrupted part-way writes a bundle or a findings document containing
what it managed to collect. Nothing in the artifact says it is partial: the
manifest lists the facts that made it and is silent about the ones that did
not. Months later it re-evaluates to a posture score drawn from half a host,
and the operator reads it as an audit.

This is T-11 (false PASS) reached by a different route, and it is the one the
operator creates by pressing Ctrl-C.

**Mitigation:** `SIGINT` and `SIGTERM` cancel the collection context, and an
interrupted run produces no artifact: no findings document, no `--save-bundle`
output, no bundle from `collect`. Stderr names the file that was not written.
Exit code 130.

The cancellation carries its reason (`context.WithCancelCause`), which keeps an
interrupt distinct from an expired `--timeout`. The two arrive identically as a
cancelled context and mean different things: a `--timeout` keeps what it
collected, because a budget accepts whatever fits inside it, whereas an
interrupt is an instruction to stop.

**Test:** `internal/cli/interrupt_test.go`, and `internal/system/signal_test.go`
for the signal-to-cause plumbing.

---

### T-13: Exfiltration or phone-home by the tool itself

A security tool is an attractive place to hide a beacon: it runs as root, reads
sensitive configuration, and nobody is surprised when it produces network
traffic.

**Mitigation:** Plumbline makes no network calls, and this is enforced rather
than asserted. No collector opens a socket, and there is no dbus connection, no
`systemctl`, no `nft list ruleset`, no update check and no telemetry. The
offline CI job runs a full scan inside `unshare -n` and asserts it produces a
document byte-identical to an online run, so a beacon added to any code path
fails that job.

The architecture depends on this rather than merely permitting it. Service
enablement is recovered from `.wants/` symlinks because nothing may query a
running daemon, and that is also what makes `--root /mnt` and offline
re-evaluation of an old bundle possible.

**Residual:** a check cannot make a network call, because checks may not import
`net` and `make check-check-purity` enforces that. The equivalent guarantee for
collectors comes from review and from the offline job, not from a compile-time
gate.

---

## 4. Explicit non-mitigations

Stated so nobody assumes protection that does not exist:

| Not defended | Why |
|---|---|
| A compromised kernel or rootkit lying to userspace | Unwinnable from userspace. Any malware-adjacent check is labelled an indicator, never an assurance. |
| An attacker who is already root on the scanned host | They control the answers. Plumbline reports state; it does not attest to it. |
| Physical or hypervisor-level attacks | Out of scope. |
| Third-party extensions (v3) | An extension is code the operator chose to run. A signature identifies the publisher; it does not make the code safe. This will be stated in `PACK-AUTHORING.md`. |

---

## 5. Review checklist for new collectors

Every collector added must answer these in its pull request:

- [ ] Does it read a path an unprivileged user can influence? If yes, T-01 applies; justify it.
- [ ] Can the path be a FIFO, socket, or device node?
- [ ] Is every read capped, and is truncation recorded rather than ignored?
- [ ] Does any untrusted string reach evidence without sanitisation?
- [ ] Does it exec? If so: argv only, pinned environment, timeout set.
- [ ] Can it loop, recurse, or follow a cycle?
- [ ] Does failure produce a typed `fact.Error`, or could it silently yield an empty fact that a check reads as PASS?

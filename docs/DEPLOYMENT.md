# DEPLOYMENT — Plumbline

Covers how a release is built, signed, published, installed, verified, upgraded and rolled back. "Deployment" for a CLI security tool means **artifact supply chain**, not servers — the project runs no infrastructure by design.

---

## 1. Principles

1. **A security tool must be verifiable.** Every artifact is signed, has an SBOM, and has documented verification steps that a user can actually follow in under a minute.
2. **No hosted infrastructure.** No install domain, no plugin registry, no telemetry endpoint. GitHub Releases plus signed files is the entire distribution system. Everything the source design proposed (`get.argus-security.io`, `plugins.argus-security.io`) is cost, uptime obligation and attack surface for one person.
3. **Reproducible builds.** Two people building the same tag get the same binary.
4. **The installer does not require trust.** `curl … | bash` for a *security auditing tool* is self-parodying. The install script verifies signatures before executing anything, and the docs lead with manual verification.
5. **Distro packaging is community, best-effort, and never a release gate.** Getting into Debian or Fedora depends on other people's decisions; it cannot be a roadmap deliverable.

---

## 2. Build

### 2.1 Matrix

| Release | OS/arch in CI and published |
|---|---|
| v1.0.0 | `linux/amd64`, `linux/arm64` |
| v2.0.0 | + `linux/armv7` if CI hardware exists |
| v3.0.0 | + `darwin/amd64`, `darwin/arm64` |

Nothing is published for a platform that is not tested in CI. Cross-compiling to riscv64 is one line in GoReleaser and zero evidence that it works; the source design listed five architectures on that basis.

### 2.2 Flags

```bash
CGO_ENABLED=0 GOFLAGS="-trimpath" \
go build \
  -ldflags "-s -w \
    -X main.version=${VERSION} \
    -X main.commit=${COMMIT} \
    -X main.date=${SOURCE_DATE_EPOCH} \
    -X main.catalog=${CATALOG_VERSION}" \
  -o dist/plumbline ./cmd/plumbline
```

- `CGO_ENABLED=0` — static, no glibc coupling, runs on Alpine and on distroless. This is what makes the single-binary claim true.
- `-trimpath` — removes local paths; required for reproducibility.
- `SOURCE_DATE_EPOCH` from the commit timestamp — no wall-clock in the binary.
- Version metadata injected, never hardcoded in source.

### 2.3 Reproducibility check

CI builds every release twice, in separate runners, and asserts identical `sha256`. A mismatch fails the release. The verification procedure is documented in `SUPPLY-CHAIN.md` so third parties can rebuild a tag and compare.

---

## 3. Signing and provenance

| Artifact | Mechanism |
|---|---|
| Binaries and archives | `cosign sign-blob` (keyless, GitHub OIDC) → `.sig` + `.pem` per artifact |
| Checksums | `checksums.txt` (SHA-256), itself signed |
| SBOM | `syft` → CycloneDX JSON per artifact, attached and signed |
| Provenance | SLSA build provenance attestation via the GitHub attestations API |
| Container image | `cosign sign` on the image digest; signature in the registry |
| Git tags | GPG or SSH signed |
| Vuln DB (v2+) | Signed the same way; the binary **verifies before loading** and refuses an unverified DB |

Keyless signing is the right default for a solo maintainer: there is no long-lived private key to lose, rotate or have stolen, and the identity is the GitHub workflow, which is publicly auditable. Document the exact expected identity and issuer so users can pin them:

```bash
cosign verify-blob \
  --certificate plumbline_1.0.0_linux_amd64.tar.gz.pem \
  --signature   plumbline_1.0.0_linux_amd64.tar.gz.sig \
  --certificate-identity-regexp '^https://github\.com/antaryx/plumbline/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  plumbline_1.0.0_linux_amd64.tar.gz
```

That command belongs in `INSTALLATION.md` above the fold, not in an appendix.

---

## 4. Release pipeline

```
tag v1.0.0 (signed)
   │
   ├─ verify: tag is signed · on a release branch · CHANGELOG has this version
   ├─ full test suite (unit · fixtures · determinism · offline · hostile · distro matrix)
   ├─ performance budget assertion
   ├─ build ×2 → compare hashes (reproducibility gate)
   ├─ syft → SBOM per artifact
   ├─ cosign → signatures
   ├─ attestation → SLSA provenance
   ├─ GitHub Release: binaries · checksums · sigs · SBOMs · notes
   ├─ container image → ghcr.io, signed, digest pinned in the release notes
   └─ post-publish smoke: download fresh, verify, run `plumbline doctor` on 4 distros
```

The post-publish smoke test is the one people skip and the one that catches the embarrassing failures — an artifact that was uploaded truncated, a binary that will not start on musl, a signature over the wrong file. Automate it, then still look at the output.

---

## 5. Distribution channels

### 5.1 Tier 1 — controlled by the project

| Channel | Available from |
|---|---|
| GitHub Releases (binaries + archives) | v1.0.0 |
| `go install github.com/antaryx/plumbline/cmd/plumbline@latest` | v1.0.0 |
| Verifying install script | v1.0.0 |
| Container image `ghcr.io/antaryx/plumbline` | v1.0.0 |
| Homebrew tap (`antaryx/tap`) | v1.0.0 — a tap is self-published, unlike homebrew-core |

### 5.2 Tier 2 — community, best-effort, unversioned promises

AUR, Debian/Ubuntu packages, Fedora COPR, Alpine, nixpkgs. Each requires either a third party's approval or ongoing maintenance the project has not budgeted for. `INSTALLATION.md` lists these as *community-maintained, may lag* and links to whoever maintains them. They never appear on a roadmap.

The source design promised `apt install argus` via an official PPA, `dnf install argus` via COPR, `apk add argus` in Alpine testing, and `pkg install argus` on FreeBSD — four ongoing packaging obligations, three of which depend on other people's review queues, all committed to before a single line of code existed.

### 5.3 The install script

```bash
curl -fsSLO https://github.com/antaryx/plumbline/releases/latest/download/install.sh
curl -fsSLO https://github.com/antaryx/plumbline/releases/latest/download/install.sh.sig
cosign verify-blob --signature install.sh.sig ... install.sh
sh install.sh
```

Four lines instead of one, and the four lines are the entire point. The script itself:

- Detects OS/arch, downloads the matching artifact **and** its signature and checksum
- Verifies checksum, then signature; **aborts on any failure**, never falls back to "install anyway"
- Installs to `~/.local/bin` by default; `--system` for `/usr/local/bin`
- Refuses to run as root unless `--system` is passed explicitly
- Prints exactly what it did and how to uninstall
- Is idempotent

`INSTALLATION.md` shows the manual path first and the script second, with a sentence explaining why piping a URL into a shell is a poor habit for a tool whose job is telling you about poor habits.

---

## 6. Container image

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY plumbline /usr/local/bin/plumbline
USER nonroot
ENTRYPOINT ["/usr/local/bin/plumbline"]
```

Distroless static, non-root by default, no shell in the image.

**Host scanning from a container — the correct invocation:**

```bash
docker run --rm \
  -v /:/host:ro \
  -v "$PWD/out:/out" \
  --pid=host \
  ghcr.io/antaryx/plumbline:1.0.0 \
  collect --root /host -o /out/host.plb
```

Then evaluate off-host:

```bash
plumbline eval out/host.plb --format terminal,json
```

`--root /host` is what makes this correct. The source design's `docker run --privileged ghcr.io/argus/argus scan` scans the *container's* filesystem and reports the result as if it were the host — confidently wrong output, which for an auditing tool is the worst category of bug (audit A-09).

Note also what is *not* here: `--privileged`. Read-only host mount plus `--pid=host` covers the great majority of checks; the doc states plainly which checks are unavailable in this mode and why, and the report marks them `SKIPPED(container_context)` rather than silently omitting them.

---

## 7. Air-gapped and offline

A first-class deployment mode, not an afterthought, because the target users often work in exactly these environments.

| Need | How |
|---|---|
| Install with no internet | Download the artifact bundle on a connected machine; verify there; transfer. Signature verification works fully offline once `cosign` and the certificate are present. |
| Scan with no internet | Default. The scan path makes zero network syscalls, and there is a CI test asserting it. |
| Vulnerability data (v2+) | `plumbline db export --to vulndb-2026-08-18.tar.zst` on a connected host, transfer, `plumbline db import` on the air-gapped one. Signature verified on import. |
| Evaluate elsewhere | `collect` inside the enclave, carry the bundle out (redacted if needed), `eval` outside. This is the flagship workflow of the whole architecture. |

---

## 8. Upgrade and rollback

**Upgrade:** replace the binary. There is no installed state on the host by default — no daemon, no database, no config that must be migrated. This is a deliberate design property that makes upgrade risk near zero.

What can change across an upgrade:

| Change | Detection | User action |
|---|---|---|
| New checks appear | Catalog version bumped; `plumbline diff` annotates added checks separately from newly-failing ones | Review new findings; add suppressions if accepted |
| Posture score moves | Score carries its catalog version; comparison across versions is flagged | Expected; re-baseline |
| A check was corrected | `### Check corrections` in the changelog, plus a startup warning for high-impact corrections | Read the changelog |
| Schema major changed | `"schema"` field in output; `--schema v1` still available for one major | Update consumers within the window |
| Config key removed | Two minors of deprecation warning first; `plumbline config validate` reports it | Run `plumbline config migrate` |

**Rollback:** reinstall the previous version. Old bundles remain readable by new binaries **and** new bundles are readable by binaries back to the same schema major. The compatibility matrix in `SUPPORT-POLICY.md` states this explicitly per release.

**Uninstall:** remove the binary, optionally `rm -rf ~/.config/plumbline ~/.local/share/plumbline`. Documented in `INSTALLATION.md`, because a tool that cannot tell you how to remove it cleanly has no business auditing your system.

---

## 9. Files on disk

| Path | Contents | Permissions |
|---|---|---|
| `~/.config/plumbline/config.yaml` | User config | `0600` |
| `~/.local/share/plumbline/bundles/` | Saved bundles | dir `0700`, files `0600` |
| `~/.local/share/plumbline/vulndb/` | Vulnerability DB (v2+) | dir `0700` |
| `/etc/plumbline/config.yaml` | System config | `0644`, root-owned |
| `/var/lib/plumbline/` | System-wide bundles, only if `collect --system` | dir `0700`, root-owned |

XDG paths, not `~/.plumbline/`. Report and bundle permissions are `0600` and are asserted in tests: these files contain the user list, the open-port inventory, the package manifest and file paths — a complete reconnaissance package for anyone who can read them (audit A-17).

Nothing is written outside these paths. No logs in `/var/log` unless `--log-file` is passed explicitly, because a root process appending attacker-influenced filenames to a shared log is a log-injection vector.

---

## 10. CI/CD usage by consumers

What a user's pipeline looks like — this is the deployment surface that matters most for the DevSecOps persona.

```yaml
- name: Install Plumbline
  run: |
    VERSION=1.0.0
    BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION
    curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
    curl -fsSLO $BASE/checksums.txt
    curl -fsSLO $BASE/checksums.txt.sig
    curl -fsSLO $BASE/checksums.txt.pem
    cosign verify-blob \
      --certificate checksums.txt.pem --signature checksums.txt.sig \
      --certificate-identity-regexp '^https://github\.com/antaryx/plumbline/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      checksums.txt
    sha256sum --ignore-missing -c checksums.txt
    tar xzf plumbline_${VERSION}_linux_amd64.tar.gz

- name: Audit
  run: |
    ./plumbline scan \
      --profile server \
      --format json,sarif \
      --output-dir ./reports \
      --suppressions .plumbline-suppressions.yaml \
      --fail-on high \
      --min-coverage 80

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./reports/plumbline.sarif
```

Two details the source design's equivalent example lacked:

- **A pinned version and verified download.** The original piped an unpinned installer from a domain into bash, inside a pipeline, for a security tool.
- **`--min-coverage`.** Without it, a scan that could not read anything exits 0 and the pipeline goes green while auditing nothing. Exit code 4 (degraded) exists for exactly this, and `if: always()` on the upload step ensures the SARIF still lands when the gate trips.

---

## 11. Incident response for a bad release

A release that produces wrong security verdicts is a genuine incident. Runbook, owned by `RUNBOOK-bad-release.md`:

1. **Assess:** wrong verdict (false PASS is severe, false FAIL is annoying), crash, or supply-chain compromise.
2. **Communicate first, fix second.** Pin an issue and edit the release notes with a warning banner within the hour. People are running this against production hosts.
3. **Do not delete the release.** Deleting artifacts breaks pinned pipelines and destroys the evidence. Mark it, supersede it.
4. **Patch release** with the correction documented under `### Check corrections`.
5. **If a false PASS shipped:** state explicitly which check, which versions, and which conditions, so users can determine whether they were affected. Anyone who acted on that PASS must be able to re-check.
6. **If the supply chain is implicated:** revoke nothing (keyless certs are short-lived), publish the affected digests, rotate the workflow identity, and follow `SECURITY.md`'s disclosure process.
7. **Post-mortem** in `postmortems/`, and a new fixture in the corpus that would have caught it. Every incident permanently adds a test.

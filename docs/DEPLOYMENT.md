# Deployment

How a release is built, signed, published, installed, verified, upgraded and
rolled back. For a CLI security tool "deployment" means artifact supply chain,
not servers. The project runs no infrastructure by design.

Section 12 lists what this document describes but the pipeline does not yet do.
Read it before you rely on anything here.

---

## 1. Principles

1. **A security tool must be verifiable.** Every release is signed, carries an
   SBOM, and has verification steps a user can follow in under a minute.
2. **No hosted infrastructure.** No install domain, no plugin registry, no
   telemetry endpoint. GitHub Releases plus signed files is the whole
   distribution system. Everything the source design proposed, meaning
   `get.argus-security.io` and `plugins.argus-security.io`, is cost, uptime
   obligation and attack surface for one person.
3. **Reproducible builds.** Two people building the same tag get the same
   binary.
4. **The installer must not require trust.** Piping `curl` into `bash` for a
   security auditing tool is self-parodying. The docs lead with manual
   verification.
5. **Distro packaging is community work and never a release gate.** Getting into
   Debian or Fedora depends on other people's decisions. It cannot be a roadmap
   deliverable.

---

## 2. Build

### 2.1 Matrix

`.goreleaser.yaml` builds `linux/amd64` and `linux/arm64`. That is the whole
published matrix today.

| Release | Target |
|---|---|
| v1.0.0, v2.0.0 | `linux/amd64`, `linux/arm64` |
| later | `linux/armv7` if CI hardware appears |
| later | `darwin/amd64`, `darwin/arm64` with macOS support |

Nothing is published for a platform that is not tested in CI. Cross-compiling to
riscv64 is one line in GoReleaser and zero evidence that it works. The source
design listed five architectures on that basis.

### 2.2 Flags

```bash
CGO_ENABLED=0 GOFLAGS="-trimpath" \
go build \
  -ldflags "-s -w \
    -X main.buildVersion=${VERSION} \
    -X main.commit=${SHORT_COMMIT} \
    -X main.date=${COMMIT_DATE}" \
  -o dist/plumbline ./cmd/plumbline
```

`CGO_ENABLED=0` gives a static binary with no glibc coupling, which runs on
Alpine and on distroless. That is what makes the single-binary claim true.
`-trimpath` removes local paths and is a reproducibility requirement. The build
date comes from the commit timestamp, so no wall clock reaches the binary.
`mod_timestamp` is pinned to the commit for the same reason. Version metadata is
injected at link time and never hardcoded in source.

### 2.3 Reproducibility

The build is deterministic by construction. Nothing checks it. See §12.

`SUPPLY-CHAIN.md` documents the procedure for a third party to rebuild a tag and
compare, which is currently the only way this property gets tested.

---

## 3. Signing and SBOM

| Artifact | What actually happens |
|---|---|
| `checksums.txt` | SHA-256 over every artifact in the release |
| Signature | `cosign sign-blob` over `checksums.txt`, keyless via GitHub OIDC, producing `checksums.txt.sig` and `checksums.txt.pem` |
| SBOM | `syft`, SPDX 2.3 JSON, one per archive and one per package |
| Git tags | signed |

One signature covers the release. Cosign signs the checksum file and the
checksum file covers everything else, so verifying two files verifies all of
them. Individual tarballs do not carry their own `.sig`.

Keyless signing is the right default for a solo maintainer. There is no
long-lived private key to lose, rotate or have stolen, and the identity is the
GitHub workflow, which is publicly auditable. Pin the expected identity and
issuer:

```bash
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/antaryx/plumbline/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --ignore-missing checksums.txt
```

That command belongs in `INSTALLATION.md` above the fold, not in an appendix,
and it is there.

---

## 4. Release pipeline

What `.github/workflows/release.yml` runs today:

```
tag v2.0.0 (signed)
   │
   ├─ checkout · setup-go · install syft · install cosign
   ├─ make verify        (seam · purity · fixtures · generated docs · full suite)
   ├─ goreleaser         build ×2 arches · archives · deb · rpm
   ├─ syft               SBOM per artifact
   ├─ cosign             sign checksums.txt
   └─ GitHub Release     binaries · checksums · sig · pem · SBOMs · notes
```

The post-publish smoke test is the step people skip and the one that catches the
embarrassing failures: an artifact uploaded truncated, a binary that will not
start on musl, a signature over the wrong file. It is not automated here. Do it
by hand until it is.

---

## 5. Distribution channels

### 5.1 Controlled by the project

| Channel | State |
|---|---|
| GitHub Releases, archives and packages | shipping since v1.0.0 |
| `go install github.com/antaryx/plumbline/cmd/plumbline@latest` | works, unsigned by construction |
| Container image | not published, see §12 |
| Verifying install script | not written, see §12 |
| Homebrew tap | not published |

### 5.2 Community, best-effort, no promises

AUR, Debian and Ubuntu packages, Fedora COPR, Alpine, nixpkgs. Each needs either
a third party's approval or ongoing maintenance the project has not budgeted
for. `INSTALLATION.md` would list these as community-maintained and possibly
lagging, and link to whoever maintains them. They never appear on a roadmap.

The source design promised `apt install argus` via an official PPA, `dnf install
argus` via COPR, `apk add argus` in Alpine testing, and `pkg install argus` on
FreeBSD. Four ongoing packaging obligations, three depending on other people's
review queues, all committed to before a line of code existed.

### 5.3 The install script, when it exists

```bash
curl -fsSLO https://github.com/antaryx/plumbline/releases/latest/download/install.sh
curl -fsSLO https://github.com/antaryx/plumbline/releases/latest/download/install.sh.sig
cosign verify-blob --signature install.sh.sig ... install.sh
sh install.sh
```

Four lines instead of one, and the four lines are the entire point. What the
script has to do:

- Detect OS and arch, download the matching artifact along with its signature
  and checksum
- Verify checksum, then signature, and abort on any failure rather than falling
  back to installing anyway
- Install to `~/.local/bin` by default, `--system` for `/usr/local/bin`
- Refuse to run as root unless `--system` is passed explicitly
- Print exactly what it did and how to undo it
- Be idempotent

`INSTALLATION.md` shows the manual path first, which is what exists today.

---

## 6. Container image

Not published. The Dockerfile below is the intended shape and the invocation
below is the correct one, both recorded so that whoever builds it does not
reinvent the mistake underneath.

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY plumbline /usr/local/bin/plumbline
USER nonroot
ENTRYPOINT ["/usr/local/bin/plumbline"]
```

Distroless static, non-root by default, no shell in the image.

Scanning a host from a container:

```bash
docker run --rm \
  -v /:/host:ro \
  -v "$PWD/out:/out" \
  --pid=host \
  ghcr.io/antaryx/plumbline:2.0.0 \
  collect --root /host -o /out/host.plb
```

Then evaluate off-host:

```bash
plumbline eval out/host.plb
```

`--root /host` is what makes this correct. The source design's `docker run
--privileged ghcr.io/argus/argus scan` scans the container's filesystem and
reports the result as though it were the host. Confidently wrong output, which
for an auditing tool is the worst category of bug (audit A-09).

Note what is absent: `--privileged`. A read-only host mount plus `--pid=host`
covers most checks. Checks that cannot run in this mode report `SKIPPED` rather
than being silently omitted.

---

## 7. Air-gapped and offline

A first-class mode, not an afterthought, because the target users often work in
exactly these environments.

| Need | How |
|---|---|
| Install with no internet | Download the artifacts on a connected machine, verify there, transfer. Signature verification works fully offline once `cosign` and the certificate are present. |
| Scan with no internet | Default. The scan path makes zero network syscalls and a CI test asserts it. |
| Evaluate elsewhere | `collect` inside the enclave, carry the bundle out redacted if needed, `eval` outside. This is the flagship workflow of the whole architecture. |
| Vulnerability data | Not applicable. There is no vulnerability database and no `plumbline db` command. |

---

## 8. Upgrade and rollback

**Upgrade:** replace the binary. There is no installed state on the host: no
daemon, no database, no config that must be migrated. That is a deliberate
design property and it makes upgrade risk close to zero.

What can change across an upgrade:

| Change | How you find out | What to do |
|---|---|---|
| New checks appear | Catalog version moves; `plumbline diff` separates added checks from newly failing ones | Review the new findings, suppress the ones you accept |
| Posture score moves | The score carries its catalog version, and comparison across versions is flagged | Expected. Re-baseline |
| A check was corrected | `### Check corrections` in the changelog, plus a startup notice for high-impact corrections | Read the changelog |
| Schema major changed | The `"schema"` field in the output | Update consumers within the support window |

**Rollback:** reinstall the previous version. Old bundles stay readable by new
binaries, and new bundles are readable by binaries back to the same schema
major.

**Uninstall:** remove the binary. `INSTALLATION.md` covers it, because a tool
that cannot tell you how to remove it cleanly has no business auditing your
system.

---

## 9. Files on disk

Plumbline writes only where you point it, with `-o`, `--save-bundle` or
`--write-script`. There is no cache, no state directory and no dotfile today.

| Path | Contents | Permissions |
|---|---|---|
| whatever you pass to `-o` or `--save-bundle` | Report or bundle | `0600` |
| whatever you pass to `--write-script` | Generated remediation script | `0700` |

If configuration and bundle directories are ever added, the shape is XDG rather
than `~/.plumbline/`, with `0600` files under `0700` directories. Report and
bundle permissions are asserted in tests: these files hold the user list, the
open-port inventory and file paths, which is a complete reconnaissance package
for anyone who can read them (audit A-17).

No logs go to `/var/log` unless `--log-file` is passed explicitly, because a
root process appending attacker-influenced filenames to a shared log is a
log-injection vector.

---

## 10. What a consumer's pipeline looks like

This is the deployment surface that matters most for the DevSecOps persona. Every
flag below exists in this build.

```yaml
- name: Install Plumbline
  run: |
    VERSION=2.0.0
    BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION
    curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
    curl -fsSLO $BASE/checksums.txt
    curl -fsSLO $BASE/checksums.txt.sig
    curl -fsSLO $BASE/checksums.txt.pem
    cosign verify-blob checksums.txt \
      --certificate checksums.txt.pem --signature checksums.txt.sig \
      --certificate-identity-regexp '^https://github\.com/antaryx/plumbline/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    sha256sum --ignore-missing -c checksums.txt
    tar xzf plumbline_${VERSION}_linux_amd64.tar.gz

- name: Audit
  run: |
    sudo ./plumbline scan \
      --format sarif -o plumbline.sarif \
      --suppress .plumbline/accepted-risks.json \
      --fail-on high \
      --min-coverage 80

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: plumbline.sarif
```

Two details the source design's equivalent lacked:

- **A pinned version and a verified download.** The original piped an unpinned
  installer from a domain into bash, inside a pipeline, for a security tool.
- **`--min-coverage`.** Without it a scan that could read nothing exits 0 and the
  pipeline goes green while auditing nothing. Exit code 4 exists for exactly
  this, and `if: always()` on the upload step keeps the SARIF landing when the
  gate trips.

`--format` takes one value. Run the command twice if you want JSON as well as
SARIF. There is no `--output-dir`, and the suppression file is
`suppressions/v1` JSON rather than YAML.

---

## 11. Incident response for a bad release

A release that produces wrong security verdicts is a genuine incident.

1. **Assess.** A false PASS is severe, a false FAIL is annoying, a crash is
   somewhere between, and supply-chain compromise is its own category.
2. **Communicate first, fix second.** Pin an issue and put a warning banner in
   the release notes within the hour. People are running this against production
   hosts.
3. **Do not delete the release.** Deleting artifacts breaks pinned pipelines and
   destroys the evidence. Mark it and supersede it.
4. **Patch release**, with the correction documented under `### Check
   corrections`.
5. **If a false PASS shipped,** state which check, which versions and which
   conditions, so users can work out whether they were affected. Anyone who
   acted on that PASS has to be able to re-check.
6. **If the supply chain is implicated,** revoke nothing because keyless certs
   are short-lived, publish the affected digests, rotate the workflow identity
   and follow `SECURITY.md`.
7. **Post-mortem** in `postmortems/`, and a new fixture in the corpus that would
   have caught it. Every incident permanently adds a test.

---

## 12. What this document describes and the pipeline does not do

Checked against `.github/workflows/release.yml` and `.goreleaser.yaml` on
2026-09-02. Earlier revisions stated all of these in the present tense, which is
the same failure the threat model was corrected for.

- **No double-build reproducibility check.** CI builds once.
- **No SLSA provenance attestation.**
- **No container image.** Nothing pushes to ghcr.io.
- **No install script**, verifying or otherwise.
- **No Homebrew tap.**
- **No post-publish smoke test** across distributions.
- **No `plumbline doctor`, `plumbline db`, `plumbline config` or `plumbline
  mapping` commands.** The binary carries `collect`, `diff`, `eval`, `explain`,
  `profiles`, `scan` and `version`.

`SUPPLY-CHAIN.md` carries the same list for the items that are supply-chain
controls. Keep the two in step.

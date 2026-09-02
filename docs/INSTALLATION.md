# Installation

## Verified install

Every release carries `.deb`, `.rpm` and `.tar.gz` for `linux/amd64` and
`linux/arm64`, each with an SPDX SBOM, plus a cosign-signed checksum file.

```bash
VERSION=2.0.0
BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION

curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
curl -fsSLO $BASE/checksums.txt
curl -fsSLO $BASE/checksums.txt.sig
curl -fsSLO $BASE/checksums.txt.pem
```

### Verify before installing

This binary runs as root on the host you are auditing. Taking it on trust
undoes every other guarantee the tool offers.

```bash
# 1. The signature is genuine and came from this repository's release workflow.
cosign verify-blob checksums.txt \
  --signature   checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp 'https://github.com/antaryx/plumbline/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. What you downloaded is what was signed.
sha256sum -c --ignore-missing checksums.txt
```

Both must print `OK` or `Verified OK`. If either fails, stop. Do not install,
and open a security report (see [`../SECURITY.md`](../SECURITY.md)).

Signing is keyless. No private key exists to leak or rotate, and the certificate
records the workflow, repository and commit that produced the artifact.

### Install

```bash
sudo tar -xzf plumbline_${VERSION}_linux_amd64.tar.gz -C /usr/local/bin plumbline
```

Or from a package. Verify the checksum the same way first:

```bash
sudo dpkg -i plumbline_${VERSION}_linux_amd64.deb     # Debian, Ubuntu
sudo rpm -i  plumbline_${VERSION}_linux_amd64.rpm     # RHEL, Rocky, Fedora
```

Neither package pulls a dependency. The binary is statically linked, so the same
one runs on glibc and musl, including from a rescue shell.

### Inspect before running

```bash
curl -fsSL $BASE/plumbline_${VERSION}_linux_amd64.tar.gz.sbom.spdx.json \
  | jq -r '.packages[].name'
```

Three third-party Go modules and the program itself. That is the whole
dependency tree of the shipped binary. `go.mod` declares a fourth, a JSON-schema
validator, which only the tests import. `go version -m $(command -v plumbline)`
says the same thing without the SBOM.

## From source

```bash
git clone https://github.com/antaryx/plumbline
cd plumbline
make verify     # optional: run the full gate first
make build      # → dist/plumbline
```

Go 1.24 is the floor `go.mod` states. Releases are built with 1.25. Go supports
only its two newest majors, and a root-privileged binary is the last one you
want built with an unmaintained toolchain.

## Air-gapped hosts

Nothing about installation or operation needs a network. Copy the verified
tarball in on removable media. The tool makes no network calls at any point, so
there is no allowlist to configure and no update check to disable.

## Upgrade

Replace the binary. There is no state, no database, no service, no config
migration. Bundles from any earlier version stay readable forever
(`docs/VERSIONING.md`).

## Uninstall

```bash
sudo rm /usr/local/bin/plumbline        # tarball install
sudo dpkg -r plumbline                  # or: sudo rpm -e plumbline
```

Plumbline writes nothing outside the paths you name with `-o` or
`--save-bundle`. There is no cache, no state directory, no dotfile to clean up.
Delete any `.plb` bundles and reports you created. They contain host inventory.

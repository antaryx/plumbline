# CI integration

## The one thing to get right

Gate on coverage, not only on findings.

```bash
plumbline scan --json --fail-on high --min-coverage 90
```

A pipeline told about the failures it can fix, while quietly not being told
about the half of the host nobody could read, is a pipeline that believes it is
green. That is why exit `4` (degraded) outranks exit `2` (findings) in the
ladder, and why `--min-coverage` matters more than `--fail-on`.

Run as root, or accept that a large part of the host reports `UNKNOWN`.

## GitHub Actions

```yaml
- name: Install plumbline
  run: |
    VERSION=2.0.0
    BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION
    curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
    curl -fsSLO $BASE/checksums.txt
    curl -fsSLO $BASE/checksums.txt.sig
    curl -fsSLO $BASE/checksums.txt.pem
    cosign verify-blob checksums.txt \
      --signature checksums.txt.sig --certificate checksums.txt.pem \
      --certificate-identity-regexp 'https://github.com/antaryx/plumbline/.*' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    sha256sum -c --ignore-missing checksums.txt
    sudo tar -xzf plumbline_${VERSION}_linux_amd64.tar.gz -C /usr/local/bin plumbline

- name: Audit
  run: sudo plumbline scan --format sarif -o plumbline.sarif --min-coverage 90

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: plumbline.sarif
```

Pin the version and verify it. A CI step that pipes an unverified download into
a root shell is a supply-chain hole in the pipeline that is auditing your hosts
for supply-chain holes.

### Reading the SARIF in the Security tab

`UNKNOWN` arrives as a `warning`, not an informational `none`. A check that
could not tell is not a check that passed. `PASS` and `NOT_APPLICABLE` are
counted in the run's invocation rather than emitted as results, because a wall
of passes buries the handful that matter. Accepted risks arrive as native SARIF
suppressions carrying their justification, so a dismissal in GitHub shows the
reason a human wrote. Full mapping:
[`adr/0018-sarif-mapping.md`](adr/0018-sarif-mapping.md).

## GitLab CI

```yaml
audit:
  script:
    - plumbline scan --json -o findings.json --fail-on high --min-coverage 90
  artifacts:
    when: always
    paths: [findings.json]
  allow_failure:
    exit_codes: [2]     # report findings without blocking; never allow 4
```

Allowing `2` while blocking `4` is the deliberate configuration. Tolerate known
misconfiguration you are working through. Never tolerate a scan that could not
see the host.

## Jenkins

```groovy
def code = sh(script: 'plumbline scan --json -o findings.json --min-coverage 90',
              returnStatus: true)
archiveArtifacts 'findings.json'
if (code == 4)  { error 'Scan degraded: coverage below threshold' }
if (code >= 10) { error "Scan did not complete (exit ${code})" }
if (code == 2)  { unstable 'Findings at or above threshold' }
```

## Tracking drift instead of absolute state

The most useful thing a pipeline can report is what changed:

```bash
plumbline collect -o today.plb
plumbline diff baseline.plb today.plb
```

`diff` prints nothing when nothing moved, so a nightly job that is quiet is
genuinely quiet. `REGRESSED` catches an expired suppression: a finding that was
accepted, whose acceptance lapsed, and which nobody would otherwise revisit.

## Suppressions in a pipeline

Commit the suppression file to the repository that owns the host's
configuration, and require review on it. The `justification` field is what makes
that review possible, and it is mandatory.

```bash
plumbline scan --suppress ops/accepted-risks.json --fail-on high
```

Set `expires_at` on every rule. It is measured against the scan's start time, so
an accepted risk resurfaces on schedule rather than silently outliving the
person who accepted it.

## What not to do

- **Do not parse the terminal report.** Its layout can change in a patch
  release. Parse `--json`. It is schema-validated in CI and it is the API.
- **Do not gate on posture alone.** It is a ratio over applicable checks, and a
  narrow profile makes it flattering. Pair it with `--min-coverage`.
- **Do not run without `--min-coverage`** unless you are also reading the exit
  code for `4`.
- **Do not treat `UNKNOWN` as a pass.** It is the tool telling you it could not
  answer.

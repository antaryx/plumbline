# Support

Plumbline is maintained by one person. That shapes what support looks like, and
saying so plainly is better than implying a service level that does not exist.

## Where to go

| For | Use |
|---|---|
| A question about using it | GitHub Discussions, or an issue if Discussions is off |
| A suspected false positive | An issue — read [`docs/FALSE-POSITIVES.md`](docs/FALSE-POSITIVES.md) first |
| A bug | An issue, with `plumbline version --json` and a redacted bundle |
| A **security vulnerability in Plumbline** | **Do not open an issue.** See [`SECURITY.md`](SECURITY.md) |
| A feature request | An issue, but read [`docs/ROADMAP.md`](docs/ROADMAP.md) first — several popular ideas are in the graveyard section with reasons |

## What makes a report actionable

A redacted bundle is worth more than anything else you can attach:

```bash
plumbline collect --redact -o report.plb
```

Every finding is reproducible from one, offline, against any catalog version —
so a maintainer can investigate without access to your host. Read
[`docs/PRIVACY.md`](docs/PRIVACY.md) before attaching one; a bundle contains
host inventory.

## Response times

Best effort. No SLA, and none is implied. Security reports are triaged first;
everything else is handled when there is time.

## What is supported

| | |
|---|---|
| Platforms | Linux, glibc and musl, amd64 and arm64 |
| Versions | The latest release. Security fixes for the current major; see [`docs/VERSIONING.md`](docs/VERSIONING.md) |
| Bundle compatibility | **Read support is forever.** Any released binary reads any historical bundle |

Not supported: macOS, BSD, Windows, 32-bit architectures, and anything you build
from a branch other than a release tag.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the workflow.
[`CONTRIBUTING.md`](CONTRIBUTING.md) has the working agreement, and it is not optional
reading — the invariants in it are cheap to violate and expensive to discover.
Every check needs PASS and FAIL fixtures; CI blocks without them.

# Quickstart

## 1. Install

```bash
VERSION=2.0.0
BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION
curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
sudo tar -xzf plumbline_${VERSION}_linux_amd64.tar.gz -C /usr/local/bin plumbline
```

Verify the signature before you install. This binary runs as root on the host
you are auditing. Two commands, in [`INSTALLATION.md`](INSTALLATION.md).

## 2. Scan

```bash
sudo plumbline scan
```

Root is optional. It is also what makes the answer complete. An unprivileged
scan cannot read `/etc/shadow` or most of `/etc/ssh`, so it reports `UNKNOWN`
there instead of passing.

## 3. Read the result

```
[+] SSHD  · 19 checks, 2 failing
  - Root login over SSH is disabled                                [ WARNING ]

[=] Scan summary
  ╭──────────────────────────────────────────────────────────────────────────╮
  │ posture   93.4   coverage 100.0% of applicable checks                    │
  ╰──────────────────────────────────────────────────────────────────────────╯

  112 checks evaluated · catalog 34
```

`UNKNOWN` is not a pass. The check could not read what it needed and refused to
guess. Treat it as a finding until you resolve it.

Coverage always prints next to posture. A score of 86 over 17% coverage is not a
host that is mostly fine. It is a host that was mostly not examined.

`FAIL` prints as `WARNING` because that word tells you what to do about it. The
result is `FAIL` in the JSON, in the exit code, and in the score.

## 4. Understand one finding

```bash
plumbline explain SSHD-0002
```

What the check tests, which facts it reads, and the remediation with every step
and caution. No host, no network, no privileges.

## 5. Keep the evidence

```bash
sudo plumbline scan --save-bundle host.plb
plumbline eval host.plb          # re-evaluate later, anywhere, ~10ms
```

A `.plb` holds the facts observed, not the verdicts drawn from them. That is
what lets a scan taken today be re-judged by a newer catalog next year.

## Next

- [`USAGE.md`](USAGE.md) for every command, with examples that do something
- [`CI-INTEGRATION.md`](CI-INTEGRATION.md) for gating a pipeline
- [`FALSE-POSITIVES.md`](FALSE-POSITIVES.md) for when a finding is wrong for you

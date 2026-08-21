# Quickstart

Zero to a useful scan. One page.

## 1. Install

```bash
VERSION=1.0.0
BASE=https://github.com/antaryx/plumbline/releases/download/v$VERSION
curl -fsSLO $BASE/plumbline_${VERSION}_linux_amd64.tar.gz
sudo tar -xzf plumbline_${VERSION}_linux_amd64.tar.gz -C /usr/local/bin plumbline
```

**Verify the signature first** — this binary will run as root on the host you
are auditing. Two commands, in [`INSTALLATION.md`](INSTALLATION.md).

## 2. Scan

```bash
sudo plumbline scan
```

Root is not required. It is what makes the answer complete: an unprivileged
scan cannot read `/etc/shadow` or half of `/etc/ssh`, and it reports `UNKNOWN`
for those rather than passing them.

## 3. Read the result

```
[+] SSHD  · 19 checks, 2 failing
  - Root login over SSH is disabled                                 [ WARNING ]

[=] Scan summary
  ╭──────────────────────────────────────────────────────────────────────────╮
  │ posture   93.4   coverage 100.0% of applicable checks                    │
  ╰──────────────────────────────────────────────────────────────────────────╯
```

Three things to know about that output:

- **`UNKNOWN` is not a pass.** It means the check could not read what it needed
  and declined to guess. Treat it as a finding until resolved.
- **Coverage always appears beside posture.** A score of 86 over 17% coverage
  is not a host that is mostly fine; it is a host that was mostly not examined.
- **`FAIL` shows as `WARNING`** in the report because that is the word that says
  what to do about it. The result is `FAIL` everywhere it matters — the JSON,
  the exit code, the score.

## 4. Understand one finding

```bash
plumbline explain SSHD-0002
```

What the check tests, which facts it reads, and the remediation with every step,
command and caution. No host, no network, no privileges.

## 5. Keep the evidence

```bash
sudo plumbline scan --save-bundle host.plb
plumbline eval host.plb          # re-evaluate later, anywhere, ~10ms
```

A `.plb` is the *facts observed*, not the verdicts drawn from them — which is
what lets a scan taken today be re-judged by a newer catalog next year.

## Next

- [`USAGE.md`](USAGE.md) — every command, with realistic examples
- [`CI-INTEGRATION.md`](CI-INTEGRATION.md) — gating a pipeline
- [`FALSE-POSITIVES.md`](FALSE-POSITIVES.md) — when a finding is wrong for you

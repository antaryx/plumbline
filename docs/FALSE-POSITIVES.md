# False positives

Shipping this document admits the tool is imperfect. That is deliberate. A
security scanner that claims otherwise is one nobody experienced believes, and
the fastest way to be trusted is to say up front where you are likely to be
wrong.

## First: is it actually a false positive?

Four things get reported as false positives. Three of them are not.

`UNKNOWN` is not a false positive. It is the tool saying it could not read what
it needed. The fix is usually to run as root, or to look at why the file was
unreadable. That unreadability is often the finding.

"It is configured but not active" is not a false positive. Plumbline reports
what is configured, not what is loaded. A host with a perfect `nftables.conf`
and a disabled `nftables.service` genuinely has no firewall, and two modules
report the two halves separately. That is the design, stated in `README.md` and
in `docs/ARCHITECTURE.md`.

"This is fine on our estate" is not one either. It is an accepted risk, and
there is a mechanism for it:
[suppressions](USAGE.md#suppressions-accept-a-risk-without-hiding-it) keep the
finding visible with your reason attached instead of deleting it.

A genuine false positive is the fourth: the check read the value, and the
verdict it drew is wrong about this host.

## Known ones

| Where | Why it happens |
|---|---|
| `AUTH-*` on a host managed by `authselect` or `pam-auth-update` | The stack is generated. A hand-edit the check sees may be overwritten at the next apply, and a correct configuration may live in a source file the check does not read. |
| `SERVICES-*` on non-systemd hosts | Enablement is recovered from `.wants/` symlinks. OpenRC and sysvinit degrade to `NOT_APPLICABLE` rather than being judged by systemd's rules. |
| `FILESYS-0010` on hosts using LDAP, SSSD or NIS | An identity absent from `/etc/passwd` may be a real account served from somewhere the scan cannot ask, because it never opens a network socket. The check reports `UNKNOWN` when `/etc/nsswitch.conf` says the local files are not the whole database. Correct, but surprising. |
| `KERNEL-*` inside a container | `/proc/sys` is the host's, namespaced. A container cannot set most of them, so failures there describe the machine, not the image. |
| `CRON-*` on a checkout or an image built as non-root | The checks require root ownership. Files owned by the build user fail correctly and unhelpfully. |
| `MEMORY-0003` on a small C utility | `-fstack-protector-strong`, the distribution default, instruments only functions with local arrays or address-taken locals. A program with neither is compiled correctly and still carries no `__stack_chk_fail`. On a stock Debian host `/usr/bin/newgrp` is exactly this. |
| `MEMORY-0004` on Alpine, or anywhere musl replaces glibc | musl does not implement `_FORTIFY_SOURCE`'s `_chk` entry points, so no binary linked against it can reference one. On Alpine the golden bundle records `/usr/bin/crontab` and `/usr/bin/passwd` failing, and both are the same `/bin/busybox` under two names. The check reads the symbol table correctly. glibc's mechanism is simply not the one in use. |
| `MEMORY-0003` and `MEMORY-0004` on a binary from a memory-safe language | Rust and Go do not use glibc's stack protector or its fortified entry points, so neither symbol appears. `sudo-rs`, which several distributions now ship as `/usr/bin/sudo`, reports as though it had no hardening at all. The symbol table is telling the truth. It is the wrong question for that binary. |
| Any module on a distribution not in the golden corpus | Six distributions are recorded and re-evaluated on every build. A seventh may lay out `/etc` in a way no check anticipated. |

## Reporting one well

A good report is one somebody can turn into a fixture. Include:

1. `plumbline version --json`, which gives the tool, catalog and schema
   versions.
2. A redacted bundle: `plumbline collect --redact -o report.plb`. `--redact`
   drops the hostname at collection time. Read [`PRIVACY.md`](PRIVACY.md) first,
   because a bundle contains host inventory.
3. The check ID and what you expected, in the form "the check says X, the host
   is actually Y, here is the file it read".
4. The distribution and version.

A bundle beats a screenshot by a wide margin. Every finding is reproducible from
it offline, so a maintainer can re-evaluate it against any catalog version
without touching your host.

## What happens to it

A confirmed false positive becomes a fixture under `testdata/fixtures/` that
reproduces the wrong verdict. Then a fix. Then that fixture stays in CI forever.
The check's ID never changes and is never reused, because it is in your
suppression files and in bundles on disk (`docs/VERSIONING.md`).

If a fix would move a verdict on other hosts, the golden-bundle diff shows that
blast radius across six real distributions before the change lands.

## Suppressing one meanwhile

```bash
plumbline scan --suppress accepted.json
```

Use a real justification and an `expires_at`. A suppression for a bug should
expire when you expect the fix, so it resurfaces instead of becoming permanent
by neglect.

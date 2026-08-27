# Privacy

## The short version

**Plumbline makes no network calls of any kind.** No telemetry, no update check,
no crash reporting, no analytics. There is nothing to opt out of because there
is nothing to opt into.

This is enforced rather than promised: a CI job runs a full scan inside
`unshare -n` and asserts it produces a document byte-identical to an online run.
Anything that reached for a socket would fail that job. See T-13 in
[`THREAT-MODEL.md`](THREAT-MODEL.md).

## What a bundle contains

A `.plb` is host inventory. Treat it as sensitive.

| Included | Detail |
|---|---|
| Account names, uids, gids, shells, home paths | From `passwd` and `group` |
| Password **properties** | Algorithm, locked, empty, ageing — **never a hash** |
| sshd effective configuration | Including `Match` blocks and resolved includes |
| PAM stack structure and module arguments | Policy, not credentials |
| Kernel parameters | Running values and the configured files |
| Mount table, firewall configuration, cron and logging configuration | |
| The Docker daemon's `ExecStart` | From `docker.service` and its drop-ins — **that one line, and no other part of the unit** |
| Filesystem **aggregates** | Counts of setuid, world-writable, unowned inodes, with a small number of example paths |
| Hostname and OS release | Unless `--redact` |
| Evidence blobs | The raw bytes of the configuration files a finding cites |

### What is never collected

- **No password hashes.** `/etc/shadow` is parsed for the *properties* of each
  entry and is never stored as an evidence blob. This is a design decision with
  a test attached (`TestGoldenBundlesCarryNoCredentialMaterial`).
- **No private keys**, no `authorized_keys` contents, no certificates.
- **No file contents from user home directories.** The filesystem walk records
  metadata — mode, owner, size — and never reads a file it walks.
- **No process list and no environment variables.** One *configured* command
  line is collected: the `ExecStart=` of `docker.service`, because the flags on
  it decide whether the Docker API is exposed to the network, which is the
  highest-severity finding this tool makes. Nothing else in the unit is kept —
  the fragments are read through the seam's opaque path, so their bytes never
  reach the evidence store, and `Environment=` and `EnvironmentFile=` are not
  parsed at all. That is the specific concern rather than a general one: a
  Docker host's `docker.service.d/override.conf` is the usual home of
  `Environment="HTTPS_PROXY=https://user:password@proxy"`. No other unit on the
  host is read for its contents by anything in the tree.
- **No network addresses.** Firewall *configuration* is read; interfaces are
  named, addresses are not.

### Filesystem aggregates, specifically

The walk visits every inode but stores counts and a handful of examples, not a
listing. A bundle from a host with two million files does not contain two
million paths — it contains "uid 4242 owns 3 inodes, for example
`/var/lib/oldapp`". That is a deliberate bound on both size and disclosure.

## Redaction

```bash
plumbline collect --redact -o report.plb
```

Drops the hostname **at collection time**, so it is never written to disk rather
than being stripped afterwards. `manifest.redacted` records that it was used, so
a reader can tell a bundle with no hostname from a host that had no name.

`--redact` does not remove account names or paths. If those are sensitive for
your estate, a bundle is not the right thing to share — send the specific
finding from `--json` instead.

## Sharing a bundle for a bug report

Bundles are the single most useful thing you can attach to an issue: every
finding is reproducible from one, offline, against any catalog version. But
read the table above first.

```bash
plumbline collect --redact -o report.plb
zstd -dc report.plb | tar -xO facts/users.passwd.json | jq .   # inspect before sending
```

A bundle is a tar of JSON under zstd. You can read every byte of what you are
about to send, and you should.

## File permissions

Bundles and reports are written `0600` — owner only — by
`system.CreateBundle`, asserted by a unit test and re-asserted on four
distributions in CI. Reports written with `--output` are never coloured, so an
artifact read months later in something that is not a terminal is not full of
escape sequences.

## Retention

Plumbline stores nothing itself: no cache, no state directory, no dotfile. It
writes only where you point it with `-o` or `--save-bundle`.

Bundles do not expire and remain readable forever by design — which means a
bundle you keep is host inventory you keep. Apply the retention policy you would
apply to a configuration backup, because that is effectively what it is.

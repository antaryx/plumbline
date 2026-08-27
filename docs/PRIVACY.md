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
| The Docker daemon's `ExecStart` | From `docker.service` and its drop-ins — **that one line, and no other part of the unit**. See the caveat below |
| Docker `log-opts` **key names** | From `daemon.json` — names only; the values are never decoded |
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
- **No `log-opts` values.** `/etc/docker/daemon.json`'s `log-opts` object is
  read for its key names and never for what they are set to, because that is
  where a logging driver's credentials live: `splunk-token` is an
  authentication token, `awslogs-credentials-endpoint` is the path to one, and
  a `gelf-` or `loki-` address is an internal hostname. The names are enough
  for the only question asked of them — `json-file` is unbounded unless
  `max-size` is set — which is what makes the trade affordable rather than
  merely cautious.

- **No network addresses.** Firewall *configuration* is read; interfaces are
  named, addresses are not.

### The one command line, and its known edge

The `ExecStart=` of `docker.service` is stored in full, argument by argument,
because the flags on it decide whether the Docker API is exposed to the network
and whether it requires a client certificate. That is a deliberate exception and
the paragraph above explains it.

It has an edge worth stating rather than leaving to be discovered. `dockerd`
accepts `--log-opt` on that command line as well as in `daemon.json`, so an
operator who wrote `--log-opt splunk-token=…` in a drop-in has put a credential
on the one line this tool keeps — where the `daemon.json` spelling of the same
option would have had its value dropped. Nothing in the tree redacts it today.

If your fleet configures a logging driver's credentials on `dockerd`'s command
line rather than in `daemon.json`, check the drop-in before sharing a bundle:

```bash
systemctl show -p ExecStart docker.service | grep -o -- '--log-opt [^ ]*'
```

Redacting the values of log options in the recorded `ExecStart` is a named work
package in `docs/ROADMAP.md`. Until it lands, this is a limit rather than a
protection.

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

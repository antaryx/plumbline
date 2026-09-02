# Privacy

## The short version

Plumbline makes no network calls of any kind. No telemetry, no update check, no
crash reporting, no analytics. There is nothing to opt out of because there is
nothing to opt into.

This is enforced rather than promised. A CI job runs a full scan inside
`unshare -n` and asserts it produces a document byte-identical to an online run.
Anything reaching for a socket fails that job. See T-13 in
[`THREAT-MODEL.md`](THREAT-MODEL.md).

## What a bundle contains

A `.plb` is host inventory. Treat it as sensitive.

| Included | Detail |
|---|---|
| Account names, uids, gids, shells, home paths | From `passwd` and `group` |
| Password properties | Algorithm, locked, empty, ageing. Never a hash |
| sshd effective configuration | Including `Match` blocks and resolved includes |
| PAM stack structure and module arguments | Policy, not credentials |
| Kernel parameters | Running values and the configured files |
| Mount table, firewall configuration, cron and logging configuration | |
| The Docker daemon's `ExecStart` | From `docker.service` and its drop-ins. That one line and no other part of the unit, with log-option values scrubbed |
| Three sandboxing directives | `NoNewPrivileges`, `ProtectSystem`, `ProtectHome` from three named units. Those three directives and no other part of the unit |
| Docker log-option key names | From `daemon.json` and from `--log-opt` on the command line. Names only, values never |
| Filesystem aggregates | Counts of setuid, world-writable and unowned inodes, with a small number of example paths |
| Hostname and OS release | Unless `--redact` |
| Evidence blobs | The raw bytes of the configuration files a finding cites |

### What is never collected

**No password hashes.** `/etc/shadow` is parsed for the properties of each entry
and is never stored as an evidence blob. That is a design decision with a test
attached, `TestGoldenBundlesCarryNoCredentialMaterial`.

**No private keys**, no `authorized_keys` contents, no certificates.

**No file contents from user home directories.** The filesystem walk records
metadata, meaning mode, owner and size. It never reads a file it walks.

**No process list and no environment variables.** Two kinds of unit content are
collected and nothing else. The `ExecStart=` of `docker.service`, because the
flags on it decide whether the Docker API is exposed to the network. And three
sandboxing directives from three named units, because nothing else records
whether a daemon runs with `no_new_privs`.

`Environment=` and `EnvironmentFile=` are never parsed. That is the specific
concern rather than a general one: a Docker host's
`docker.service.d/override.conf` is the usual home of
`Environment="HTTPS_PROXY=https://user:password@proxy"`.

The mechanism is worth stating because it is structural rather than a promise to
remember. `internal/collect/unit` is told which directive names to keep and
discards everything else while parsing, so an unwanted directive is never held
in memory, let alone recorded. There is no filtering step a future collector
could forget. Unit fragments are also read through the seam's opaque path, so
their bytes never reach the evidence store. What travels is a digest an auditor
reproduces on the host.

No unit is read in bulk. Both collectors work from a fixed list of unit names
written in the source: one unit for Docker, three for the sandboxing audit.
Nothing enumerates the units on this host and opens what it finds, so the bytes
read are bounded by a constant rather than by what somebody installed.

**No `log-opts` values.** The `log-opts` object in `/etc/docker/daemon.json` is
read for its key names and never for what they are set to, because that is where
a logging driver's credentials live. `splunk-token` is an authentication token.
`awslogs-credentials-endpoint` is the path to one. A `gelf-` or `loki-` address
is an internal hostname. The names answer the only question asked of them, which
is whether `json-file` is unbounded because `max-size` is unset. That is what
makes the trade affordable rather than merely cautious.

**No network addresses.** Firewall configuration is read. Interfaces are named,
addresses are not.

### The one command line, and what is taken out of it

The `ExecStart=` of `docker.service` is stored argument by argument, because the
flags on it decide whether the Docker API is exposed to the network and whether
it requires a client certificate. That is a deliberate exception and the
paragraph above explains why it earns its place.

The values of `--log-opt` are scrubbed out before it is recorded. `dockerd`
accepts log options on its command line as well as in `daemon.json`, and that is
where a logging driver's credentials get configured. A drop-in reading

```ini
ExecStart=/usr/bin/dockerd -H fd:// --log-driver=splunk --log-opt splunk-token=abc123
```

reaches a bundle as

```
/usr/bin/dockerd -H fd:// --log-driver=splunk --log-opt splunk-token=[REDACTED]
```

Three things about how that is done are worth stating, because each could
reasonably have gone the other way.

The key survives and the value never does, including values that are not
secrets. `max-size=10m` is scrubbed exactly as `splunk-token` is. A scrubber
holding a list of sensitive names is a scrubber that misses the next logging
driver's credential option, so the rule is structural: a log option's key is
policy and its value is not. Nothing in the tool needs the values, since
`CONTAINERS-0008` asks only whether `max-size` is present. If a later check ever
does need one, the answer is a typed field, not a wider raw command line.

It is a visible marker, not an omission. `[REDACTED]` lets a reader tell "this
option was set and its value is not in this artifact" from "this option was not
set". Those are different facts about the host and only one of them is a
finding.

Everything else is exactly what `systemd` would have passed. Only the flags
above are treated this way, and the fragment digests are unaffected, because
they are computed over the file's real bytes at the seam. Verifying a finding
against the live host still works.

An unexpanded `$VARIABLE` is left alone. It is a name, not a value. What it
expands to lives in an `EnvironmentFile` this tool deliberately does not read,
so the token discloses nothing, and `CONTAINERS-0006` needs to still see it in
order to say it could not read the whole command line.

This is asserted end to end rather than promised. A test collects a bundle from
a fixture whose drop-in configures the splunk driver with its token, then
searches every member of the compressed archive as bytes
(`TestABundleFromASecretBearingHostCarriesNoSecret`).

## Redaction

```bash
plumbline collect --redact -o report.plb
```

Drops the hostname at collection time, so it is never written to disk rather
than stripped afterwards. `manifest.redacted` records that it was used, so a
reader can tell a redacted bundle from a host that had no name.

`--redact` does not remove account names or paths. If those are sensitive for
your estate, a bundle is not the right thing to share. Send the specific finding
from `--json` instead.

## Sharing a bundle for a bug report

Bundles are the single most useful thing you can attach to an issue. Every
finding is reproducible from one, offline, against any catalog version. Read the
table above first.

```bash
plumbline collect --redact -o report.plb
zstd -dc report.plb | tar -xO facts/users.passwd.json | jq .   # inspect before sending
```

A bundle is a tar of JSON under zstd. You can read every byte of what you are
about to send, and you should.

## File permissions

Bundles and reports are written owner-only, `0600`, by `system.CreateBundle`.
A unit test asserts it and CI re-asserts it on four distributions. Reports
written with `--output` are never coloured, so an artifact read months later in
something that is not a terminal is not full of escape sequences.

## Retention

Plumbline stores nothing itself. No cache, no state directory, no dotfile. It
writes only where you point it with `-o` or `--save-bundle`.

Bundles do not expire and stay readable forever by design, which means a bundle
you keep is host inventory you keep. Apply the retention policy you would apply
to a configuration backup, because that is effectively what it is.

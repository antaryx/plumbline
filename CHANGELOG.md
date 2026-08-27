# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog];
versioning follows `docs/VERSIONING.md`, which governs four separate version
numbers (tool, catalog, schema, vulnerability data).

Every release that alters a check's verdict logic MUST carry a
`### Check corrections` section naming the check, the old behaviour, the new
behaviour, and who is affected. A user's posture score changing without an
explanation in this file is a defect.

## [Unreleased]

### Fixed
- **The sysctl collector follows a symlinked configuration file.**
  `/etc/sysctl.d/99-sysctl.conf` is a link to `/etc/sysctl.conf` on Debian-family
  hosts, which is how the traditional file comes to be applied last among the
  drop-ins. The seam opens with `O_NOFOLLOW`, so the link was recorded as an
  unreadable file and `KERNEL-0007` and `KERNEL-0017` both declined to answer.

  The chain is followed one hop at a time and **back through the seam**, which
  is what keeps `--root` governing where the read lands; resolving with the
  host's own filesystem calls would dereference against the real machine.
  Bounded at four hops, a dangling link is skipped rather than recorded as
  unreadable — `sysctl --system` skips it too, and a link to nothing configures
  nothing — and a target that is not a regular file is refused.

  **The target is read through `ReadOpaque` where a direct read uses
  `ReadFile`**, and that asymmetry is the safety property. A configuration file
  is read for evidence, so its bytes reach the store; a *link* is a path chosen
  by whoever could write the directory, so following one with `ReadFile` would
  let a symlink planted in a `sysctl.d` directory copy any file on the host into
  an artifact designed to travel. Reading opaquely keeps that impossible while
  still producing the digest and the parsed settings, and the digest is
  identical either way, so a finding citing the link still resolves against the
  blob the direct read stored.

  Settings are attributed to the **link**, not the target, because the link's
  name is what decides where it sorts among the drop-ins. `Sysctl.Resolved`
  carries the other half so a finding does not send an operator to open a
  symlink.

### Changed
- **`ubuntu-2404-hardened` was re-recorded and now carries no `UNKNOWN` at
  all** — the first bundle in the corpus to reach 100% coverage, and the first
  time its standing description (the bundle on which every check evaluates) has
  been literally true. All eight resolved to real verdicts: three CONTAINERS
  checks to `NOT_APPLICABLE` because the recipe installs no Docker,
  `KERNEL-0007` and `SERVICES-0006` to `PASS`, and `KERNEL-0017`,
  `SERVICES-0007` and `SERVICES-0008` to `FAIL`.

  **Its posture fell from 96.77 to 92.46, and that is the corpus working.**
  Three real findings appeared on a bundle that had been hiding them behind
  `UNKNOWN`: systemd 259 ships journald with `NoNewPrivileges` and neither
  `ProtectSystem` nor `ProtectHome`, and Ubuntu's kernel defaults
  `unprivileged_bpf_disabled` to 2 with no file setting it. All three reproduce
  on any Ubuntu 24.04 host.

  The other five bundles were deliberately not re-recorded. The symlink was only
  ever present on this one — the stock Ubuntu and Debian images do not ship
  `/etc/sysctl.d/99-sysctl.conf` — so re-recording them would sweep whatever
  moved upstream into a diff about a symlink.

### Added
- **`KERNEL-0017` (BPF hardening written to the sysctl configuration).**
  Catalog 25, 95 checks. `HIGH`, above `KERNEL-0006`'s `MEDIUM` on purpose: that
  one describes a boundary that is up right now, this one describes one that is
  scheduled to fall down on a host whose operator believes it is hardened and
  whose other checks agree.

  **The gap it closes is a real one and neither existing check sees it.**
  `KERNEL-0006` reads the running value and passes. `KERNEL-0007` compares
  running against configured and *skips a parameter no file mentions*, because
  there is nothing to compare it to. So a host hardened with `sysctl -w` and
  nothing written to disk passes both and reverts at the next reboot. It is in
  the golden corpus, not just in a fixture: `ubuntu-2404-stock` runs with
  `unprivileged_bpf_disabled = 2` and no file setting it.

  Two parameters are required and they do different jobs — who may call
  `bpf()`, and what the JIT emits for the programs that get loaded. **`2` is
  accepted for `kernel.unprivileged_bpf_disabled`** and noted as the weaker of
  the two: it refuses unprivileged `bpf()` exactly as `1` does and merely
  leaves the value raisable, so failing it would be a finding against a host
  that is not exposed. **Only `2` is accepted for `net.core.bpf_jit_harden`**,
  because `1` blinds constants for unprivileged programs only — the case that
  stops mattering once an attacker has privilege.

  A parameter set to different values in two files is `UNKNOWN`, not a verdict:
  procps and systemd-sysctl walk the drop-in directories in different orders,
  so which wins after a reboot depends on which applied them, and guessing
  would be a confident claim about the one thing the check reports on.

- **`net.core.bpf_jit_harden` is now probed.** It was the only half of the BPF
  pair the collector did not read.

### Changed
- **Golden posture scores moved for the first time in this cycle**, on four of
  the six bundles, because `KERNEL-0017` finds something real on them. It is
  also the first check in five work packages to *raise* coverage rather than
  lower it: it reads `kernel.sysctl`, a fact the corpus already carries, rather
  than one recorded after it.

### Security
- **`ParseProtectSystem` accepted enum names in the wrong case**, which could
  report `PASS` for a service systemd left unprotected. `ProtectSystem=Full` is
  rejected by systemd — `protect_system_from_string` is a string table looked
  up with `streq` — so it is logged, ignored, and the default `no` stays in
  force with `/usr` writable. This build lowercased the value and read it as
  `full`. Enum names are now compared exactly, and a case variant is reported
  as a value systemd cannot parse, which is both correct and the safe direction
  if this reading of systemd is ever wrong: the operator is told to look at the
  line rather than being quietly passed. Introduced in catalog 23; affects
  `SERVICES-0007` only.

### Added
- **`SERVICES-0008` (ProtectHome on audited system services).** Catalog 24, 94
  checks. `HIGH`, the same as `SERVICES-0007` deliberately: that one describes
  a daemon that can persist on this host, this one a daemon that can walk to
  the next. Rating them differently would be a claim about which is worse,
  which depends on the estate.

  A root daemon that can read `/root` and `/home` reaches
  `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.kube/config` and whatever
  token a tool cached in `~/.config`. None of those is protected by file
  permissions against a process already running as root, and all are reusable
  elsewhere — which is what turns one compromised daemon into lateral movement
  across an estate.

  **`read-only` passes and buys less than the other two, and the verdict says
  so.** It stops a daemon planting an `authorized_keys` file; it does not stop
  it reading a private key, which is most of what the check is about. A pass
  naming a read-only unit says that in as many words rather than reporting
  "home directories are protected".

  `cron.service` is exempt — user cron jobs routinely execute scripts kept in a
  home directory. `dbus.service` and `systemd-journald.service` are audited.

- **`fact.ParseProtectHome`, `HomeProtection()`, `HomeProtected()` and
  `HomeReadable()`.** The grammar is the same shape as `ProtectSystem`'s and
  has the same asymmetry: `parse_boolean` first and case-insensitively, then a
  case-sensitive string table. **`read-only` is hyphenated and nothing else is
  accepted** — `readonly`, `read_only` and `Read-Only` are all values systemd
  rejects, and all three are the spelling an operator uses while believing the
  home directories are protected.

### Changed
- **The three sandboxing checks share `partitionUnits`.** Pass-before-exemption,
  unreadable-before-either, masked-is-neither: each was a property asserted
  separately in three copies of the same loop, and each was a bug worth having
  a test for. A fourth check gets all of them by construction. `SERVICES-0006`
  and `-0007` were rewired onto it with no verdict changing.

  `TestEachSandboxCheckCarriesItsOwnExemptions` now asserts the full matrix
  rather than a contrast. `dbus.service` is the unit that proves the lists must
  be per-check: exempt from `-0006` because its launch helper is setuid,
  audited by `-0007` and `-0008` because that fact says nothing about where the
  daemon may write or read. A shared list would have excused it from all three
  and cost two checks half their subject.

### Added
- **`SERVICES-0007` (ProtectSystem on audited system services).** Catalog 23,
  93 checks. `HIGH` — the highest in the module alongside `SERVICES-0005`, and
  for the same reason from the other direction: a daemon that can write `/usr`
  turns a service compromise into a host compromise that survives the service
  being restarted, with no exploitation step in between.

  Anything from `yes` upward passes. The check does not insist on `strict`,
  because the right level depends on what the daemon legitimately writes and a
  host that chose `yes` deliberately is not the problem — the problem is the
  service that never considered the question.

  **The value is a superset of the booleans**, in systemd's own resolution
  order: it tries `parse_boolean` first, so `true`, `1` and `on` are all `yes`
  and `off` is `no`. A build accepting only the four enum names would raise a
  `HIGH` finding against a service that is in fact protected.
  `fact.ParseSystemdBool` moved out of the collector into `internal/fact` so
  both sides can use one grammar — a check may not import a collector package.

  **It is a better check than `SERVICES-0006` and the exemption list is why.**
  Only `cron.service` is exempt, because it runs arbitrary operator-supplied
  jobs inside its own mount namespace, so a read-only `/usr` or `/etc` becomes
  a restriction on code the packager never saw. `dbus.service` is *not* exempt
  here, unlike from `-0006`: its setuid launch helper is what makes
  `NoNewPrivileges` unsafe there and has nothing to do with where the daemon
  may write, and on a systemd host dbus-activated services are started by
  systemd as their own units rather than as children of dbus, so they do not
  inherit its namespace.

  That leaves two auditable units where `-0006` has one, and it is the reason
  exemptions are per-check rather than a shared "awkward services" list. A
  shared list would have exempted dbus from both and cost this check half of
  what it can verify. `TestTheTwoSandboxChecksCarryTheirOwnExemptions` asserts
  the divergence on one fixture.

- **`fact.ParseProtectSystem` and `ServiceSandbox.SystemProtection()`**, which
  resolve the directive to a level. The collector records the value as written
  and validates it — an unparseable one is logged and ignored by systemd, so it
  goes to `Malformed` and the default stays in force — and the reading lives on
  the fact so a bundle recorded today is re-read by a later build's
  understanding of the grammar.

- **Exemptions for SERVICES checks.** A check can now declare units it
  deliberately does not hold to its standard, with the reason. `SERVICES-0006`
  exempts `cron.service` and `dbus.service` from `NoNewPrivileges`, because
  setting it there breaks the service rather than hardening it: cron's jobs
  inherit `no_new_privs` and stop being able to call `sudo`, and dbus activates
  system services through a setuid `dbus-daemon-launch-helper`.

  **An exemption is not a suppression.** A suppression is an operator accepting
  a finding on their host and lives in a suppressions file; an exemption is the
  catalog saying the remediation would break the service — a property of the
  software, true everywhere it runs. Only one of those should be invisible to
  the next operator, and it is not this one: exempt units are named in every
  verdict with their reason, whether the check passes or fails, and the detail
  says in as many words that this is not a suppressed finding.

  Three properties are enforced rather than left to an author's care:

  - **An exemption never hides a unit that could not be read.** It is a claim
    about a configuration that was *seen*; excusing an unreadable file would
    turn "I could not look" into "it is fine". `services-sandbox-denied` is
    `UNKNOWN` even though the unit it cannot read is exempt.
  - **An exemption never downgrades a unit that complies anyway.** A host whose
    `dbus.service` does set the bit is credited with it. The exemption is a
    floor, not a ceiling.
  - **Exemptions cannot make a check vacuous.** If no unit on a host was
    actually held to the standard, the result is `NOT_APPLICABLE` and says so
    — "the check reporting that it had nothing to examine, not that the host
    satisfied it". With two of three units exempt, one more reasonable-looking
    entry would otherwise turn this check into a green tick that means nothing,
    silently. That is the failure CONTRIBUTING.md rule 3 exists for, and an
    exemption list is the most plausible way to reach it by accident.

### Changed
- **`SERVICES-0006` passes on a stock host** where it used to fail, because the
  two units it used to fail are now exempt. `systemd-journald.service` is the
  only audited unit that can still fail, which is a real reduction in what the
  check claims and is stated in its description rather than left to be
  inferred from the exemption list.

### Added
- **`SERVICES-0006` (NoNewPrivileges on audited system services).** Catalog 22,
  92 checks. `MEDIUM`.

  `NoNewPrivileges=yes` sets the kernel's `no_new_privs` bit, which cannot be
  cleared once set and makes the kernel refuse to grant privileges the process
  did not already hold — a setuid binary runs as the calling user and file
  capabilities are ignored. It turns "find any local escalation" into
  "escalate with what you already have".

  It reads a fixed list — `cron.service`, `systemd-journald.service`,
  `dbus.service` — rather than every unit on the host, because reading every
  unit means reading every unit *body*, which is what the SERVICES module
  exists in order not to do.

  A unit that is not installed is skipped rather than failed; if none is
  installed the check is `NOT_APPLICABLE`. A masked unit is skipped too: systemd
  refuses to start one, so the unhardened vendor file underneath describes no
  process. An unreadable unit or drop-in is `UNKNOWN` when nothing else failed,
  and does not suppress a failure that was found — ADR-0014.

  The three ways of not having the bit are told apart in the finding, because
  they are three different conversations: never written, written as `no` (a
  decision somebody made), and written as a value systemd rejects (which it
  logs and ignores, so the file looks configured and the host is not).

- **`internal/collect/unit`, one implementation of systemd's unit assembly.**
  Search-root precedence, drop-in gathering, basename shadowing, lexical
  ordering across directories, masked and symlinked units, `ReadOpaque`
  fragment reads. Extracted from the Docker service collector, which now calls
  it; the new SERVICES sandboxing collector calls it too.

  `Request.Directives` is the privacy boundary rather than a convenience
  filter: a directive whose name was not asked for is discarded during the
  parse and never held, so `Environment=` cannot reach a fact by omission. That
  is what makes it safe for two collectors to read unit bodies at all.

  `Unit.List` and `Unit.Last` are systemd's two folds — list-valued settings
  accumulate and are cleared by a bare assignment, scalars are overwritten and
  a bare assignment restores the default.

- **`services.hardening` fact**, recording `NoNewPrivileges`, `ProtectSystem`
  and `ProtectHome` for the audited units, plus which of them systemd would
  refuse to parse. Separate from `services.units` so the older fact keeps its
  promise to read no unit bodies at all.

### Changed
- **`fact.DockerUnitState` is now `fact.UnitState`**, with `UnitPresent`,
  `UnitAbsent`, `UnitMasked`, `UnitDenied`, `UnitNotRegular`, `UnitTruncated`
  and `UnitError`. The type was generic in everything but its name once a
  second collector needed it. **The wire values are unchanged**, so a `.plb`
  recorded before the rename decodes into it unaltered. `UnitFragment`,
  `UnitFragmentKind` and the fragment kinds moved to `internal/fact/unit.go`
  alongside it.

- **The Docker service collector is 724 lines shorter by half** and keeps
  everything about dockerd: the `ExecStart` fold, the argument split, and the
  `--log-opt` scrubber, which runs at the single point where a command line
  becomes fact data. It was deliberately not moved into `collect/unit` — it is
  a statement about dockerd's flag grammar, not about unit files, and a generic
  redaction hook would have been a place for a later caller to forget to pass
  one.

- **The SERVICES collector package doc no longer says unit bodies are never
  read.** It states the four bounds that make the exception safe instead — a
  named list rather than a walk, a directive allowlist enforced during the
  parse, `ReadOpaque`, and values recorded only where a check reads them — and
  says plainly that none of them holds for a collector that reads units in
  bulk.

### Fixed
- **A refused stat during unit lookup is now recorded rather than skipped
  silently.** A unit file in a higher-precedence directory *replaces* the one
  below it, so a location that could not be examined may hold a file that
  changes everything; `findUnit` treated that as "not here" and recorded
  nothing, though its own comment promised otherwise. It now returns a fragment,
  which makes `Unit.Complete` false and stops a caller reporting an absence it
  did not establish. Affects `CONTAINERS-0006`, `-0007`, `-0008` and
  `SERVICES-0006`.

- **A continued directive joins with a single space.** The old code left two
  where the backslash had been, which was invisible while the only consumer
  split the value into arguments and would have carried the file's layout into
  a scalar directive's value.

### Security
- **`--log-opt` values are scrubbed out of the recorded `ExecStart`.**
  `dockerd` takes log options on its command line as well as in
  `daemon.json`, and `ExecStart` is the one command line a bundle keeps — so
  `--log-opt splunk-token=…` in a drop-in travelled, where the `daemon.json`
  spelling of the same option had its value dropped. A bundle now discloses the
  same amount whichever file an operator used.

  The key survives and the value never does, `max-size` included. A scrubber
  holding a list of sensitive names is a scrubber that misses the next logging
  driver's credential option, so the rule is structural: a log option's key is
  policy and its value is not. `[REDACTED]` is a visible marker rather than an
  omission, because "set, and not carried" and "not set" are different facts
  about the host.

  All four spellings are handled — `--log-opt v`, `--log-opt=v`, and the
  single-dash forms `pflag` does not actually accept, because being wrong in
  the permissive direction costs a redacted token nobody reads and being wrong
  in the other direction costs a secret. An unexpanded `$VARIABLE` is left
  alone: it is a name rather than a value, and `CONTAINERS-0006` needs to still
  see it to report that the command line was not read in full.

  Asserted end to end. `TestABundleFromASecretBearingHostCarriesNoSecret`
  collects a bundle from a fixture whose drop-in configures the splunk driver
  with its token and searches every member of the compressed archive as bytes.

  This is the first place in the tree that deliberately records something other
  than what the file says. Fragment digests are unaffected — they are computed
  over the real bytes at the seam — so verifying a finding against the live
  host still works.

### Fixed
- **`CONTAINERS-0008` no longer reports a `PASS` from a command line it could
  not read in full.** A driver named in a drop-in is not the last word: `pflag`
  takes the last `--log-driver`, and systemd expands a `$VARIABLE` into however
  many words it holds, so an unread fragment or an unexpanded variable can
  carry a `--log-driver=none` after it. The verdict is now `UNKNOWN` there.

  A driver named in `daemon.json` is not exposed to this and still passes:
  `dockerd` refuses to start when an option is given as a flag and in the
  configuration file at once, so a unit nobody read cannot be contradicting it.
  The size bound gets the same treatment with one extra case — `log-driver` and
  `log-opt` are *different* options, so `dockerd` permits that split and a
  drop-in can bound a driver the file named.

### Added
- **`CONTAINERS-0008` (logging driver bounded and retrievable).** Catalog 21,
  91 checks. `LOW`: nothing here is a privilege boundary, and both failure
  modes — a full filesystem and a missing log — are recoverable in a way
  `CONTAINERS-0006`'s is not.

  Docker's default driver is `json-file` and `json-file` has no size limit
  unless one is configured. Every byte a container writes to stdout is
  appended to a file in `/var/lib/docker` that nothing rotates: not logrotate,
  which does not know about it, not journald, which does not own it, and not
  the daemon, which will not trim it. A full `/var/lib/docker` is not a
  logging incident but an outage — the daemon cannot write container state and
  on most hosts `/var` is the same filesystem the journal and the package
  manager use — and it is reachable by anything that can make a containerised
  service log.

  Four shapes pass: `local`, which rotates by default; `journald` and
  `syslog`, which hand the output to the daemon that already owns rotation
  here; a shipping driver (`fluentd`, `gelf`, `awslogs`, `splunk`, `gcplogs`),
  which keeps the logs beyond this host's own lifetime; and `json-file` with a
  `max-size` log option, which is Docker's own documented way to keep the
  default driver and bound it.

  `"none"` fails, and for the opposite reason: it bounds the logs perfectly by
  keeping none of them, so `docker logs` returns nothing and a compromised
  container that restarts takes its own evidence with it.

  A driver this build does not recognise is `UNKNOWN` rather than a failure.
  Docker supports logging plugins, and a plugin named here is almost certainly
  a log shipper somebody installed on purpose — reporting the operator's own
  answer to this check as the finding is worse than saying so.

- **`log-opts` key names in `containers.docker_daemon`.** Names only, never
  values, and rather more urgently than `Keys`: `log-opts` is where
  `splunk-token` and `awslogs-credentials-endpoint` live, and a bundle
  travels (ADR-0015). The names alone answer the only question a check asks —
  `json-file` is unbounded unless `max-size` is set — which is what makes the
  trade affordable rather than merely cautious. A log option written with the
  wrong value type does not make the document `malformed`, because the values
  are not read.

- **`DockerService.StringFlag` and `StringFlags`.** The value-taking long
  flags on `dockerd`'s command line, in both spellings `pflag` accepts, with
  every occurrence kept for the repeatable ones — `--log-opt` is given once
  per option, so taking the last would discard the one that decides the
  verdict.

### Changed
- **`CONTAINERS-0008` reads the systemd unit as well as `daemon.json`**, and
  declares `containers.docker_service` for it. `dockerd` takes `--log-driver`
  and `--log-opt` on its command line, and configuration management that owns
  the unit but not `daemon.json` puts them there. Reading only the file would
  report the compiled-in default on a host that configured the thing being
  asked for — a `FAIL` against somebody who did the work, which is the class of
  finding that teaches an operator to stop reading the report. It is the same
  trade `CONTAINERS-0007` made, at a lower severity and with the same answer.

  Where the verdict rests on an *absence* — no driver named, no bound set — an
  unread drop-in or an unexpanded `$DOCKER_OPTS` makes it `UNKNOWN` instead.
  That is ADR-0014 in the direction it actually points: an incomplete
  examination invalidates a negative result and never a positive one.

- **`unitCouldSetTLS` is now `unreadFragments`** and lives in
  `checks/containers/containers.go` rather than `sockets.go`. Three checks now
  need the list of unit fragments nobody opened, each for a different flag, and
  the shape of the mistake being avoided is the same for all of them.

- **`CONTAINERS-0007` (unauthenticated TCP socket in `daemon.json`).** Catalog
  20, 90 checks. `CRITICAL`, identical to `CONTAINERS-0006` deliberately: the
  two are one exposure written in two files, and rating them differently would
  tell an operator that where they typed it changes what it does.

  `{"hosts": ["tcp://0.0.0.0:2375"]}` is the same open door as `-H
  tcp://0.0.0.0:2375`, and an audit that read only the systemd unit was a
  scanner you could pass by moving a line between two files. That was the gap
  `CONTAINERS-0006` shipped with and named in its own detail string; this
  closes it.

  **`dockerd` refuses to start when an option is given as a flag and in the
  configuration file at once**, and `hosts` is the option it refuses over most
  often. So on any host whose daemon is actually running, at most one of the
  two files decides the sockets — which is what makes the pair exhaustive
  without double-counting, and what makes an absent `hosts` key a pass rather
  than a hole.

- **`checks/containers/sockets.go`, one reading of dockerd's socket grammar for
  both checks.** `classify`, `addrOf`, `loopbackOnly`, `specList`,
  `tlsVerified` and the loopback/`--tls`/`--tlsverify` rules were
  `CONTAINERS-0006`'s and are now shared. Two readings that agree today and
  drift later would not be a cosmetic inconsistency: the same configuration
  would be `CRITICAL` in one file and a pass in the other.
  `TestTheTwoSocketChecksReadASpecTheSameWay` asserts the property rather than
  the sharing that implements it.

  `tlsverify` is honoured from either file by both checks. The socket may be
  bound in the unit and the certificates configured in `daemon.json`, or the
  other way round — different options, so `dockerd` accepts the split — and a
  check reading only its own file would report a mutually authenticated
  endpoint as an open one.

### Changed
- **A `FAIL` from either socket check now names the fragment it could not
  read**, when one went unread. The binding is established and the mitigation
  is not: a `--tlsverify` could be sitting in a denied `override.conf`. The
  verdict stays `FAIL` — ADR-0014, a binding that was found is a finding
  whatever else went unread — but the sentence claiming "with no authentication
  on it" no longer stands unqualified when the scan could not see everywhere
  authentication might be configured.

- **`CONTAINERS-0007` is `UNKNOWN` on all six golden bundles**, for
  `CONTAINERS-0006`'s reason and not a second one: it declares
  `containers.docker_service`, which the bundles predate. That dependency is
  not incidental — its subject is `hosts` in `daemon.json`, which every bundle
  does carry, but whether a socket found there is protected turns on
  `tlsverify`, which may be set on the command line instead. Declaring only the
  fact it would like to read would have kept coverage up and produced a
  `CRITICAL` false positive on the first re-evaluated bundle from a host that
  had configured TLS properly. Coverage falls again on each bundle; no verdict
  moves and no posture score changes.

### Added
- **`CONTAINERS-0006` (unauthenticated TCP socket) and the `docker.service`
  collector it reads.** Catalog 19, 89 checks. The module's only `CRITICAL`,
  and the first check in the tree that reads a systemd unit body.

  The Docker API is root on the host and authenticates nobody over plain TCP:
  a reachable `tcp://…:2375` is `docker run -v /:/host --privileged` away from a
  root shell, with no exploit and no credential involved. Port 2375 is scanned
  continuously and an exposed daemon is mining cryptocurrency within hours.
  Severity drops to `HIGH`, not to a pass, when every binding is to loopback:
  that is unreachable from the network and reachable by every local user, by
  every `--network=host` container, and by the second half of an SSRF.

  `--tls` does not clear the check and `--tlsverify` does. The first encrypts
  and asks the client for nothing, so anyone who can reach the port still gets
  a root shell over a well-encrypted channel; only the second requires a
  certificate the daemon's CA signed. `tlsverify` is honoured from
  `daemon.json` as well as from the unit — they are different options, so
  `dockerd` accepts the split, and reading only the unit would report a
  mutually authenticated endpoint as an open one.

- **`containers.docker_service`, the other half of the daemon's configuration.**
  `fact.DockerDaemon` has said since it landed that an option passed on
  `dockerd`'s command line is invisible to it. This is that command line:
  `docker.service` plus its drop-ins, folded in systemd's own order, with the
  `ExecStart` arguments split the way systemd splits them.

  **Reading the drop-ins is the collector, not a refinement of it.** Every
  distribution ships the same vendor unit binding `-H fd://`, so the unit file
  on an exposed host is byte-identical to the unit file on a safe one — the
  exposure lives in `/etc/systemd/system/docker.service.d/override.conf`, which
  is what `systemctl edit docker` writes and what every "reach Docker from
  another machine" guide asks for. A collector that read only the unit file
  would report the stock answer on the hosts this check exists for.

  Two systemd precedence rules are implemented rather than approximated,
  because both change verdicts. A drop-in whose *filename* appears in a
  higher-precedence directory is ignored entirely, which is how an
  administrator neutralises a vendor drop-in; applying it anyway would report a
  critical exposure on a host somebody had deliberately fixed. And the
  surviving set is applied in lexical order *by filename across all
  directories*, not in directory order, so `10-foo.conf` from `/usr/lib`
  applies before `20-bar.conf` from `/etc` — and the last `ExecStart` to be
  applied is the one that runs.

- **Unit bodies are read through `ReadOpaque`, so they never enter a bundle.**
  Only the `ExecStart` arguments and a digest travel. This is the one place the
  new collector departs from its sibling, which reads `daemon.json` through the
  ordinary `ReadFile` and stores the bytes: a Docker host's `override.conf` is
  where `Environment="HTTPS_PROXY=https://user:password@proxy"` lives, and that
  is the ADR-0015 concern rather than a theoretical one. `Environment=` and
  `EnvironmentFile=` are not parsed at all, and a `$DOCKER_OPTS` left in the
  command line is reported as an ambiguity rather than resolved by reading a
  file full of secrets. `TestUnitBytesDoNotEnterTheBundle` asserts the method.

- **`TLS` and `TLSVerify` on `fact.DockerDaemon`.** Additive optional fields, so
  `containers.docker_daemon` stays at version 1 per §2.2 of the data model.
  They exist for where they are *not*: the socket is bound in the unit and the
  certificates are often configured in `daemon.json`, and without them a host
  that did the work would be reported as an open one.

### Changed
- **`CONTAINERS-0006` is `UNKNOWN` on all six golden bundles**, and the pins
  record it. Every one was recorded before `containers.docker_service` existed,
  so the fact the check requires is not in them and the runner resolves it to
  `UNKNOWN(fact_not_collected)` — DATA-MODEL §6.1 working as promised. Coverage
  falls on each bundle; no verdict moves, and every posture score is unchanged.
  Clearing it means a recording recipe that installs Docker, which the roadmap
  already names as its own work package.

### Added
- **`MEMORY` module completed.** `MEMORY-0002` (full RELRO), `MEMORY-0003`
  (stack protection) and `MEMORY-0004` (`_FORTIFY_SOURCE`) join `MEMORY-0001`.
  Catalog 15, 83 checks. None is in the `cis-l1` profile: the CIS Level 1 server
  baseline does not cover per-binary build flags.

  All four share one evaluator, because the combining rules are where a check of
  this shape goes wrong and there are three of them: FAIL outranks UNKNOWN, a
  property that does not apply is not one that passes, and a file that does not
  say is not a file that says no.

- **Symbol-table and dynamic-section reading in the ELF collector.** `BindNow`,
  `HasCanary`, `HasFortify`, plus the discriminators that keep them honest:
  `Dynamic`, `Symbols`, `SymbolCount` and `FortifyCandidates`. Additive fields,
  so `memory.elf` stays at version 1 per §2.2 of the data model.

  Eager binding is read from all three encodings. `DT_BIND_NOW` is the tag the
  specification names and is now effectively extinct: on a sample of stock
  Debian binaries not one carried it and every one carried `DF_1_NOW`. Reading
  only the documented tag would have reported every correctly hardened binary
  on a current distribution as lazily bound.

  Symbols are read from `.dynsym` and `.symtab` together. A stripped image —
  every binary a distribution installs — keeps the first and discards the
  second; an unstripped static binary has the reverse.

- **`fact.ELFSymbols`, a third state for symbol evidence.** An absent symbol and
  an absent symbol *table* are different observations, and a boolean merged
  them. A fully stripped binary has no `__stack_chk_fail` for the same reason it
  has no symbol of any kind, so `MEMORY-0003` and `MEMORY-0004` resolve to
  `UNKNOWN` there rather than condemning a hardened binary for having nothing to
  look at.

### Added
- **`CONTAINERS-0004` (live restore) and `CONTAINERS-0005` (experimental
  features)**, completing the Docker daemon configuration checks. Catalog 18,
  88 checks. Neither is in `cis-l1`.

  `CONTAINERS-0004` is `MEDIUM` and is an availability control in a security
  catalogue, which the description justifies rather than assumes. Without
  `live-restore`, restarting `dockerd` stops every container on the host — so
  the daemon does not get restarted, and the Docker security update waits for a
  maintenance window that keeps slipping. The exposure is not the downtime; it
  is the months of running a known-vulnerable daemon because the alternative
  was an outage nobody would authorise. The remediation says up front that
  enabling it costs one outage and that it is unsupported on a Swarm node.

  `CONTAINERS-0005` is `LOW`, the lowest in the module: nothing here is a
  privilege boundary, and a failure means somebody deliberately enabled
  experimental mode and may have had a reason. It is a question rather than an
  accusation.

  **`CONTAINERS-0005` is the first check in this module where an unwritten key
  is a PASS.** `-0002`, `-0003` and `-0004` all insist their option was
  requested, because `dockerd` leaves those off and an absent key means the
  permissive value is in force. `experimental` also defaults to off — and there
  that is the value the check wants, so demanding `"experimental": false` be
  written down would fail every correctly configured host for not having said
  something it did not need to say. Both rules are "`nil` means the daemon's
  default"; the default points in opposite directions.
  `TestSilenceIsAPassOnlyWhereTheDefaultIsSafe` asserts the divergence over
  fixtures that are silent on both options in exactly the same way, so it is
  attributable to the checks and not the file.

  An unreadable `daemon.json` is still `UNKNOWN` for `-0005`, even though PASS
  is its answer for silence. The file may well enable experimental mode, and
  falling back to the check's own default would be reporting a verdict drawn
  from a document nobody opened.

  Two fixtures were added and one was corrected. `containers-docker-icc-only`
  had claimed to isolate `CONTAINERS-0003`; the arrival of `-0004` would have
  made it fail two checks and isolate nothing, so it now sets `live-restore`
  explicitly for that reason alone.

- **`CONTAINERS-0003`, inter-container communication.** Reports a daemon that
  leaves `icc` at its permissive default, so every container on the default
  bridge can reach every port of every other one. Catalog 17, 86 checks.

  **Rated `LOW`, where `CONTAINERS-0001` and `-0002` are `MEDIUM`**, and the
  reason is reach rather than kind: those two apply to every container the
  daemon starts, while this governs the default bridge alone. Containers on a
  user-defined network are unaffected — and Docker Compose creates one per
  project — so on a Compose-only host the setting changes very little. It still
  matters for plain `docker run`, and it costs nothing to set. The limitation
  is stated up front in the check's description rather than left for an
  operator to discover.

  Adding it needed no re-recording: the corpus already carries
  `containers.docker_daemon`, so a new check over an existing fact only moves
  the expectations. That is the payoff from re-recording at catalog 16.

- **`CONTAINERS` module, first two checks.** `CONTAINERS-0001` (user-namespace
  remapping) and `CONTAINERS-0002` (`no-new-privileges`), with the Docker
  daemon collector now wired into `internal/cli/catalog.go`. Neither is in
  `cis-l1`, which selects by module and does not name this one.

  **A host with Docker and no `daemon.json` FAILs both, and that is the point.**
  Such a host runs on compiled-in defaults — `userns-remap` off,
  `no_new_privileges` off — which is a real configuration and the most common
  Docker installation there is. Excusing it as `NOT_APPLICABLE` would leave the
  module silent on exactly the hosts it exists for. The `NOT_APPLICABLE` gate is
  `Installed` (is there a `dockerd` binary), never the presence of the file.

  Every verdict drawn from the file says so: `dockerd` takes the same options as
  command-line flags and the stock unit passes some, so a finding that claimed
  to describe the running daemon would be claiming more than it checked.

- **`CONTAINERS` collector for the Docker daemon.** Reads
  `/etc/docker/daemon.json` into `containers.docker_daemon`, modelling
  `userns-remap`, `icc`, `log-driver`, `experimental`, `live-restore`,
  `no-new-privileges` and `hosts`.

  It is the first collector in the tree to parse JSON, and the malformed case
  is more consequential here than in any text config: a line-oriented file has
  partial meaning, and a JSON document has none. One stray comma and `dockerd`
  refuses to start, so a rejected file is recorded as `malformed` and yields no
  values at all rather than reading as "no options set".

  Two distinctions the fact is shaped around: an absent `daemon.json` is not an
  absent Docker (a daemon on its defaults has `icc` on and no user-namespace
  remapping, which is a configuration worth judging), and an absent key is not
  a false key (`icc` defaults to *true*, so the modelled booleans are `*bool`
  and `fact.OptBool` reports whether the document set them).

  `Keys` records the top-level key names only, never values: `daemon.json`
  holds registry mirrors, proxy URLs and storage paths, and a bundle travels.

### Known false positives
- **`MEMORY-0003` on small C utilities.** `-fstack-protector-strong` instruments
  only functions with local arrays or address-taken locals, so a program with
  none carries no `__stack_chk_fail` while being compiled correctly.
  `/usr/bin/newgrp` on stock Debian is exactly this.
- **`MEMORY-0003` and `MEMORY-0004` on binaries from memory-safe languages.**
  Rust and Go use neither glibc's stack protector nor its fortified entry
  points. `sudo-rs`, shipped as `/usr/bin/sudo` on several distributions,
  reports as though it had no hardening at all.

  Both are stated on the checks themselves and in `docs/FALSE-POSITIVES.md`.
  Neither is fixable from a symbol table, which is why they are documented
  rather than worked around.

- **`MEMORY` module, first check.** `MEMORY-0001` reports privileged binaries
  linked at a fixed address (`ET_EXEC`) rather than as position-independent
  executables, which is what lets ASLR randomise their code. Catalog 14, 80
  checks. Not in the `cis-l1` profile: the CIS Level 1 server baseline does not
  cover per-binary build flags, and adding it there would change what that
  profile claims to be.

- **`memory.elf` fact and the collector that produces it.** Reads PIE, NX and
  partial RELRO out of the ELF program headers with `debug/elf`, over a fixed
  list of setuid-root utilities and privileged daemons. Nothing is executed.
  Symbolic links are resolved through the seam, because `/usr/bin/sudo` is an
  alternatives link on every Debian-family host and stopping at it would examine
  nothing on the binary most worth examining.

  `NX` is three states rather than a boolean. A binary with no `PT_GNU_STACK`
  header leaves the decision to the kernel, by a rule that differs across
  architectures and kernel versions, so the file does not answer the question
  and the collector does not invent one.

- **`System.ReadOpaque`.** A read whose *bytes* are not evidence, with the same
  caps, the same refusal of non-regular files and the same digest as `ReadFile`.
  Bytes read this way never enter a bundle's evidence store; the digest, on the
  fact, is what survives. The exclusion is enforced at the seam rather than by
  the caller, alongside the existing credential-file exclusion, because a
  collector that has to remember to opt out is one that will eventually forget.

  On a live host the twelve binaries `MEMORY` examines are about 2.0 MB. They
  contribute 2.4 KB of fact and no evidence — an artifact 835 times smaller than
  storing them would have produced, with nothing lost that an auditor can use:
  `sha256sum` on the host reproduces the recorded digest, which a stored copy
  made by the same scan cannot.

### Changed
- **Golden bundles re-recorded at catalog 16.** All six now carry `memory.elf`
  and `containers.docker_daemon`. The CONTAINERS checks are `NOT_APPLICABLE` on
  every one — the recipes install no Docker — which holds coverage at the
  baseline below and marks an honest limit: a bundle recorded inside a container
  cannot carry a container runtime's configuration. Covering CONTAINERS against
  a real daemon needs a recipe that installs one.

- **Golden bundles re-recorded at catalog 15.** All six carry `memory.elf`,
  so the `MEMORY` module reaches real verdicts instead of
  `UNKNOWN(fact_not_collected)`. Coverage returns to its pre-MEMORY baseline —
  100 on ubuntu-stock, debian and alpine; the residual `UNKNOWN`s on fedora,
  rocky and ubuntu-hardened are the pre-existing AUTH and KERNEL ones.

  Two new `FAIL`s, both documented limits rather than defects in the hosts:
  alpine's `MEMORY-0004` (`/usr/bin/crontab` and `/usr/bin/passwd` are one
  busybox binary under two names, and musl has no `_chk` entry points) and
  debian's `MEMORY-0003` (`/usr/bin/newgrp`, 52 symbols, nothing needing a
  canary). Both are pinned deliberately: a run where either became a `PASS`
  would mean the symbol reading had begun inventing evidence.

- **Third known false positive recorded.** `MEMORY-0004` on musl, alongside the
  small-C-utility and memory-safe-language cases.

### Check corrections

None. No existing check changed its verdict on any fixture or any golden bundle.

---

## [1.0.0] — 2026-08-21

**Trustworthy core.** 79 checks, nine modules, catalog 13. `findings/v1`, flag
names, exit codes and check IDs are contracts from here (`docs/VERSIONING.md`).

### Fixed
- **Escape sequences no longer print as literal text in a finding's `Subject`.**
  A coloured report showed `Subject : \x1b[2m/etc/crontab\x1b[0m`, with the
  escape rendered as four characters beside the path it was meant to colour.

  The cause was an ordering one, introduced in RC-4. `wrap()` sanitises every
  line it produces, `sanitize.Text` escapes C0 control characters, and `ESC` is
  one — so a value painted *before* reaching the wrapper arrives at the terminal
  as text. Both orders look equally reasonable at the call site and only one
  works, so the colour is now applied by `fieldWrappedIn` *after* wrapping, and
  `fieldWrapped` carries the rule in its doc comment.

  The guard is `TestNoEscapeSequenceIsPrintedAsText`, which asserts the symptom
  rather than the call site: nowhere in a coloured report may `\x1b` appear as
  text. That covers every field and every renderer, including ones not yet
  written. It was confirmed to fail against the defect before being kept.

- **Dashboard card headers now carry their result's colour.** `PASS`, `FAIL` and
  `UNKNOWN` were dim over a coloured number, which reads as two unrelated things
  stacked — the eye lands on the word, finds it grey, and concludes the card is
  inactive. Header and number are now one colour, so a card is a single object
  that means one thing.

  Reported as a padding bug from the RC-5 dependency purge. It was not one:
  `pad()` has always measured with `visibleWidth`, which skips SGR escapes, and
  a coloured render checked column by column comes out at exactly 78. The
  numbers were coloured throughout; the headers were the regression.

### Changed
- **Posture gauge bands are now 90 / 70**, from 85 / 60. A host at 85 has one in
  seven of its applicable checks failing, which is not a green situation.
  Coverage still caps whatever posture earns, and `gaugeTone` is now a separate
  function so the rule is tested as a rule rather than read back out of
  rendered bytes.

### Added
- **`docs/PERFORMANCE.md`**, from measured numbers on a stated reference host.
  Evaluating all 79 checks over a collected bundle costs **~10 ms**; a full
  filesystem sweep costs **31.9 s cold and 2.8 s warm** over the same 731,571
  inodes. That eleven-fold spread is the finding: **the tool is disk-bound by
  design and the engine is free.** `FILESYS-0010` cannot know an orphaned file
  is absent without visiting every inode, and a tool that checked only `/etc`
  would be fast and would miss it.

  There is deliberately no CI performance gate: a wall-clock assertion on a
  shared runner measures the runner's neighbours and gets disabled within a
  month.

### Known gaps
- **Two v1 release criteria are not met**, both documentation: 21 of the
  documents `DOCUMENT-MAP.md` gates on are outstanding, dominated by all seven
  of Tier 5, and `THREAT-MODEL.md` has not been re-reviewed against the
  implementation. They are recorded in `docs/ROADMAP.md` rather than
  reclassified as done because the tag was cut. `README.md` carries Tier 5's
  load in the meantime.

---

## [1.0.0-rc1] — 2026-08-21

**Release candidate.** v0.5.0's four items are complete (SARIF export,
`plumbline explain`, the profile architecture, the golden-bundle corpus) and the
work from here is polish, stability and documentation. No new checks, no new
output formats, no new schema fields.

### Removed
- **`lipgloss` and its thirteen transitive modules (RC-5).** The dashboard RC-4
  introduced is unchanged — byte-identical output — and now draws itself with
  `strings.Builder`, the package's existing colour helpers and hardcoded box
  characters. **Direct and indirect dependencies are back to four.**

  What the library contributed was a box border, a horizontal join and a
  hex-to-terminal downsample. What it cost was termenv, go-colorful,
  go-runewidth, uniseg, terminfo, x/ansi, x/cellbuf, colorprofile and more, in
  a binary that runs as root, two of them pinned to untagged commits. It also
  had to be actively restrained: its package-level styles inspect `os.Stdout`
  at first use, which violates the OS seam and makes output depend on what the
  terminal answered. The replacement cannot do that, because it is only
  strings.

  This package already had the hard part — `visibleWidth`, which measures a
  string containing SGR escapes, and which is the thing `text/tabwriter` cannot
  do.

### Added
- **Generated reference documentation (RC-5).** `tools/gendocs` writes
  `docs/MODULE-CATALOG.md` and `docs/CHECK-REFERENCE.md` from `cli.Catalog()` —
  the same assembly the binary evaluates with, so there is no second list of
  checks to drift. `make docs` regenerates them; `make invariants` fails if the
  committed files have drifted, so a check added without regenerating is a
  failed build rather than a discovery six months later.

- **`.goreleaser.yaml` (RC-5).** linux/amd64 and linux/arm64, `.deb` and `.rpm`
  via nfpms, an SPDX SBOM per artifact via syft, and keyless cosign signing of
  the checksum file — no private key to leak, and a certificate that records
  the workflow and commit that produced the artifact. Builds are `CGO_ENABLED=0`
  and `-trimpath`, with the build date taken from the commit rather than the
  clock so two builds of one tag are byte-identical. `make verify` runs as a
  before-hook: nothing ships from a tree that would not pass review.

### Changed
- **The scan summary is a dashboard (RC-4).** A posture gauge across the grid
  and PASS / FAIL / UNKNOWN / SKIPPED cards beneath it, drawn with
  `charmbracelet/lipgloss`, plus a 24-bit hex palette shared by the dashboard
  and the check lines. Titles are now bold and paths, IDs and labels dimmed, so
  the sentence an operator reads carries the weight rather than the identifier
  they copy.

  **The grid did not move.** Everything is still 78 columns, derived from
  `reportWidth` and never from `$COLUMNS`, so two scans of an unchanged host
  stay byte-identical. lipgloss is driven by a renderer built over `io.Discard`
  with its colour profile passed in explicitly, so it never probes a terminal,
  never touches `os.Stdout`, and emits bytes that are a pure function of the
  colour decision `useColor` already made. With colour off it is given the
  Ascii profile: the boxes still draw and nothing is painted.

  It shipped on `lipgloss`, which took the dependency count from 4 to 17. That
  was reversed in RC-5 before either reached a release; the entry above records
  what it cost and why.

### Fixed
- **`lipgloss.Width` is the inner width, not the total.** The first draft of
  the dashboard assumed otherwise and every box ran two columns past the grid —
  invisible on a wide terminal, a wrapped mess on the eighty-column one the
  grid exists for. `TestTheDashboardFitsTheGrid` now checks the arithmetic
  instead of the developer's eye.

### Fixed
- **`os_release` was empty on every modern distribution (WP-37).** Since
  systemd moved the file to `/usr/lib`, `/etc/os-release` is a symlink on
  Ubuntu, Debian, Fedora and RHEL alike. The seam opens privileged reads with
  `O_NOFOLLOW` and correctly refused it, `hostMeta` discarded the error, and
  every report from those four carried a blank field with nothing anywhere
  saying why. A field that is silently empty on the four most common Linux
  distributions is worse than one that is absent everywhere: it reads as a host
  that had nothing to say.

  **The seam is not weakened.** Resolution is explicit and bounded — Stat,
  Readlink, resolve, Stat again, capped at eight hops — with every hop going
  back through the seam, so the scan root, the escape refusal and the final
  refusal of anything that is not a regular file all still apply. A loop ends
  in an error rather than a hang; a link to a FIFO is refused rather than
  waited on. The same walk already existed inside the AUTH collector for Red
  Hat's PAM stacks and is now one shared function, `collect.ResolveLinks`,
  with the reasoning in one place. The golden corpus confirmed that extraction
  changed no verdict on any of the six recorded distributions.

  Lookup now follows the order `os-release(5)` specifies: `/etc/os-release`,
  then `/usr/lib/os-release`. `/etc/hostname` is deliberately *not* resolved
  the same way — no distribution ships it as a link, so one found there was put
  there by somebody, and following it would put the first line of whatever it
  points at into a field labelled "hostname".

### Added
- **Graceful `SIGINT` and `SIGTERM` handling (RC-2).** Exit code 130 was
  reserved in CLI-SPEC.md §6 from the beginning and produced by nothing. It is
  now produced by the thing it was reserved for.

  The handler is installed once, at the process entry point, and cancels the
  context every command already derives its `--timeout` from. Nothing else
  changed: the collector runner has always selected on that context at every
  point it could block, so the cancellation reaches the bottom of the pipeline
  through the mechanism that was already there rather than through a new one.
  A Ctrl-C part-way through a walk of `/` now unwinds in about 30ms.

  **An interrupted run produces no artifact.** `scan` writes no findings
  document and honours no `--save-bundle`; `collect` writes no bundle and names
  on stderr the file it did not write. This is deliberately stricter than the
  `--timeout` path, which keeps what it collected: a budget is a decision to
  accept whatever fits inside it, while an interrupt is a decision to stop. A
  bundle assembled from half a collection carries no mark saying so — the
  manifest lists the facts that made it and is silent about the ones that did
  not, so months later it re-evaluates to a posture score drawn from half a
  host.

  The cancellation carries its reason with it (`context.WithCancelCause`),
  which is what keeps 130 and 11 apart. Both arrive as a cancelled context, and
  inferring which from a flag set elsewhere is how a Ctrl-C ends up telling an
  operator to raise a budget they never reached. The reason survives the two
  levels of derivation a scan puts beneath the process context, and there is a
  test for each level.

  **The second signal kills.** The handler is uninstalled the moment the first
  one arrives, restoring the default disposition — the safety valve for a
  collector wedged in a syscall that never returns.

  The RC-1 progress indicator now erases on interrupt like any other ending,
  which closes the known limitation noted there.

- **A progress indicator for `scan` and `collect` (RC-1).** Collection is the
  slow half of a scan and it used to be the silent half — tens of seconds of a
  blank terminal on a real server, which looks exactly like a hang. A transient
  one-line indicator now runs while the collectors do, and erases itself before
  the report starts:

  ```
  ⠹ Collecting host evidence (12s)
  ```

  The elapsed time appears only after three seconds. "0s" answers nothing;
  "47s" distinguishes a walk over a large filesystem from a wedged one, which
  is the actual question behind "is this hung".

  **It writes to stderr and only to stderr**, so `--format json` cannot put a
  frame in a findings document — by construction rather than by care. It is
  keyed off stderr rather than stdout, which corrects what CLI-SPEC.md §7 used
  to say: `plumbline scan > report.txt` leaves stderr on the terminal, and that
  is exactly the run where an operator most wants to see something happening.

  **Four conditions must all hold or nothing is drawn**, because the two
  answers do not cost the same. A missing indicator is a cosmetic loss on one
  run; an indicator somewhere it cannot be erased is thousands of lines of
  half-drawn braille in a CI log somebody has to read months later. stderr must
  be a character device, `PLUMBLINE_NO_PROGRESS` must be unset, `TERM` must be
  set and not `dumb`, and no CI marker may be present — that last one because
  several CI systems allocate a pty, which defeats the terminal check while the
  output still goes to a log nobody is watching.

  `NO_COLOR` is deliberately not consulted: it governs colour, this emits none,
  and `PLUMBLINE_NO_PROGRESS` — reserved in CLI-SPEC.md §8 long before there
  was anything to suppress — is the control for this.

  Interrupting with Ctrl-C left the last frame on screen when this shipped;
  RC-2 fixed it.

- **Version is now `1.0.0-rc1`.** It appears in every findings document, every
  SARIF run and every bundle manifest, so a report says which candidate
  produced it.

- **Golden bundles (WP-34).** Six real collections from six real Linux
  userlands — Ubuntu 24.04 stock and hardened, Debian 13, Fedora 44, Rocky 9
  and Alpine 3.20 — recorded once into `testdata/bundles/` and re-evaluated by
  `TestGolden` on every `make verify`. `make golden-diff` reports which bundles
  no longer match; `make golden-update` rewrites the expectations.

  **This is a different question from the one the fixture corpus answers.**
  A fixture asks whether a check reaches the right verdict on a tree built to
  provoke it, and it is written by the same person, at the same time, with the
  same misconception. A golden bundle asks whether anything moved on a host
  nobody was thinking about when the change was written.

  `ubuntu-2404-hardened` is the one that carries the catalog: **every check
  reaches a real verdict on it** — no `NOT_APPLICABLE` at all — which no fixture
  and no stock base image manages alone. Its recipe was written from the
  remediation this tool prints, and doing that caught a wrong hardening setting
  on the first pass: `ClientAliveCountMax 0` looks stricter than 3 and disables
  idle disconnection entirely, which is exactly what SSHD-0007 said.

  Two gates, deliberately different in kind. Per-check expectations regenerate
  with `make golden-update` so a PR shows which checks moved on which
  distribution; posture and counts are typed by hand in
  `internal/cli/golden_test.go` and are not regenerated, because a gate that can
  be silenced by the same command that runs it will eventually be silenced by
  habit.

  Recording is a deliberate act — `testdata/bundles/record.sh`, needs docker,
  never run by CI — and two tests hold the corpus safe to publish:
  `TestGoldenBundlesCarryNothingOfTheRecordingHost` and
  `TestGoldenBundlesCarryNoCredentialMaterial`. Both read the raw archive rather
  than the decoded facts, because the failure being guarded against is a value
  arriving somewhere nobody thought to look.

  This closes the v1.0.0 release criterion of golden bundles for ≥6
  distribution/version combinations, three milestones early.

- **Profile architecture (WP-33).** `--profile` on `scan` and `eval` scopes an
  evaluation to a declared baseline, and `plumbline profiles` lists the
  built-ins with the count each selects. Two are embedded: `default` (the whole
  catalog) and `cis-l1`.

  **An excluded check is `SKIPPED`, never omitted and never
  `NOT_APPLICABLE`** — the first would make a narrow profile look like a clean
  host, the second would claim the subject is absent when the question was
  withdrawn. It carries a new optional `skipped_by` field naming the profile.

  **An excluded check leaves the posture denominator.** The profile declares
  what applies, so a thirty-check baseline reports coverage against thirty
  checks rather than reading as a poorly covered scan.

  `--profile` is the flag `scan` already had. It recorded a label in the bundle
  manifest and did nothing else; it now scopes the evaluation, and that
  manifest field becomes the record of the scope. Profiles select from the
  catalog and can never add to it: a finding that exists only under one profile
  is one nobody else can reproduce.

  **`cis-l1` is not a CIS benchmark and says so in its own description.** No
  check in this catalog carries a CIS mapping — the catalog maps to NIST
  800-53 r5 only — so the selection is this project's reading of Level 1
  themes. Passing it is evidence of sensible hardening, not of compliance.

- **`plumbline explain CHECK-ID` (WP-32).** Prints one catalog entry in full:
  what the check tests, which facts it reads, the remediation with every step
  and command, the control mappings and the references. This is where the
  remediation procedure lives — a scan report prints only a summary, because a
  block running to forty lines per finding is one an operator scrolls past.

  Reads the catalog and nothing else: no host, no bundle, no privileges, no
  network. The ID is case-insensitive, and an unknown one suggests the IDs in
  the same module.

- **`--format sarif` (WP-31).** SARIF 2.1.0 for GitHub Advanced Security and
  anything else that ingests it, on both `scan` and `eval`. The full mapping is
  `docs/adr/0018-sarif-mapping.md`; the decisions that matter:

  `UNKNOWN` becomes `level: warning`, never `none`. `none` files it as
  informational, which reports a cleaner host than the scan found; `error`
  claims a failure nobody observed. The consequence of an `UNKNOWN` is a
  finding's consequence — somebody has to look — and the message opens
  `Could not determine (reason):` with the literal state in
  `properties["plumbline/result"]`.

  Accepted risks use SARIF's native `suppressions` array with
  `kind: "external"` and the operator's justification, so a dismissal in GitHub
  carries the reason a human wrote. The result keeps the level its original
  verdict earned.

  `PASS` and `NOT_APPLICABLE` are not results; they are counted in
  `invocations[0].properties` alongside posture and coverage. Seventy-four
  passing checks per run bury the three that matter.

  `partialFingerprints["plumblineFingerprint/v1"]` is `finding.Fingerprint` —
  the same string a suppression file matches on. **This raises the stakes on
  fingerprint stability**: breaking the derivation would now also cost every
  user their GitHub security-tab history, with no migration. ADR-0018 records
  why, and `VERSIONING.md` §4.4 already forbids it outside a schema major.

  No new dependency: the SARIF subset needed is structs and `encoding/json`.

### Schema
- **`findings-v1` gained an optional `skipped_by` string on a finding.**
  Additive within the major (`VERSIONING.md` §4.1). A new constraint enforces
  that it appears only on a `SKIPPED` finding and never alongside a
  `suppression`.

### Fixed
- **Multi-paragraph prose rendered as one run with `\x0a` escapes embedded in
  it.** `internal/render/text`'s wrapper sanitised before splitting on
  newlines, and `sanitize.Text` escapes every C0 control character — a newline
  among them — so the separator was destroyed before it was looked for. Prose
  now splits first and sanitises each line, and reflows rather than honouring
  the source's hard wrapping. Invisible until `explain` rendered a paragraph
  longer than one line.

### Changed
- **`.gitignore` now covers `*.sarif` and suppression files.** Both are reports
  about a real host — the same reconnaissance a bundle is — and both are the
  first thing anyone writes to the repository root while wiring up code
  scanning. Nothing of either kind is checked in; the corpus CI re-evaluates is
  `testdata/bundles`.
- `--format` now accepts `sarif`. It previously returned a usage error saying
  the format was planned.

### Fixed
- **`eval` and `diff` now say so when handed a findings document.** Passing
  `scan --json > out.json` output to either produced
  `malformed bundle: reading tar: invalid input: magic number mismatch`, which
  described the sixth thing that went wrong and not the first. They now report
  what the file actually is and how to write the file they wanted. The test is
  the file's first bytes, never its extension — a bundle an operator chose to
  name `.json` is still a bundle.
- `scan --help`, `collect --help` and `diff --help` name `--save-bundle` and
  `-o` explicitly, with the `.plb` extension and the reason the two artefacts
  are not interchangeable. The trap was one an operator falls into while
  reading `--help`, so the answer belongs there.

---

## [0.4.0] — 2026-08-20

**A report a person reads, a finding a team can accept, and an answer to "what
changed overnight".** Catalog version 13, 79 checks across nine modules, schema
`findings-v1` — the same catalog `v0.3.1` shipped. Every verdict this release
reaches about a host is one `v0.3.1` would have reached. What changed is what
happens to that verdict afterwards.

Three work packages, and the thread connecting them is that a finding must
never go quiet. The report may reorganise it, an operator may accept it, and a
diff may decide it did not move — but nothing here can make it disappear.

**1 — The terminal report is laid out in the manner of `lynis` (WP-28).**
A scan phase of one line per check under `[+] MODULE` headings, each carrying a
bracketed verdict flush against a fixed 78-column grid — `[ OK ]`,
`[ WARNING ]`, `[ UNKNOWN ]`, `[ SKIPPED ]`, `[ DISABLED ]` — and a
`[=] Warnings and suggestions` phase at the bottom holding every detail,
evidence excerpt and remediation. The previous layout interleaved the two,
which put forty lines of advice between two check results and destroyed the
column of verdicts the layout exists to provide.

The grid is fixed rather than read from the terminal, because a report has to
be byte-identical across two runs of an unchanged host or a nightly diff is
noise. Only check titles are ever truncated; a check ID, a path or an evidence
excerpt is a value an operator copies.

**2 — Findings can be accepted, and acceptance is not concealment (WP-29).**
`--suppress PATH` applies a `suppressions/v1` file mapping a finding
fingerprint to a justification and an optional expiry. **There is no
auto-discovered filename and no implicit default** — an explicit path is the
deterministic design for a tool that decides whether a host is safe.

A suppression never removes a finding. The result becomes `SKIPPED`, the
finding carries a `suppression` object recording the justification and
`original_result` — what the check actually reached — and accepted risks get
their own `[=] Accepted risks` section and a distinct `[ SUPPRESSED ]` token.
"We accepted this" can never render as "we never looked".

A blank justification, an unknown field, a duplicate fingerprint or a
`check_id`/`subject` label that fingerprints to something else are all parse
errors, and a bad file aborts the scan rather than running with nothing
suppressed. Expiry is measured against the scan's start time rather than the
wall clock, so re-evaluating an archived bundle gives the same answer forever.

**3 — `plumbline diff OLD NEW` (WP-30).** Compares two bundles and reports only
what moved, in five categories: `NEW FAILURE`, `REGRESSED`, `VERDICT CHANGED`,
`NEWLY SUPPRESSED`, `RESOLVED`. Each change shows both ends of its transition,
and the summary carries a posture delta beside a coverage delta.

Both sides are re-evaluated with today's catalog, so a check whose logic was
corrected between the two collections cannot appear as the host having changed.
A suppressed finding is compared by `original_result`, so accepting a risk
diffs as an acceptance rather than as a fix — and a rule that lapsed between
the two collections shows as `REGRESSED` rather than as somebody having broken
something.

### Added
- `--suppress PATH` on `scan` and `eval` (WP-29).
- `plumbline diff OLD NEW`, with `--suppress`, `--no-color` and `-o` (WP-30).
- `[ SUPPRESSED ]` and `[ DISABLED ]` status tokens, distinct from
  `[ SKIPPED ]`: an accepted risk, a check the profile did not run, and a check
  whose subject is absent are three different facts.

### Changed
- **The default terminal layout (WP-28).** Breaking for anything parsing it —
  which was already unsupported. `--json` emits `findings/v1`, which is the API.
- Suppressed findings leave the posture denominator (a team is not scored down
  for reviewing something) and reduce coverage, which is the existing
  documented meaning of `SKIPPED`.

### Schema
- `findings-v1` gained an optional `suppression` object on a finding. Additive
  within the major (`VERSIONING.md` §4.1); consumers written before it existed
  ignore it and correctly see a `SKIPPED` finding. The `result` enum is
  unchanged.
- The constraint "a result other than `FAIL` carries no remediation" now
  excepts suppressed findings, which keep the fix they would otherwise need so
  the acceptance stays reviewable. This relaxes a rule — no previously valid
  document becomes invalid.
- A new constraint enforces that `suppression` appears only on `SKIPPED`.

### Build
- **Go 1.24 floor, 1.25 release toolchain.** `go.mod` declares the minimum a
  source build needs; CI builds the release binaries with 1.25. Go supports
  only its two newest majors, so 1.23 — which CI used until now — no longer
  receives stdlib security fixes, in a tool that runs as root.
- **golangci-lint moved to v2** (config migrated with `golangci-lint migrate`,
  action v9, linter pinned v2.13.1). The same thirteen linters run. Three
  findings the older pinned linter did not report were fixed.
- `github.com/klauspost/compress` 1.18.0 → 1.19.2, which clears GO-2026-5841
  (an out-of-bounds read in `compress/s2`). That package is not linked into
  this binary — only `zstd` is — so the advisory was never reachable here;
  `govulncheck` reported and still reports zero reachable vulnerabilities.

### Fixed
- The fixture corpus did not survive a `git checkout`: three FILESYS checks
  returned `PASS` on a fresh clone because git cannot store an empty directory
  and one fixture file had never been added. `TestEveryFixtureSurvivesACheckout`
  now makes that class of defect impossible to reintroduce.
- `cli-host` carried no `/etc/nsswitch.conf`, which made FILESYS-0010's verdict
  depend on the uid of whoever cloned the repository.
- Four CI steps parsed the terminal report as JSON after `v0.3.0` changed the
  default output. (Both released in `v0.3.1`.)

### Check corrections
None. No check's verdict logic changed in this release, and the catalog version
is deliberately unchanged at 13 — a bump would falsely signal that scores are
no longer comparable with `v0.3.1`.

### Build
- **The minimum Go version is now 1.24** (`go.mod`), and CI builds with 1.25.
  Go supports only its two newest majors, so 1.23 — which CI used until now —
  no longer receives stdlib security fixes, and this project ships a binary that
  runs as root. 1.24 is also the floor `klauspost/compress` v1.19.x requires,
  so the bump unblocks that dependency update.
- **golangci-lint moved to v2** (config migrated with `golangci-lint migrate`,
  action to v9, linter pinned to v2.13.1). The same thirteen linters run. Three
  findings the older pinned linter did not report were fixed: two tagged-switch
  simplifications, and a `//nolint` with a stated reason on a `rune`→`byte`
  conversion whose bounds check is the surrounding case guard.

### Added
- **`plumbline diff OLD NEW` (WP-30).** Compares two bundles and reports only
  what moved, in five categories: `NEW FAILURE`, `REGRESSED`,
  `VERDICT CHANGED`, `NEWLY SUPPRESSED` and `RESOLVED`. Each change shows both
  ends of its transition, and the summary carries a posture delta beside a
  coverage delta.

  **Both sides are re-evaluated with today's catalog**, so a check whose logic
  was corrected between the two collections cannot appear as the host having
  changed. There is consequently no catalog-drift flag.

  A suppressed finding is compared by `suppression.original_result`, so
  accepting a risk diffs as an acceptance rather than as a fix — and a rule that
  lapsed between the two collections shows as `REGRESSED` rather than as
  somebody having broken something.

  `VERDICT CHANGED` (`FAIL` ↔ `UNKNOWN`) is not one of the four transitions the
  work package named. It is here because `UNKNOWN` leaves the posture
  denominator and `FAIL` does not, so without it a host could show a posture
  delta with no change listed to explain it.

  Terminal output only; `--json` is a usage error, because rendering a
  comparison as a document would be a second public API and `findings/v1` does
  not describe one.

- **Acknowledgeable suppressions (WP-29).** `--suppress PATH` applies a
  `suppressions/v1` file mapping a finding fingerprint to a justification and an
  optional expiry.

  **A suppression never removes a finding.** The result becomes `SKIPPED` and
  the finding carries a new `suppression` object recording the justification,
  the expiry, and `original_result` — what the check actually reached. Accepted
  risks get their own `[=] Accepted risks` section in the terminal report and a
  distinct `[ SUPPRESSED ]` status token, so "we accepted this" can never read
  as "we never looked".

  A blank justification, an unknown field, a duplicate fingerprint, or a
  `check_id`/`subject` label that fingerprints to something else are all **parse
  errors**, and a bad file is a hard error rather than a scan with nothing
  suppressed. Rules that lapsed or matched nothing are reported on stderr.

  Expiry is measured against the scan's start time rather than the wall clock,
  so re-evaluating an archived bundle gives the same answer forever.

  An accepted risk leaves the posture denominator (a team is not scored down for
  reviewing something) and reduces coverage, which is the existing meaning of
  `SKIPPED`.

### Schema
- **`findings-v1` gained an optional `suppression` object on a finding.**
  Additive within the schema major (`VERSIONING.md` §4.1); consumers written
  before it existed ignore it and correctly see a `SKIPPED` finding. The
  `result` enum is unchanged.
- The constraint "a result other than `FAIL` carries no remediation" now excepts
  suppressed findings, which keep the fix they would otherwise need so the
  acceptance stays reviewable. This relaxes a rule — no previously valid
  document becomes invalid.
- A new constraint enforces that `suppression` appears only on `SKIPPED`.

### Changed
- **The terminal report is laid out in the manner of `lynis` (WP-28).** A scan
  phase of one line per check under `[+] MODULE` headings, each carrying a
  bracketed verdict flush against a fixed 78-column grid — `[ OK ]`,
  `[ WARNING ]`, `[ UNKNOWN ]`, `[ SKIPPED ]`, `[ DISABLED ]` — and a
  `[=] Warnings and suggestions` phase at the bottom carrying every detail,
  evidence excerpt and remediation. The previous layout interleaved the two,
  which put forty lines of advice between two check results and destroyed the
  column of verdicts the layout exists to provide.

  `NOT_APPLICABLE` and `SKIPPED` render as different tokens rather than
  collapsing into one: the first means the subject is not on this host, the
  second that the check was deliberately not run.

  `UNKNOWN` keeps its own heading at equal weight in the suggestion phase. The
  detail moved; the emphasis did not.

  **This is a layout change to output that is explicitly not the API**
  (`docs/VERSIONING.md`, `CLI-SPEC.md` §Output). Anything parsing the terminal
  report was already unsupported and should ask for `--json`.

---

## [0.3.1] — 2026-08-20

**Verification harness repairs. No change to the tool.** Catalog version 13
unchanged, 79 checks unchanged, schema `findings-v1` unchanged, no check's
verdict logic touched. A scan of your host produces byte-identical output to
`v0.3.0`.

This release exists because `v0.3.0` shipped with a red pipeline, and a
security auditor whose own verification does not pass is not one you should
trust. Everything below was a defect in the test corpus or the CI harness. Two
of them had been failing on every CI run since the checks were written, and
passing on every developer machine — which is the interesting part.

### The fixture corpus did not survive a git checkout

Three FILESYS checks returned `PASS` on a fresh clone and `FAIL` in the
working tree that authored them. Git cannot store an empty directory and does
not store files nobody added, so `filesys-sticky/var/spool/upload`,
`filesys-system-dir/etc/cron.d` and `filesys-suid-writable/opt/vendor/helper`
did not exist in the tree CI checks out. Each check correctly found nothing
wrong with a subject that was not there. **The FAIL half of those fixtures
existed only on one machine**, so rule 5 was satisfied on paper and not in
fact.

`TestEveryFixtureSurvivesACheckout` now asserts that every path a
`fixture.json` names exists, that no fixture directory is empty, and that every
fixture file is tracked by git. It caught an untracked file of its own within
the hour.

To be explicit, because it was the first hypothesis and it was wrong: **git
stripping the SUID and SGID bits was not the cause.** Git records those
fixtures as `0644` and always has; the manifests declare the modes and the fake
seam applies them, so the checks never read the on-disk bits. No manifest
needed a mode override added, and none was.

### A fixture's verdict depended on who cloned the repository

`scan --root` reads through the live seam, so a fixture tree carries the
ownership of whoever checked it out — uid 1000 on a developer machine, 1001 on
a GitHub runner, 0 in a container. `cli-host/etc/passwd` contains `alice:1000`,
so on one of those three the owners resolved and FILESYS-0010 returned `PASS`.

On the other two the owner did not resolve, and the check declined to call it
stray without knowing the local files were the whole account database — it
returned `UNKNOWN(ambiguous_system_state)`, which is rule 3 working exactly as
intended. But an `UNKNOWN` is not an evaluated check, so coverage fell to 98.73
and the `--min-coverage 100` gate failed. **The bug moved coverage rather than
a verdict**, which is why it was invisible in a diff and green on the machine
that wrote it.

The check was right and is untouched. The fixture was wrong: a Debian 12 host
with no `/etc/nsswitch.conf` does not exist. With the file present the check
reaches a verdict under any ownership, and `docs/FIXTURES.md` §4.3 now states
the rule that live-seam fixtures have to follow.

### CI parsed a human report as JSON

Four workflow steps grep a `findings/v1` document out of `scan` and `eval`.
`v0.3.0` made the terminal report the default output and did not update them,
so they failed while reporting a degraded exit code — a symptom of the parse,
not of coverage. They pass `--json` now, and the distro step prints the summary
and every non-`PASS` finding when an assertion fails instead of exiting 1 with
no evidence.

### Verified
All twelve CI jobs pass on `main`: `verify`, `go test -race`, `golangci-lint`,
schema validation, the hostile-input corpus, the zero-network namespace scan,
both cross-compiles, and scans on `alpine:3.20`, `debian:13`, `fedora:latest`
and `ubuntu:24.04`. The suite was additionally run as uid 1001 over a
`git archive` of the release tree, which is what a runner actually receives.

### Check corrections
None. No check's verdict logic changed in this release, and the catalog version
is deliberately unchanged at 13 — a bump would falsely signal that scores are
no longer comparable with `v0.3.0`.

---

## [0.3.0] — 2026-08-20

**Engine maturation and resilience.** Catalog version 13, 79 checks across nine
modules, schema `findings-v1` unchanged.

Three things happened, and each closed a hole the previous milestone could not
have found.

**1 — The walker learned to aggregate, and FILESYS-0010 became possible.**
The shared walk recorded rows: the first N inodes matching a pure predicate.
That answers "show me the setuid binaries" and cannot answer "does every uid on
disk resolve to an account", because the join is against a fact that does not
exist when the predicate is registered and recording every owned inode to defer
the join would overflow the row cap on any host that has users. A `Tally` folds
instead of recording — one bucket per distinct key, an unbounded count inside
it, one exemplar path — so memory is bounded by distinct *owners* rather than
by inodes, and a tally covers a ten-million-inode filesystem in about 3 MB. The
join then happens in the check, where facts live. `users.nsswitch` was
collected alongside it, because "not in `/etc/passwd`" and "belongs to nobody"
are the same statement only when the local files are the whole account
database.

**2 — The default output became a report for a person.** `plumbline scan`
printed a `findings/v1` document, which is right for a pipeline and wrong for
whoever typed the command. `internal/render/text` is now the default: a header
with the scan's context, a per-module listing, a full block for every FAIL
**and every UNKNOWN**, and a summary that states the UNKNOWN count on its own
line instead of burying it. **This is a breaking change for anything piping the
output into a parser** — add `--json`. No new dependency: plain SGR escape
sequences and `text/tabwriter`.

**3 — The scanner stopped drawing verdicts from files it could not parse.**
Pointed at a host with four kilobytes of random bytes in every configuration
file, it used to return **22 PASS, 23 FAIL and zero fact errors**. No parser
panicked; every one of them silently produced an empty, confident fact, and an
empty configuration satisfies every negative assertion in the catalog. The same
host now produces five fact errors and no PASS or FAIL from any content-reading
module. Recorded in *Check corrections* below, because it moves posture scores
on damaged hosts.

### Milestone scope
`v0.3.0` was originally scoped as "feature complete for v1" with eighteen
items, and shipped four. **Feature freeze moves to v0.4.0**, which carries the
other fourteen — SARIF, `diff`, suppressions, `doctor`, the platform matrix and
the remaining collectors. The re-scoping is recorded in `docs/ROADMAP.md`
rather than applied quietly, because a milestone that redefines itself on the
way to being tagged is exactly the thing a reader cannot reconstruct from a
diff.

### Check corrections
- **Every check reading a configuration file now returns `UNKNOWN` where it
  previously reported a verdict drawn from a file it could not really parse.**
  A scan of a host with four kilobytes of random bytes in every config file
  used to produce 22 `PASS` and 23 `FAIL` findings and **zero fact errors**;
  it now produces five fact errors and no `PASS` or `FAIL` from any
  content-reading module. Affected: anyone whose posture score was computed
  over a host with a damaged `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `sshd_config`, `rsyslog.conf`, `nsswitch.conf`, a PAM stack, a firewall
  ruleset or a `sysctl.d` drop-in. Posture will move, and coverage will drop to
  reflect what was actually readable — which is the correct figure and was not
  being reported
- **Every SSHD check now returns `UNKNOWN` over a configuration `sshd -t`
  rejects**, including checks whose keyword the file appears to set. sshd
  refuses a config file as a unit rather than skipping the bad line, so on such
  a host the daemon runs whatever last parsed and the file on disk describes
  nothing. Previously these reported sshd's compiled-in defaults, which is
  correct for a valid file that omits a keyword and a confident wrong answer
  for a file that never loads
- **USERS-0006 no longer returns `PASS` over an `/etc/passwd` that is not an
  account database.** It read the (true) observation "this file contains no NIS
  import lines" off a file with no accounts in it at all. It now routes through
  the module's `unknownIfIncomplete` gate like every other check here
- **A required fact this build cannot decode is now `UNKNOWN(fact_version_mismatch)`
  rather than a verdict.** Re-evaluating a bundle written by a newer Plumbline
  reported `NOT_APPLICABLE: the SSH server is not configured on this host` —
  a statement about the host manufactured from a decode failure

### Added
- **`collect.NotText`, one gate on every collector's read path.** A NUL byte is
  *proof* a file is not the text configuration it was read as — every consumer
  of these files on Linux is C reading NUL-terminated strings, so the software
  that acts on the file stops at that byte or refuses it, and any reading of
  ours that continued past it would describe a configuration that is not in
  force. Applied in the `users`, `sshd`, `logging`, `network`, `auth` and
  `kernel` collectors. Invalid UTF-8 is deliberately **not** treated as
  malformation: a GECOS field carries a Latin-1 name on older hosts, and
  `sanitize` already handles those bytes correctly
- **`fact.SSHDConfig.SyntaxErrors`** — non-blank, non-comment lines that are not
  a keyword followed by an argument. `sshd_config(5)` defines no keyword taking
  zero arguments, so each is fatal to `sshd -t`. Unrecognised keywords are
  deliberately not recorded: the valid keyword set differs by OpenSSH release,
  and calling a newer option a syntax error would report a fault on a host that
  is merely more current than this build
- **`fact.Opaque`** — the marker for a fact that is present, preserved, and not
  interpretable by this build. An interface rather than a concrete type so that
  `internal/catalog` need not import `internal/bundle` to evaluate anything.
  `finding.ReasonFactVersion` was declared for this case and had never been
  produced by anything
- **Four `edge-*` fixtures** and module-wide tests over them. The tests are
  module-wide rather than per-check on purpose: the per-check version of these
  gates had already been forgotten three times — SSHD-0002 (the module's own
  reference implementation), SSHD-0007 and USERS-0006 all read their fact
  directly instead of through the shared funnel and so carried none of the
  shared gates
- **A human-readable terminal report, and it is now the default.** Running
  `plumbline scan` printed a `findings/v1` document, which is the right answer
  for a pipeline and the wrong one for the person who typed the command.
  `internal/render/text` renders a header with the scan's context, a
  per-module listing of every check, a full block for every FAIL and every
  UNKNOWN — detail, evidence, remediation summary and effort — and a summary
  table. `PASS` is green, `FAIL` red, `UNKNOWN` yellow, `NOT_APPLICABLE` and
  `SKIPPED` dim. No external dependency: plain SGR escape sequences and
  `text/tabwriter`
- **`--json`**, shorthand for `--format json`, on `scan` and `eval`. It is
  shorthand over the *default*, not an override — `--format terminal --json` is
  a usage error rather than a silent discard of what the operator typed
- **`--no-color`**, alongside `NO_COLOR` in the environment (honoured at any
  value, including `0`, per the no-color.org convention) and a non-terminal
  stdout. `--output` is never coloured whatever the rules say
- **Aggregating walker tallies** (`internal/collect/walker/tally.go`). The walk
  already answered "which inodes match this predicate" by recording rows. It
  now also answers "how are these inodes distributed across a keyspace" by
  folding: one bucket per distinct key, an unbounded count inside it, and one
  exemplar path. Memory is bounded by distinct keys rather than by inodes, so a
  tally can cover a ten-million-inode filesystem inside a budget a
  row-recording interest would exhaust in its first populated directory. New
  fact namespace `fs.tally.<name>` (`fact.FSTally`), new truncation reason
  `max_keys`, default keyspace cap 16,384
- **FILESYS-0010 — every uid and gid owning a file resolves to a local account
  or group.** MEDIUM. Files left behind by a deleted account are not untidiness:
  `useradd` allocates the lowest free uid, so the next account created inherits
  the number and everything the departed one owned, and nothing records that it
  happened
- **`users.nsswitch`** (`fact.NSSwitch`) — `/etc/nsswitch.conf`, parsed into
  which name services answer for which databases. Four USERS check specs
  already named this file as a known limitation; it is now collected

### Changed
- **`/etc/shadow` lines now require the nine fields `shadow(5)` defines.** The
  parser accepted any line with two, which let arbitrary text containing a
  single colon become an account with a password state — which is how four
  kilobytes of random bytes produced ten accounts and a `FAIL` reporting weak
  password hashes for people who do not exist
- Firewall ruleset files containing a NUL are recorded as `SourceError` rather
  than `SourcePresent`, so NETWORK-0001 no longer tells a host it has a
  firewall configured when nftables would refuse to load the file
- An unparseable rsyslog or journald drop-in is recorded as an unresolved
  include rather than skipped, so one bad drop-in degrades the checks that
  depend on it instead of reading as a file that configures nothing
- **`--format` now defaults to `terminal` rather than `json` on `scan` and
  `eval`.** This is the one change in this release that can break a caller:
  anything piping `plumbline scan` into a JSON parser must add `--json` or
  `--format json`. The exit codes, the schema and every flag that gates on
  findings are unchanged, and a test asserts the chosen format cannot move the
  exit code — rendering is display, gating is a verdict, and if the two could
  influence one another then `--json` would be a way to change what CI
  concluded about a host
- `--format` reports an unknown value by name and refuses `sarif` with a
  message that says it is coming rather than that it is a typo. The two are
  different problems for whoever is reading the error
- `internal/collect/collectors/users` reads a fourth file. `Produces()` gains
  `users.nsswitch`; a missing file is recorded as a *state* rather than as a
  fact error, because glibc falling back to a compiled-in default is a real
  observation about the host and simply not the same one as "configured to
  files"
- `walker.Walk` and the `fswalk` collector accept a walk justified by a tally
  alone. Previously a walk with no interests was a caller error
- `bundle.decoderFor` tests the `fs.tally.` prefix before `fs.`. The ordering is
  load bearing: `fs.tally.owner_uid` also carries the `fs.` prefix, and
  decoding it as an `FSMatches` would have *succeeded* — `encoding/json`
  ignores unrecognised fields — leaving an empty, complete-looking match set
  where a tally used to be, and FILESYS-0010 returning a confident PASS from a
  bundle that recorded a host full of unowned files. `TestRoundTripWalkerTallyFacts`
  pins it

### Security
- **The terminal renderer is where a hostile filename stops being a curiosity.**
  A path may contain arbitrary bytes including ESC, and this is the renderer
  that writes to an operator's session and that deliberately emits escape
  sequences of its own. Sanitisation already happens once, upstream, where
  untrusted text becomes part of a finding (T-03); `TestNoEscapeSequenceFromTheHostReachesTheTerminal`
  asserts the defence actually holds *through* this renderer rather than
  assuming it, and a second test asserts that with colour on, every ESC byte in
  the output is one the renderer wrote
- Reports written with `--output` are created owner-only, through the same path
  bundles are. A terminal report names paths, accounts and misconfigurations;
  it is the same reconnaissance material the JSON is

### Documentation
- `docs/DATA-MODEL.md` §3.1 documents what `parse` covers and, as importantly,
  the three things deliberately *not* treated as malformation. §3.2 documents
  `fact.Opaque` and the third state between present and missing
- `docs/FIXTURES.md` describes the `edge-*` corpus and what each fixture
  isolates
- **`docs/ROADMAP.md` rewritten against reality.** It still described the
  project as pre-v0.1 with everything ahead of it. v0.1.0 and v0.2.0 are now
  marked complete with what each actually shipped, the v1 module table carries
  a shipped-count column beside its target, and the 42-check gap between the
  78 that shipped and the ~120 planned is accounted for module by module rather
  than left to be rediscovered as a defect. v0.3.0 is scoped into engine
  maturation, UX and CLI polish, and edge-case resilience, in that order
- From this release, **every work package syncs `ROADMAP.md`, `CHANGELOG.md`
  and `DATA-MODEL.md` with what is actually in `main`.** A roadmap that
  disagrees with the code is worse than no roadmap, because people plan against
  it
- `docs/checks/FILESYS-0010.md`, and `docs/DATA-MODEL.md` §2.3 gains
  `fs.tally.<tally>` and `users.nsswitch`
- `docs/CLI-SPEC.md` §Output rewritten: which flags exist today and which are
  still specification, the three colour rules in precedence order, and an
  explicit statement that `--format json` is the API and the terminal report is
  not. `README.md` gains a usage section showing both
- **`docs/ROADMAP.md` v0.3 marks the terminal renderer done.** Per the rule
  adopted last release, the roadmap is synced in the same commit as the code

### Notes on what FILESYS-0010 will not do
- **It will not report a directory account as unowned.** "This uid is not in
  `/etc/passwd`" is a fact about a file; "this uid belongs to nobody" is a fact
  about the host, and the two coincide only when the local files are the whole
  account database. Where `nsswitch.conf` routes `passwd` or `group` anywhere
  else — including `systemd`, which is on the default line of every current
  systemd distribution — an unresolved identity yields
  `UNKNOWN(ambiguous_system_state)` naming the routing table, not a FAIL
- **The PASS branch never consults `nsswitch.conf`**, and that asymmetry is
  what keeps the check useful rather than permanently unknown. A name service
  can add identities that resolve; it cannot remove one `/etc/passwd` already
  resolves. So on a healthy directory-joined host every uid on disk still
  resolves locally and the check passes outright

---

## [0.2.0] — 2026-08-20

**The catalog milestone: 78 checks across nine modules**, every one with PASS
and FAIL fixtures enforced in CI, evaluated from a single filesystem traversal
and a bounded set of configuration reads. Catalog version 11.

| Module | Checks | | Module | Checks |
|---|---|---|---|---|
| SSHD | 19 | | AUTH | 6 |
| KERNEL | 16 | | CRON | 5 |
| USERS | 10 | | LOGGING | 5 |
| FILESYS | 9 | | SERVICES | 5 |
| | | | NETWORK | 3 |

### Security
- **Password hashes never enter a bundle.** Evidence recording is wired at the
  seam, so reading a file stored its bytes — which, applied to `/etc/shadow`,
  would have copied every password hash on the host into an artifact designed
  to be sent to auditors. `/etc/shadow`, `/etc/gshadow`,
  `/etc/security/opasswd` and `/etc/master.passwd` are now excluded from the
  evidence store, with no flag to re-enable them, and `users.shadow` records
  only whether a field is empty or locked and which crypt scheme it uses
  (ADR-0015)
- USERS-0009 (password maximum age) ships at **LOW** severity and names the
  framework conflict in its own finding. NIST SP 800-63B advises against forced
  rotation; CIS requires ≤365 days and the DISA STIGs require ≤60. Plumbline
  reports against the CIS threshold and states the disagreement rather than
  resolving it, so an organisation following NIST suppresses the check with a
  recorded reason instead of inheriting this project's opinion silently
- SSHD-0020 records the joint between two modules: with `UsePAM no`, sshd never
  runs the PAM account phase, so the password-aging policy USERS-0009 and
  USERS-0010 report is configured and not enforced for SSH logins
- `--redact` is documented precisely in `CLI-SPEC.md`: it removes the hostname,
  it does not anonymise account names, and it never was what kept hashes out of
  a bundle

### Check corrections
- **SSHD-0002 (root login) now reports a `Match` block that re-enables root
  login.** Previously a configuration with `PermitRootLogin no` globally and
  `PermitRootLogin yes` inside a `Match` block returned PASS, citing the
  Match-scoped directive as evidence but not acting on it. It now returns FAIL
  at MEDIUM — one class below the HIGH of a global misconfiguration, because the
  exposure is conditional rather than universal — and names the `Match` criteria
  in the detail.
  **Who is affected:** any host whose `sshd_config` re-enables root login inside
  a `Match` block. Those hosts move from PASS to FAIL and their posture score
  falls accordingly. The verdict was wrong before: the insecure state was
  reachable and the finding said otherwise.

### Added
- **FILESYS module (WP-24), 9 checks.** Catalog version 11. Six over the shared
  traversal — setuid or setgid executables writable by group or other
  (FILESYS-0001), the same outside the system binary directories (0002),
  world-writable files (0003), world-writable directories without the sticky
  bit (0004), world-writable system directories (0005), device nodes outside
  /dev (0006) — and three over the mount table: /tmp (0007), /dev/shm (0008)
  and /home (0009).
- **The shared filesystem walker is wired into the scan.** WP-15 built it and
  nothing consumed it; `internal/cli/catalog.go` now imports both the walker
  and the FILESYS interest registrations, so one traversal per scan actually
  happens. Five interests are registered: `suid`, `sgid`, `world_writable`,
  `world_writable_dir`, `device_outside_dev`.
- **The asymmetric truncation rule is enforced and tested first.** Every FILESYS
  check that concludes something from *not* finding a match returns
  `UNKNOWN(source_truncated)` when the walk hit a limit, and every check that
  reports something the walk *did* find returns FAIL whether or not the
  traversal finished. `filesys-truncated` is driven twice — once complete,
  where every check must PASS, and once with a four-inode budget, where every
  one must return UNKNOWN — because without the first half a check that
  returned UNKNOWN unconditionally would satisfy the second while being
  useless.
- **`fs.mounts` fact**, carrying each mount point's type, per-mount options,
  superblock options and a `Known` flag. It is derived from the mount table the
  walk **already reads** to apply its filesystem-type skip list rather than
  from a second read of /proc/self/mountinfo: two reads of one kernel table
  could disagree and the disagreement would be invisible. It is published
  unconditionally, including when no interest is registered and no traversal
  happens, because making it depend on an unrelated module's wiring would leave
  the mount checks UNKNOWN for a reason unconnected to the host.
- `parseMountInfoLine` now returns the per-mount and superblock option lists.
  The two are kept separate because mountinfo reports them separately and they
  are not the same thing — "is /tmp nosuid" is a question about the first, and
  answering from the second would be right often enough to look correct.
- **No FILESYS check carries an allowlist of blessed binaries**, per the
  runbook. Which setuid executables are legitimate differs per distribution and
  a hardcoded list silently excuses whatever an attacker names their implant
  after. What is asserted instead are properties no legitimate setuid binary
  has: being writable by a non-owner, and sitting outside the directories a
  package manager installs into.
- **SERVICES module (WP-21), 5 checks.** Catalog version 9. Cleartext-credential
  services not enabled (SERVICES-0001), network discovery and RPC portmapping
  (0002), exactly one time synchronisation daemon (0003), every enabled unit
  resolving to a unit file that exists (0004), and unit directories writable by
  root alone (0005).
- `services.units` fact. **systemd enablement is recovered from symlinks**:
  `systemctl enable` writes no database row and sets no flag inside the unit
  file, it creates a link in `<target>.wants/`, so reading those directories
  recovers exactly what `systemctl is-enabled` reports with no dbus and no
  privilege. Masking is tested before enablement because systemd does — a
  masked unit does not start even with a `.wants` symlink naming it.
- **`System.Readlink`**, which returns a symlink's target *as written* and
  resolves nothing (ADR-0017). A seam method returning a resolved absolute path
  would have dereferenced it against the real host rather than the scan root,
  silently, because a developer's machine has the file a fixture names.
  Resolution happens in the collector and goes back through `Stat`, so `--root`
  still governs it. `ErrNotSymlink` was added so `live` and `fake` agree about
  a path that is not a link.
- `symlinks` fixture-manifest key. Git stores symlinks natively, so unlike
  ADR-0013's inode overrides this is a containment rule rather than a
  capability gap: an *absolute* target committed as a real link resolves
  against the developer's root, and a fixture naming
  `/usr/lib/systemd/system/sshd.service` points at the real unit on every Linux
  workstation. Relative targets stay as real links and need no entry.
- **NETWORK module (WP-22), 3 checks.** Catalog version 10. A host firewall is
  configured (NETWORK-0001), its default inbound policy denies (0002), and
  exactly one configuration is in force (0003). The module is small on purpose:
  SSHD covers the exposed service and KERNEL covers the packet-handling
  parameters a firewall does not govern.
- `network.firewall` fact — **derived properties only, never ruleset contents**.
  A firewall configuration is a map of the network, and a bundle designed to
  travel would carry it wherever the bundle is filed. An empty configuration
  file is not a firewall: Debian's nftables package installs
  /etc/nftables.conf whether or not anybody wrote a rule in it, so statements
  are counted rather than the file's existence being trusted.
- **AUTH module (WP-23), 6 checks.** Catalog version 10. Password quality
  enforced (AUTH-0001), its parameters strict enough (0002), account lockout
  configured (0003), empty passwords refused (0004), strong password hashing
  (0005), and password history kept (0006).
- `auth.pam` fact — **the PAM stack as a graph, not a file**. Three include
  directives with different scopes build it: `@include` inlines a whole file,
  `<type> include` pulls in one management group, and confusing them either
  drops three quarters of a Debian host's rules or imports password rules into
  the auth stack. Both distribution layouts are always probed, so the layout is
  read from what is there rather than guessed. Control flow is deliberately
  **not** simulated: implementing the bracketed `[success=1 default=ignore]`
  jump semantics wrongly would produce confident verdicts about which module
  actually runs.
- Red Hat's `/etc/pam.d/system-auth` is a symlink on every stock install, which
  the seam's `O_NOFOLLOW` correctly refuses. The collector resolves the chain
  explicitly through `Readlink` — one observed hop at a time, bounded, each
  recorded — and cites the resolved file, because citing the link would send an
  operator to edit something authselect overwrites. Without this the module
  would report UNKNOWN across the entire Red Hat family.
- **LOGGING module (WP-20), 5 checks.** Catalog version 8. rsyslog log file
  permissions (LOGGING-0001), remote forwarding configured (0002), persistent
  journal storage (0003), journald-to-rsyslog forwarding (0004), and a reliable
  forwarding transport (0005).
- `logging.rsyslog` and `logging.journald` facts. **Both of rsyslog's
  configuration languages are parsed**: the sysklogd legacy format
  (`*.* @@host`), rsyslog's own `$Name value` directives, and RainerScript
  objects (`action(type="omfwd" ...)`), including statements that span several
  lines. All three appear in the same file on a stock Debian or RHEL host, and
  a parser reading only one would report a correctly-forwarding host as not
  forwarding. Which language a statement was written in is preserved into the
  fact, because a finding has to quote the operator's file back in the language
  it is actually written in.
- The journald fact records whether `/var/log/journal` exists. `Storage=auto`
  is the default and its effect is a property of the filesystem rather than of
  the configuration; without that one stat, "Storage is not configured" would
  be UNKNOWN on the majority of hosts.
- **journald precedence is last-wins**, the reverse of `sshd_config`: systemd
  drop-ins override the main file. `Journald.Overridden()` lets a finding cite
  the replaced occurrences so a reader who edited the main file can see why
  their value is not in force.
- `testdata/fixtures/cli-host` gains a compliant logging configuration. Unlike
  the CRON checks, these read file *contents* rather than ownership, so the
  baseline can exercise them rather than skipping the module.
- **CRON module (WP-19), 5 checks.** Catalog version 7. `/etc/crontab`
  ownership and write permissions (CRON-0001), the five drop-in directories
  (0002), access restricted by an allow list (0003), the access-control files'
  own permissions (0004), and schedule disclosure (0005).
- `cron.files` fact — file metadata only. **No crontab contents are collected.**
  Every check in the module asks who may *write* the schedule, not what it says,
  and a crontab's command lines carry script paths, hostnames and occasionally
  credentials passed as arguments. That is ADR-0015's reasoning applied before
  the mistake rather than after it.
- **ADR-0016** formalises `system.FileInfo`'s ownership fields as a verdict
  input. `UID` and `GID` have been in the seam since the initial slice, added
  for the walker; CRON is the first module whose PASS or FAIL rests on a uid
  comparison, and that promotion carries obligations. Chiefly: **uid 0 cannot
  double as "not recorded"** the way inode 0 does for `Dev`/`Ino`, because 0 is
  precisely the value an ownership check tests for and an unrecorded zero would
  read as "owned by root". Facts carrying ownership carry an explicit state
  beside it.
- `unstattable` fixture-manifest key, distinct from `unreadable`. A file at mode
  0640 is unreadable and perfectly stat-able; what defeats a stat is a parent
  directory refusing traversal. Without the distinction the CRON module's
  `UNKNOWN(insufficient_privileges)` branch had no way to be reached from a
  fixture.
- golangci-lint pinned to v1.64.8 in CI. The config is v1 format, so `latest`
  would silently move the linter to a major that cannot read it — which is how
  the G304 exclusion went missing once already.
- **SSHD module (WP-18), complete at 19 checks.** Catalog version 6.
  - Authentication: `PasswordAuthentication` (SSHD-0003), `PermitEmptyPasswords`
    (0004, the module's only CRITICAL), `MaxAuthTries` (0006), `IgnoreRhosts`
    (0013), `HostbasedAuthentication` (0014), `StrictModes` (0019), `UsePAM`
    (0020)
  - Forwarding and session environment: `X11Forwarding` (0005),
    `AllowTcpForwarding` (0008), `PermitUserEnvironment` (0015),
    `AllowAgentForwarding` (0018)
  - Session lifetime: `ClientAliveInterval` × `ClientAliveCountMax` (0007),
    `LoginGraceTime` (0016)
  - Logging and notice: `LogLevel` (0009), `Banner` (0017)
  - Cryptography: `Ciphers` (0010), `MACs` (0011), `KexAlgorithms` (0012)
- **`Match` blocks that loosen a secure global setting are reported as
  conditional failures**, one severity class below a global misconfiguration,
  with the `Match` criteria quoted in the detail. Reporting PASS would have been
  false assurance — the insecure state is reachable — and reporting FAIL at full
  severity would have overstated an exposure limited to a named subset of
  connections. Only the twelve keywords `sshd_config` actually permits inside a
  `Match` block are treated this way.
- **The three algorithm-list checks return UNKNOWN when the keyword is absent,
  not PASS.** The effective `Ciphers`, `MACs` and `KexAlgorithms` lists are
  compiled into the sshd binary, changed between OpenSSH releases, and are
  rewritten by Red Hat's `crypto-policies`; Plumbline does not read the binary's
  version, so asserting the default would be a guess. A relative form (`+`, `-`,
  `^`) inherits the same unknowability — except that a `+` or `^` adding a broken
  algorithm is a definite FAIL, because that algorithm is enabled whatever the
  base list holds. Same asymmetry as ADR-0014.
- **USERS module (WP-17), complete at 10 checks.** Catalog version 4 introduced
  the module; 5 completes it.
  - Accounts: root uid uniqueness (USERS-0001), system-account shells (0002),
    empty passwords (0003), password hash algorithms (0004), duplicate uids and
    names (0005), legacy NIS import entries (0006)
  - Groups: group 0 confined to root (0007), duplicate gids and group names
    (0008)
  - Password aging: bounded maximum age (0009), minimum age set (0010)
- `users.shadow` records the minimum and maximum age fields as **pointers**. An
  empty field is not a zero: an empty maximum means the password never expires,
  while a maximum of 0 would mean it expires daily, and a parser conflating them
  would report the most permissive setting in the file as the strictest
- `users.group` records NIS compatibility lines, so a negative assertion over
  the group database is held to the same completeness standard as one over
  `/etc/passwd`
- `users.passwd`, `users.shadow` and `users.group` facts — three facts rather
  than one, because an unprivileged scan can read two of the three files and a
  single fact would let the unreadable one erase them
- **KERNEL module (WP-16), complete at 16 checks.** Catalog version 2
  introduced the module, 3 completes it.
  - Memory and process protections: ASLR (KERNEL-0001), `kptr_restrict`
    (0002), Yama `ptrace_scope` (0003), `dmesg_restrict` (0004),
    `suid_dumpable` (0005), unprivileged BPF (0006),
    `perf_event_paranoid` (0013)
  - Filesystem race protections: `protected_symlinks` (0009),
    `protected_hardlinks` (0010), `protected_fifos` (0011),
    `protected_regular` (0012)
  - Core dump destination (0014) — the module's first non-integer parameter
  - Network stack: per-interface reverse-path filtering (0008),
    per-interface source routing (0015), TCP SYN cookies (0016)
  - Configuration drift between the running kernel and its own sysctl files
    (0007)
- `kernel.sysctl` fact — running values from `/proc/sys` **and** configured
  values from `/etc/sysctl.conf` and the `sysctl.d` directories, kept as
  separate observations. A host whose file says hardened and whose kernel says
  otherwise is the finding KERNEL-0007 exists to make
- Shared filesystem walker (`internal/collect/walker`) and the `fswalk`
  collector: one traversal per scan, no matter how many modules ask about the
  filesystem. Consumers register interest predicates up front and the walk
  evaluates all of them per inode in a single pass
- `fs.<interest>` facts — one per registered interest (`fs.suid`,
  `fs.world_writable`, …), each carrying the walk's truncation marker and its
  own overflow count
- Fixture manifests can describe inode identity (`inodes`) and file type
  (`modes` type prefixes), so a bind-mount cycle, a character device and a SUID
  binary are expressible without root (ADR-0013)

### Changed
- **The check-purity gate matches import *lines* rather than any occurrence of
  a quoted path.** SERVICES-0003 is about clock synchronisation so its tags
  include `"time"`, which the old grep read as an import of the `time` package.
  That is the same false positive the `net` pattern was already fixed for, and
  a gate that cries wolf is one somebody eventually silences. All nine
  forbidden import forms — bare, aliased, blank, dot, `net/...`,
  `internal/system` — were verified to still fire.
- **`system.FileInfo.LinkTarget` is removed.** It had been in the struct since
  the initial slice and nothing ever populated it. Left beside a working
  `Readlink` it is the trap ADR-0016 was written about: a future collector
  reads it, gets `""`, and concludes the path is not a link, in code that
  compiles and passes review. Not a schema change — `system.FileInfo` never
  reaches a fact or a bundle.
- `fs.mounts`, `services.units`, `network.firewall` and `auth.pam` are
  registered in the bundle decoder, so a saved bundle re-evaluates to the same
  findings as the scan that produced it. The omission was caught by
  `TestSaveBundleFromScan`, which is what that test exists for.
- `testdata/fixtures/cli-host` gains systemd enablement symlinks (real and
  **relative**, so they resolve inside the tree no matter who follows them), a
  firewall configuration, a PAM stack, and a mount table. It now measures 73
  pass / 5 fail over 78 checks at coverage 100.
- **`cmd/plumbline`'s offline test compares an offline scan against an online
  scan of the same fixture** instead of asserting every finding passes. The old
  assertion was a proxy and it broke for a reason unrelated to networking: the
  CLI fixtures are read through the *live* seam, so their files carry the
  ownership of whoever checked the repository out, and git cannot record
  ownership. Both runs go through `unshare -r` and only the offline one adds
  `-n`, because `-r` maps the calling uid to 0 inside the namespace — a bare
  online run would differ in identity as well as in networking.
- `testdata/fixtures/cli-host` is documented as a **realistic checkout
  baseline**, not a clean host. "Clean" for it means the scan exits 0, not that
  it produces no findings; the CRON ownership checks fail over it permanently
  and by construction.
- The required-fact gate attaches evidence when a fact error names a path, so a
  check that resolves to UNKNOWN because a file was unreadable now cites that
  file. `DATA-MODEL.md` §5.5 has always required every UNKNOWN to carry
  evidence; the gate was the one path that did not
- `KERNEL-0008` and `KERNEL-0015` combine `conf.all` with each interface's own
  value by the rule the kernel actually uses — `max()` for `rp_filter`,
  logical `AND` for `accept_source_route`. The two point in opposite
  directions, and a host with `conf.all.accept_source_route = 0` refuses
  source routing however its interfaces are set
- The check-purity gate matches the net **import** forms (`"net"`, `"net/`)
  rather than any string beginning with `net`. A sysctl key is called
  `net.ipv4.conf.all.rp_filter`; the old pattern reported it as an impure
  import, and a gate that cries wolf is a gate someone eventually silences
- `fake`'s `modes` override is translated rather than cast: `"4755"` now
  produces a setuid file instead of silently producing `0755`. A fixture that
  asked for SUID and quietly did not get it now gets it, which may turn a
  passing test into a failing one — that is the bug being fixed
- Bundle reads decode the `fs.*` namespace by prefix, so a walker fact
  re-evaluated from a bundle stays typed rather than falling back to
  `UnknownFact`


## [0.1.0] — 2026-08-18

**Pre-release. No stability guarantees.** The walking skeleton: one collector,
one check, and every architectural claim under test. Flag names, exit codes and
the findings schema are contracts from this point on; everything in Go stays
`internal/` and may change without notice (ADR-0007).

Catalog version 1 · schema `findings/v1` · bundle `bundle/v1`

### Added
- `System` interface with `live` (scan-root aware) and `fake` (fixture-backed)
  implementations — the single OS seam
- `fact` package: typed facts, `FactSet`, typed fact errors, generic `Get`
- `finding` package: five result states, severity weights, evidence,
  remediation, stable fingerprints
- `catalog` package: check registry, evaluation runner with required-fact
  gating and panic isolation
- sshd collector with `Include` resolution, `Match` scope tracking and
  first-value-wins precedence
- SSHD-0002 (root login over SSH disabled) — reference check, 9 fixtures
- `schema/findings-v1.schema.json` and `schema/bundle-v1.schema.json`
- `make verify`: formatting, vet, tests, and architectural invariant gates
- `tools/fixturegate`: mechanises the rule that every check carries PASS and
  FAIL fixtures, parsing check IDs and test tables with `go/ast` rather than
  regular expressions
- `bundle` package: zstd-compressed `.plb` archives per `DATA-MODEL.md` §6,
  with per-member sha256 verified before anything is parsed. An unregistered
  fact ID — or a known ID at an unknown `fact_version` — is preserved as opaque
  bytes, so an old binary opens a newer bundle instead of failing
- `collect` registry and runner: dependency DAG with cycles rejected at init,
  independent branches concurrent, `Expensive` collectors serialised to one at
  a time, per-collector budgets, and panic isolation. A collector that hangs,
  panics or lacks a privilege it declared produces a recorded fact error rather
  than a hung or silently incomplete scan
- `sanitize` package: C0, C1, DEL and invalid-UTF-8 bytes are made visible
  rather than deleted, and length caps are spent on output so a hostile 10 MB
  source costs no more than a benign one (`THREAT-MODEL.md` T-03)
- Content-addressed evidence: raw sources stored at `evidence/<sha256>.blob`,
  deduplicated by construction, cited by digest from `finding.Evidence.SHA256`
- `score` package: posture and coverage, read through accessors that cannot be
  used without acknowledging that either may be *undefined*
- `render/json`: `findings/v1`, deterministic and schema-validated in CI
- `cmd/plumbline`: `collect`, `eval`, `scan`, `version`, `--redact`, and the
  exit-code ladder as a single tested function
- Offline proof: a full scan in a network namespace with no interfaces
- Hostile-input corpus: FIFO, 40-deep symlink chain, symlink to `/etc/shadow`,
  100 MB file, ANSI filenames, cyclic include, directory-as-file, zero-byte
  config, CRLF
- CI: build for amd64 and arm64, `make verify`, race, schema validation,
  offline, hostile corpus, and a scan on ubuntu:24.04, debian:13,
  fedora:latest and alpine:3.20

### Changed
- `fact.SSHDConfig` carries `Digests`, mapping each file read to its sha256, so
  a finding can cite evidence an auditor can verify. `FactVersion` deliberately
  **not** bumped: the field is optional and no check is required to consider it
  (ADR-0009, `DATA-MODEL.md` §2.2)
- `summary.posture` and `summary.coverage` in `findings-v1` accept `null`.
  `null` means undefined, which is **not** zero: a consumer that coerces it
  reports a host in perfect failure when nobody looked at it (ADR-0010)
- `go.mod` requires Go 1.23

### Security
- Bundles and reports are written `0600`, with the mode applied after opening
  so that overwriting a world-readable file does not inherit its permissions
- `--redact` removes the hostname at collection time, so the identity is never
  written to disk
- Working-directory configuration is ignored when euid is 0 unless passed with
  `--config` (`THREAT-MODEL.md` T-07)
- Bundle reads are capped, integrity-checked before parsing, and never
  extracted to disk (`THREAT-MODEL.md` T-09)

### Dependencies
- `github.com/klauspost/compress` (zstd; pure Go, no cgo — ADR-0008)
- `github.com/spf13/cobra` (command surface)
- `github.com/santhosh-tekuri/jsonschema/v5` (tests only; never linked into the
  binary)

### Check corrections
None. SSHD-0002 is new in this release.

### Check corrections
None beyond the SSHD-0002 correction recorded above. Every other check in this
release is new.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/

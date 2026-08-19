# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog];
versioning follows `docs/VERSIONING.md`, which governs four separate version
numbers (tool, catalog, schema, vulnerability data).

Every release that alters a check's verdict logic MUST carry a
`### Check corrections` section naming the check, the old behaviour, the new
behaviour, and who is affected. A user's posture score changing without an
explanation in this file is a defect.

## [Unreleased]

Nothing yet. `docs/ROADMAP.md` v0.3 is next: the terminal and SARIF renderers,
`diff`, suppressions and `doctor` — none of which changes a fact or a check.

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

# FIXTURES — Plumbline

A fixture is a fake system that a check can be evaluated against. Fixtures are
why ~110 checks are testable without ~1000 virtual machines, and they are the
highest-value asset in this repository. A check without fixtures is unverified,
and an unverified security check is worse than no check at all — it produces
confident output nobody has ever confirmed.

**Implementation:** `internal/system/fake`
**Location:** `testdata/fixtures/<name>/`

---

## 1. Anatomy

```
testdata/fixtures/sshd-include/
├── _plumbline/
│   └── fixture.json           the manifest — not part of the simulated system
├── etc/ssh/sshd_config
└── etc/ssh/sshd_config.d/
    └── 50-cloud-init.conf
```

The tree *is* the filesystem. A path the check asks for as
`/etc/ssh/sshd_config` resolves to `<fixture>/etc/ssh/sshd_config`. Anything not
present in the tree does not exist on the simulated host, which is exactly what
you want for `NOT_APPLICABLE` cases.

`_plumbline/` is invisible to the simulated system: `ReadDir("/")` filters it
out. It carries everything a filesystem tree cannot express.

---

## 2. The manifest

`_plumbline/fixture.json`. Every field is optional; a tree with no manifest is
a valid fixture and is the common case.

```json
{
  "description": "Unprivileged run: config exists but is unreadable",
  "euid": 1000,
  "now": "2026-01-01T00:00:00Z",
  "unreadable": ["/etc/ssh/sshd_config"],
  "missing": ["/etc/shadow"],
  "modes": { "/etc/shadow": "0640", "/tmp": "1777", "/usr/bin/passwd": "4755" },
  "owners": { "/etc/shadow": "0:42" },
  "inodes": { "/srv/data": "64:900", "/mnt/bind": "64:900" },
  "exec": {
    "systemctl is-active sshd": { "stdout": "active\n", "exit_code": 0 },
    "sshd -t": { "stderr": "", "exit_code": 0 }
  }
}
```

| Field | Purpose |
|---|---|
| `description` | Shown in test failure output. Write it as the scenario, not the filename. |
| `euid` | What the scan believes it is running as. Default 0. |
| `now` | Frozen clock, RFC3339. Default `2026-01-01T00:00:00Z`. |
| `unreadable` | Paths that exist but fail with `ErrPermission`. **This is how an unprivileged run is simulated** — you cannot commit a file to git that root can read and you cannot. |
| `missing` | Paths present in the tree that must behave as absent. Useful for reusing one tree across several scenarios. |
| `modes` | Octal mode overrides. **Required for any permission check**, because git preserves only the execute bit. Also sets setuid, setgid, sticky and the file type — see §2.1. |
| `owners` | `"uid:gid"` overrides. Git records neither. |
| `inodes` | `"dev:ino"` identity overrides. How a fixture describes a bind mount — see §2.2. |
| `exec` | Canned command output, keyed by space-joined argv. |

An `Exec` call with no matching entry is a **test failure**, not an empty
result. Silently returning nothing would let a collector appear to work while
never actually running the command it depends on.

### 2.1 `modes` is the full Unix mode, not just the permission bits

Write the octal number `stat -c %a` would print, with the type prefix when the
inode is not a regular file:

| Fixture value | Means |
|---|---|
| `"0644"` | permissions only; whatever the inode already is, it stays |
| `"4755"` | setuid, `rwxr-xr-x` — a SUID binary |
| `"2755"` | setgid |
| `"1777"` | sticky, world-writable — `/tmp` |
| `"010600"` | a FIFO |
| `"020600"` | a character device |
| `"060600"` | a block device |
| `"0140660"` | a unix socket |

The translation is deliberate, not a cast: Go encodes setuid and the file type
in high bits of its own choosing, so a naive `fs.FileMode(0o4755)` is `0o755`
with a meaningless bit set. A fixture asking for a SUID binary would get an
ordinary one and the SUID check written against it would pass for the wrong
reason — the exact class of quiet wrongness fixtures exist to catch.

A value with no type prefix leaves the type alone. `"0644"` on a directory
keeps it a directory.

The type prefixes exist because a FIFO, a socket and a device node cannot be
committed to git, and `mknod` needs root so the tree cannot be generated at
test time either. The shared filesystem walker must never open any of them —
opening an unprivileged user's FIFO as root hangs the scanner forever — and
that rule needs a test. See ADR-0013.

### 2.2 `inodes` describes what a directory tree cannot

`"dev:ino"` per path. Two paths given one identity **are** a bind mount, which
is the only way to write down a tree that contains itself:

```json
"inodes": {
  "/srv/data": "64:900",
  "/srv/data/self": "64:900"
}
```

Without this, the walker's cycle detection could not be tested at all: real
values from the fixture tree make every path genuinely distinct (which is
right), no Linux filesystem permits hardlinking a directory, and creating a
real bind mount needs root and a mount namespace.

Two rules when using it:

- **`"0:0"` is rejected.** Zero means "not recorded" on the seam (ADR-0012), so
  accepting it would silently switch cycle detection off for that path.
- **Override the whole device, not one directory.** The walker does not cross
  filesystem boundaries by default, and it decides what a boundary is by
  comparing `Dev` against the root's. Giving one directory a different `Dev`
  therefore reads as a separate filesystem and the walk correctly declines to
  enter it. If a fixture is describing a bind mount, give every path in the
  tree the same device — or, if it is describing a *second filesystem*, give
  only that subtree a different one, which is how `fswalk-mounts` tests the
  boundary rule.

---

## 3. Naming

`<module>-<scenario>`, lowercase, hyphenated:

```
sshd-hardened              the good case
sshd-permit-yes            the specific bad case
sshd-default               keyword absent, built-in default applies
sshd-include               value arrives via a drop-in
sshd-match-trap            the value exists but is Match-scoped
sshd-absent                subject not installed → NOT_APPLICABLE
sshd-unreadable            permission denied → UNKNOWN
sshd-unresolved-include    ambiguous state → UNKNOWN
sshd-bad-value             unparseable → UNKNOWN

kernel-hardened            the good case; running and configured agree
kernel-weak                every parameter at its insecure value
kernel-partial             the middling values: neither best nor worst
kernel-absent              parameter not in this kernel → NOT_APPLICABLE
kernel-denied              exists, permission denied → UNKNOWN
kernel-drift               file hardened, host never rebooted
kernel-conflict            two drop-ins disagree → UNKNOWN
kernel-unparseable         value is not the documented integer → UNKNOWN
kernel-loopback-only       no non-loopback interface → NOT_APPLICABLE

users-clean                the good case
users-uid0                 a second account holds uid 0
users-shells               system accounts that can open a session
users-nopassword           empty password fields beside locked ones
users-weakhash             MD5 and DES hashes
users-duplicates           shared uid and shadowed name
users-nis                  directory imports → the list is not the whole list
users-malformed            unparseable lines in both databases
users-locked-only          no stored hash to assess → NOT_APPLICABLE
users-unprivileged         /etc/shadow refused → UNKNOWN, the rest still answer
```

Name the *scenario*, never the expected result. `sshd-pass` becomes a lie the
moment a check's threshold changes.

`kernel-partial` earns its place: a module whose fixtures only cover the best
and worst values never tests the middle, and the middle is where a check
returns a plausible verdict with the wrong severity. `fs.suid_dumpable` at 2 is
a real exposure and a smaller one than at 1, and only a fixture holding 2
proves the check says so.

`users-unprivileged` is the same idea applied to privilege rather than value.
It is the only fixture in the corpus where one file is refused and others are
not, and it is what proves the USERS collector degrades **per file** instead of
failing as a unit. A module whose fixtures are all readable never tests the
path every unprivileged run in production will take.

`users-clean` deserves a note too: its non-root accounts are **locked**, not
empty. A lock token refuses every password and an empty field accepts every
password, so a fixture that used one where it meant the other would let a check
pass for exactly the wrong reason.

---

## 4. Required coverage

Every check needs at minimum:

- one fixture yielding **PASS**
- one fixture yielding **FAIL**

And, wherever the check can reach them:

- **NOT_APPLICABLE** — subject not installed
- **UNKNOWN** — at least the permission case, plus any ambiguity the check
  handles specially

CI enforces the first two. The reference check `SSHD-0002` has nine fixtures
covering all five states, which is the standard to aim at for anything
security-significant.

### 4.1 The ones people forget

These are where real bugs live, and every one of them is represented in the
SSHD-0002 corpus:

| Scenario | Why it matters |
|---|---|
| **Keyword absent** | Does the check know the daemon's built-in default, or does it assume absence means safe? |
| **Value in a drop-in** | Tools that read only the main config file get the opposite verdict. |
| **Match / conditional scope** | A value that is plainly visible in the file but does not govern the global config. |
| **Unreadable** | Unprivileged runs must produce UNKNOWN, never PASS. |
| **Unresolvable include** | The value might exist somewhere you could not see. UNKNOWN, not the default. |
| **Invalid value** | The daemon would refuse to start, so the file is not the running config. |
| **Duplicate keys** | Which one wins? Encode the daemon's actual precedence. |
| **CRLF line endings** | Configs edited on Windows. One line of parser code, one class of bug. |
| **Comment on the value line** | `Port 22 # default` — is the value `22` or `22 # default`? |

### 4.2 What is *not* a committed fixture

Two kinds of test input deliberately do not live in `testdata/fixtures/`.

**Hostile input is generated at test time.** A FIFO, a 40-deep symlink chain, a
symlink to `/etc/shadow` and a 100 MB file are not file contents, and git cannot
carry them. They are built in a temporary directory by
`internal/system/live/hostile_test.go` and
`internal/collect/collectors/sshd/hostile_test.go`, which has the side benefit
that the tests exercise a real filesystem rather than a recording of one. The
CRLF, zero-byte and cyclic-include cases live there too, because they test the
parser against a generated tree rather than a scenario worth naming.

**`cli-host` is a fixture for the CLI, not for a check.** It carries
`/etc/hostname` and `/etc/os-release` so that `--redact` has an identity to
remove and so the container matrix has a scan target whose verdict is identical
on every distribution. No check reads it.

---

## 5. Recording a fixture from a real host

Hand-authored fixtures test what you imagined. Recorded ones test what
actually exists. Both are needed, and recorded ones catch distro divergence
that nobody would think to invent.

```bash
# from v0.2, once `collect` exists
plumbline collect --root / -o ubuntu-2404.plb
plumbline fixture from-bundle ubuntu-2404.plb -o testdata/fixtures/ubuntu-2404-stock
```

Rules for recorded fixtures:

1. **Redact before committing.** No real hostnames, no real usernames beyond
   the distro defaults, no key material, no IP addresses. `--redact` handles
   the common cases; read the diff before committing regardless.
2. **Trim to what is used.** A whole `/etc` is unreviewable in a pull request.
   Keep the files the checks under test actually read.
3. **Record the provenance** in `description`: distro, version, and whether the
   host was stock or hardened.
4. **Never commit anything from a production host.**

---

## 6. Golden bundles

A tier above fixtures. A golden bundle is a recorded bundle plus the complete
expected findings JSON. Any catalog change immediately shows its blast radius
as a findings diff across every recorded distro.

```
testdata/bundles/
├── ubuntu-2404-stock.plb
├── ubuntu-2404-stock.expected.json
├── debian-13-hardened.plb
└── debian-13-hardened.expected.json
```

The workflow: change a check → `make golden-diff` → read what moved. A change
that alters findings on eight distros when you expected one is telling you
something before your users do.

**Regenerating expected output is a reviewed act, not a convenience.**
`make golden-update` exists, and a PR that runs it without explaining every
changed line in the description gets rejected. This is where a "quick fix"
silently rewrites the definition of PASS for the whole corpus.

---

## 7. Anti-patterns

| Do not | Because |
|---|---|
| Mock the check's inputs directly in Go | You skip the collector, where most bugs actually live. Tests go through the real collector against a fixture tree. |
| Share one fixture across unrelated checks | It grows to satisfy everyone and stops representing any real system. |
| Encode the expected result in the fixture name | The name becomes wrong when a threshold changes. |
| Commit a fixture with real credentials, even fake-looking ones | Secret scanners fire, and you will not enjoy the conversation. |
| Add a fixture without a `description` | Failure output becomes a path with no context, six months later, at 23:00. |
| Use `unreadable` to paper over a collector bug | UNKNOWN is for genuine ignorance, not for scenarios you did not want to handle. |

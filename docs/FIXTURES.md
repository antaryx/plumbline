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
  "modes": { "/etc/shadow": "0640", "/tmp": "1777" },
  "owners": { "/etc/shadow": "0:42" },
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
| `modes` | Octal mode overrides. **Required for any permission check**, because git preserves only the execute bit. |
| `owners` | `"uid:gid"` overrides. Git records neither. |
| `exec` | Canned command output, keyed by space-joined argv. |

An `Exec` call with no matching entry is a **test failure**, not an empty
result. Silently returning nothing would let a collector appear to work while
never actually running the command it depends on.

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
```

Name the *scenario*, never the expected result. `sshd-pass` becomes a lie the
moment a check's threshold changes.

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

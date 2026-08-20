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
  "unstattable": ["/etc/cron.d"],
  "missing": ["/etc/shadow"],
  "modes": { "/etc/shadow": "0640", "/tmp": "1777", "/usr/bin/passwd": "4755" },
  "owners": { "/etc/shadow": "0:42" },
  "symlinks": { "/etc/systemd/system/sshd.service": "/dev/null" },
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
| `unreadable` | Paths whose **contents** fail with `ErrPermission`; `Stat` still succeeds. **This is how an unprivileged run is simulated** — you cannot commit a file to git that root can read and you cannot. |
| `unstattable` | Paths whose **metadata** fails with `ErrPermission`. Distinct from `unreadable` — see §2.3. |
| `missing` | Paths present in the tree that must behave as absent. Useful for reusing one tree across several scenarios. |
| `modes` | Octal mode overrides. **Required for any permission check**, because git preserves only the execute bit. Also sets setuid, setgid, sticky and the file type — see §2.1. |
| `owners` | `"uid:gid"` overrides. Git records neither. |
| `symlinks` | Declares a path to be a symlink and gives its target verbatim. **Use this rather than committing a real link whenever the target is absolute** — see §2.4. |
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

### 2.3 `unstattable` is not `unreadable`

They look interchangeable and are not, and the difference decides a verdict.

`unreadable` defeats `ReadFile` and `ReadDir` while leaving `Stat` working.
That is what an ordinary permission problem actually looks like: `/etc/shadow`
at mode 0640 owned `root:shadow` cannot be read by an unprivileged user, but
`stat /etc/shadow` succeeds for anyone. Its mode, its owner and its size are
public.

`unstattable` defeats `Stat` as well, which on a real host is caused by
something different: a **parent directory** that refuses traversal. When that
happens nothing about the path can be observed — not the mode, not the owner,
not whether it exists at all.

```json
"unstattable": ["/etc/cron.d", "/etc/cron.allow"]
```

The two keys are separate because folding them together would have made every
unreadable-file fixture also claim its ownership was unknown, which is not what
such a host looks like — and it would have made the CRON module's
`UNKNOWN(insufficient_privileges)` branch untestable, since every path it reads
is metadata rather than contents. `cron-denied` is the fixture that uses it.
See ADR-0016.

### 2.4 `symlinks` keeps an absolute link target inside the fixture

Git stores symlinks natively, so unlike `inodes` this is not a capability the
format lacks. It is a **containment rule**, and it has one trigger: the target
is an absolute path.

```json
"symlinks": {
  "/etc/systemd/system/multi-user.target.wants/sshd.service":
      "/usr/lib/systemd/system/sshd.service",
  "/etc/systemd/system/telnet.socket": "/dev/null"
}
```

A real symlink committed with that target resolves against **the developer's
root, not the fixture's**. `/var/tmp/jobs` in `cron-symlink` gets away with it
because nothing on a developer's machine is there and nothing dereferences it.
`/usr/lib/systemd/system/sshd.service` is on every Linux workstation, and
anything that follows the link — `find -L`, `tar -h`, an editor indexing the
tree, a future tool that walks `testdata/` — reads the real host through it. A
fixture that can read the real host has stopped being a fixture. Git for
Windows compounds the problem: with `core.symlinks` off the link is checked out
as a text file containing its target, and the scenario silently becomes a
different one.

Declaring the link in the manifest creates no real link, so nothing can follow
it, and `Readlink` hands the string back exactly as written.

Three rules:

- **The tree still needs a placeholder file at the path.** An empty file is
  fine. `Stat` and `Readlink` both consult the tree before the manifest, so a
  path misspelled here reports `ErrNotExist` from both rather than existing
  only as a link to nowhere.
- **A `modes` entry with the `0120000` prefix is not enough on its own** and is
  rejected at load. It would make `Stat` report a symlink whose `Readlink` says
  it is not one — two seam methods contradicting each other about one inode,
  which no real filesystem does. A `symlinks` entry sets the type bit for you;
  add a `modes` entry only if the permission bits matter, which for a symlink
  they do not (the kernel ignores them; `lstat` reports `lrwxrwxrwx`, and that
  is what a declared link reports by default).
- **An empty target is rejected.** `readlink` can never return `""` for a real
  link, so honouring it would hand a check a value no host can produce.

A **relative** target is legal, needs no manifest entry, and is what
`cli-host` uses. That fixture is evaluated through the *live* seam — `scan
--root testdata/fixtures/cli-host` — where there is no manifest to read, so its
systemd links are real ones written relative to their own directory. They
resolve inside the fixture tree no matter who follows them, which is the same
containment property reached the other way. Resolving a relative target is the
*caller's* job, against the link's own directory and back through the seam, so
that `--root` still applies.

---

## 3. Naming

`<module>-<scenario>`, lowercase, hyphenated:

```
sshd-hardened              the good case — every check's secure value
sshd-permit-yes            the bad case — every check's insecure value
sshd-default               keyword absent, built-in default applies
sshd-include               value arrives via a drop-in
sshd-match-trap            the value exists but is Match-scoped
sshd-match-loosened        the secure global is overridden inside a Match block
sshd-crypto-relative       algorithm lists use the +, - and ^ forms
sshd-absent                subject not installed → NOT_APPLICABLE
sshd-unreadable            permission denied → UNKNOWN
sshd-unresolved-include    ambiguous state → UNKNOWN
sshd-bad-value             unparseable → UNKNOWN

cron-compliant             the good case
cron-writable              the escalation, reached by mode and by ownership
cron-vendor                stock distribution modes; nothing here is a mistake
cron-denylist              access governed by cron.deny, which fails open
cron-absent                no cron installed → NOT_APPLICABLE
cron-denied                metadata refused → UNKNOWN
cron-symlink               a redirection out of /etc

filesys-clean              the good case; every FILESYS check passes
filesys-suid-writable      a setuid helper at 4775 — a root shell with a wait
filesys-suid-outside       setuid shells in /home and /var/tmp, both 4755
filesys-world-writable     a 0666 config and a 0777 script, plus a symlink
filesys-sticky             a 0777 drop point with no sticky bit
filesys-system-dir         /etc/cron.d world-writable AND sticky
filesys-device             a block node in /var/tmp with /dev/sda's numbers
filesys-mounts-weak        /tmp not separate, /dev/shm without noexec, bare /home
filesys-mounts-unknown     the mount table is unreadable → UNKNOWN
filesys-truncated          nothing wrong; driven with a tiny inode budget
filesys-unowned            uid 4242 owns a tree no account claims → FAIL
filesys-unowned-directory  the same disk, with nsswitch routing to SSSD → UNKNOWN

auth-rhel                  the good case, Red Hat layout, stacks reached by symlink
auth-debian                the same host in the common-* layout — verdicts must match
auth-weak                  every AUTH check fails
auth-optional              pwquality present, correct, and 'optional' — so inert
auth-minlen                minlen 8 and four *positive* credits, which require nothing
auth-unresolved            an @include naming a file that is not there → UNKNOWN
auth-denied                /etc/pam.d refuses traversal → UNKNOWN
auth-absent                no PAM at all → NOT_APPLICABLE

network-nftables           default-deny nftables; the policy is on its own line
network-ufw                the same host via ufw, whose policy lives in a second file
network-accept             a deny list: default accept with a few blocks
network-both               ufw and firewalld, each individually sound
network-empty              Debian's stock comments-only nftables.conf
network-none               no firewall configuration of any kind
network-denied             the one file present is unreadable → UNKNOWN

services-compliant         the good case; also the usr-merge and relative-link shapes
services-cleartext         telnet and rsh enabled through socket activation
services-masked            enabled AND masked — the mask wins
services-discovery         a server image carrying a desktop package set
services-notime            no time daemon enabled
services-twoclocks         two time daemons competing for the clock
services-dangling          an enablement symlink to a unit file that is gone
services-unresolved        a link whose target cannot be stat'ed → UNKNOWN
services-writable          the escalation, reached by mode and by ownership
services-absent            not a systemd host → NOT_APPLICABLE
services-denied            /etc/systemd/system refused → UNKNOWN

logging-compliant          both daemons correct, RainerScript throughout
logging-legacy             the same host in legacy syntax — verdicts must match
logging-weak               every logging check fails
logging-nodefault          stock host; every verdict comes from a built-in default
logging-rsyslog-absent     journald only → the rsyslog checks step aside
logging-absent             neither daemon → NOT_APPLICABLE
logging-unresolved-include include matched nothing → UNKNOWN
logging-unreadable         both configurations refused → UNKNOWN
logging-dropin-override    a systemd drop-in overrides the main file

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
users-gid0                 group 0 reached three different ways
users-aging                password aging in four states, one of them empty
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

The SSHD module leans on its fixtures differently from the others: five of them
are asserted **across the whole module** rather than per check.
`sshd-hardened` must PASS every check, `sshd-permit-yes` must FAIL every check,
`sshd-absent` must be NOT_APPLICABLE everywhere, `sshd-unresolved-include` must
be UNKNOWN(`ambiguous_system_state`) everywhere, and `sshd-unreadable` must be
UNKNOWN(`insufficient_privileges`) everywhere. A check added without a value in
the first two fails a test immediately, which is a much better error than
discovering months later that the "clean host" fixture never satisfied it.

`sshd-match-trap` and `sshd-match-loosened` are the same trap from both sides.
In the first, the only secure value is inside a `Match` block and must not count
toward the global verdict; in the second, the global value is secure and a
`Match` block reintroduces the insecure one. A tool that got either wrong would
report a permissive host as compliant. Note that the second fixture's `Match`
block contains **only keywords `sshd_config` actually permits there** — a block
containing `StrictModes` or `Ciphers` would be a configuration sshd refuses to
load, which would make it a fixture for a state that cannot exist.

`sshd-crypto-relative` exists for the one asymmetry in the module. `Ciphers`,
`MACs` and `KexAlgorithms` may be written relative to the compiled-in default
(`+` appends, `-` removes, `^` places at the head), and the effective list is
then unknowable from configuration alone — except that a `+` or `^` which *adds*
a broken algorithm enables it whatever the base list holds. The fixture uses one
of each form so that the FAIL and the two UNKNOWNs are all exercised.

`logging-compliant` and `logging-legacy` are one fixture written twice, and the
pair is the point. They describe the same host — the same file mode, the same
TCP destination, the same journald settings — one entirely in RainerScript and
one entirely in the sysklogd and `$`-directive syntaxes rsyslog inherited. Both
appear in the wild, frequently in the same file, and a parser that understood
only one would report a correctly-forwarding host as not forwarding. A test
asserts every check reaches the *same verdict* over both, which is a stronger
statement than either fixture could make alone.

`logging-dropin-override` exists because systemd's precedence is the reverse of
`sshd_config`'s: the last occurrence wins, so a drop-in overrides the main file.
The fixture sets `Storage=persistent` in `journald.conf` and `volatile` in a
drop-in, and the check must report volatile and cite the overridden line.

`cron-vendor` earns its place the way `kernel-partial` does. It holds the modes
Debian, Ubuntu, RHEL and Fedora all ship — `/etc/crontab` at 0644, the drop-in
directories at 0755 — none of which is a mistake. It is what proves the two
escalation checks do not fire on a vendor default while the disclosure check
does, at LOW, and it is what would catch a future tightening of CRON-0001 or
CRON-0002 turning every unhardened host into two HIGH findings.

`cron-denied` is the only fixture using `unstattable` (§2.3), and it is the
only way to reach the state where a path's owner and mode are unknowable. Every
CRON check must return UNKNOWN over it rather than reporting on the paths it
happened to reach.

`filesys-truncated` is the module's most important fixture and the only one
that violates nothing. It is driven **twice**: once with a normal walk, where
every inode check must return PASS, and once with `MaxInodes: 4`, where every
one of them must return `UNKNOWN(source_truncated)` instead. Both halves are
needed — without the first, a check that returned UNKNOWN unconditionally would
satisfy the second while being useless. This is the runbook's WP-23 rule
mechanised: *a truncated walk can invalidate a negative result, never a
positive one.*

`filesys-unowned` and `filesys-unowned-directory` are a matched pair, and the
pair *is* the test. Their ownership is byte-for-byte identical: `/var/lib/oldapp`
is owned by uid 4242 and gid 4242, and `/home/alice/notes.txt` carries the
stray gid alone so the uid and gid arms of FILESYS-0010 are exercised
independently rather than always together. The **only** difference between the
two fixtures is one word in `/etc/nsswitch.conf` — `passwd: files` against
`passwd: files sss`. The first must FAIL and the second must return
UNKNOWN(`ambiguous_system_state`), because a check that reads `/etc/passwd`
alone would report every Active Directory user's home directory as unowned. Two
fixtures rather than one, because a single fixture could show that the check
handles one case and could not show that it distinguishes them.

Both use the `owners` manifest key, which is the only way a fixture can state a
uid at all: git records ownership no more faithfully than it records mode.

`filesys-suid-writable` and `filesys-suid-outside` exist as a pair because they
separate two properties that look like one finding. In the first, a setuid
binary under `/opt` is group-writable: FILESYS-0001 fails and FILESYS-0002
passes, because `/opt` is a directory a package manager installs into. In the
second, setuid shells sit in `/home/alice` and `/var/tmp` at mode 4755 — owned
by root, writable by nobody else — so FILESYS-0001 passes and only their
*location* gives them away. Neither check can be written as a name allowlist,
and the pair is what proves the two rules are independent.

`filesys-system-dir` is the same trick for directories. `/etc/cron.d` is
world-writable **and** sticky, so FILESYS-0004 passes over it. The sticky bit
restricts deleting existing entries and says nothing about creating new ones,
and creating one file in `/etc/cron.d` is root on a schedule — which is
FILESYS-0005's entire reason for existing separately.

`filesys-world-writable` carries a symlink deliberately. A symlink's own mode is
`lrwxrwxrwx` and the kernel ignores it, so an interest that did not exclude
symlinks would report every one on a host as world-writable and bury the two
real findings among thousands of false ones.

`filesys-mounts-weak` models a host that *looks* fine: `/dev/shm` has `nosuid`
and `nodev` but not `noexec`, which is the distribution default on many systems.
A fixture where nothing was configured would not have tested the case that
actually occurs.

`auth-rhel` and `auth-debian` are one hardened host written twice, and the pair
is the point. Fourteen-character minimum, faillock, history of five, no
`nullok`, strong hashing — one keeps its rules in `system-auth` and
`password-auth` reached through symlinks to authselect's generated files, the
other in `common-*` pulled in with `@include`. A collector that understood one
family would report "no password quality is enforced" on every host of the
other, which is a wrong verdict produced entirely by packaging. A test asserts
every check reaches the **same verdict** over both.

`auth-rhel` is also the only fixture whose primary files are symlinks that must
be *followed to be read*. The seam's `ReadFile` refuses a symlink with
`O_NOFOLLOW`, so without explicit resolution the AUTH module would report
UNKNOWN across the entire Red Hat family. It uses the manifest's `symlinks` key
(§2.4) rather than real links, because the targets are absolute.

`auth-debian` carries the bracketed control form —
`password [success=1 default=ignore] pam_unix.so … yescrypt` — which a
`strings.Fields` split reads as control `[success=1` and module
`default=ignore]`. A naive parser then finds no `pam_unix.so` at all and
reports UNKNOWN on a stock Debian host: a wrong answer that looks like caution.

`auth-optional` is one line different from a working host. `pam_pwquality` is
present, correctly placed and correctly parameterised, and marked `optional` —
so PAM runs it, it decides the password is unacceptable, and the password is set
anyway. It exists because that line reads to a human exactly like one that
works.

`network-empty` earns its place the way `cron-vendor` does: it holds Debian's
stock `/etc/nftables.conf`, the file the package installs whether or not
anybody has written a rule in it. Nothing but comments. It is what proves
NETWORK-0001 counts statements rather than testing for the file's existence —
treating presence as protection would report every host with that package
installed as firewalled, by a dependency somebody else chose.

`network-both` is deliberately a fixture where the *individual* configurations
are both sound. ufw and firewalld are each enabled with a deny default, so
NETWORK-0001 and 0002 pass and only 0003 fails. That is what makes the conflict
hard to notice on a real host, and a fixture where one of them was also
misconfigured would not have tested it.

`services-compliant` carries two shapes a naive fixture would not have, and
both are load-bearing. Its `/lib` is the **usr-merge symlink**, so
`/lib/systemd/system` and `/usr/lib/systemd/system` are one directory — the
collector proves they are the same by inode rather than assuming a layout,
because assuming either one double-counts every vendor unit on half the
distributions in service. And `dbus.service` is enabled through a real
**relative** symlink, which is what an administrator running `ln -s` produces
and which names a completely different file if it is read as absolute.

`services-masked` exists for one case that reading the `.wants` directory alone
gets wrong. `telnet.socket` has both an enablement symlink and a mask, and
systemd will not start it: a masked unit cannot be started by anything,
including a unit that `Requires=` it. SERVICES-0001 must therefore **pass** over
it. Getting this backwards produces a FAIL about a service that cannot run,
which sends somebody to disable something already off while the real findings go
unread.

`services-dangling` and `services-unresolved` are two fixtures for what looks
like one situation. "The link's target is not there" is a FAIL; "we were not
allowed to look at the target" is UNKNOWN. A single fixture could not have shown
that the collector keeps them apart, and a single boolean in the fact would have
collapsed them into a guess — the same distinction `cron-denied` draws for
metadata.

`users-clean` deserves a note too: its non-root accounts are **locked**, not
empty. A lock token refuses every password and an empty field accepts every
password, so a fixture that used one where it meant the other would let a check
pass for exactly the wrong reason. It also carries `operator:x:11:0`, a system
account in group 0 — the Red Hat convention — so that the *clean* host is what
proves USERS-0007 does not fail a distribution default.

`users-gid0` is deliberately a triple violation: root outside group 0, an
ordinary account inside it, and a supplementary member listed on the group line.
USERS-0007 makes three separate propositions, and three fixtures each proving
one would not prove the check reports all three when all three are true — which
is the case where an operator fixes what they were told about and stays exposed
by the rest.

`users-aging` carries the pointer distinction that `internal/fact` exists to
preserve. `alice`'s minimum and maximum fields are **empty**, not zero: an empty
maximum means the password never expires while a maximum of 0 would mean it
expires daily. A fixture with `0` where it meant empty would let a parser that
conflated the two look correct. `bob` holds minimum 30 against maximum 20, the
state in which an account is required to change its password and forbidden from
doing so; and `daemon` carries the same unbounded defaults as `root` while
locked, which is what proves the aging checks gate on `Authenticates()` rather
than iterating every line.

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

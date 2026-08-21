# ubuntu-2404-hardened — a stock image with the services a real server runs and
# a hardening pass over their configuration.
#
# Three of the four bundles in this corpus are stock base images, and a stock
# base image has no sshd, no syslog daemon and no cron. That leaves the SSHD
# module — nineteen checks, the largest in the catalog — and all of LOGGING
# correctly NOT_APPLICABLE, and a golden bundle that never evaluates a check
# cannot notice when that check's verdict moves. This bundle exists to cover
# them.
#
# Every change below was written from the remediation this tool prints for the
# check it addresses: `plumbline explain AUTH-0003` says which three faillock
# rules are needed and in what order, and that is what is here. That is a
# deliberate second use for this file — if the remediation is wrong, following
# it does not produce a PASS, and this bundle is where that shows up.
#
# ── what a container cannot harden ──────────────────────────────────────────
#
# The mount table and the running kernel belong to the machine, not the image.
# /tmp and /home cannot be made separate mounts from inside a container
# (FILESYS-0007, FILESYS-0009), and /proc/sys is read-only without --privileged
# so dmesg_restrict and the core-dump pattern cannot be set (KERNEL-0004,
# KERNEL-0014). Those four stay FAIL here and they are *correct* FAILs: this
# host genuinely is in that state. A recipe that ran --privileged to make the
# number prettier would be recording a host nobody has.
#
# KERNEL-0007 is UNKNOWN for a related reason and is the most valuable single
# finding in this corpus. Ubuntu ships /etc/sysctl.d/99-sysctl.conf as a symlink
# to ../sysctl.conf, the live seam opens privileged reads with O_NOFOLLOW and so
# declines to follow it, and the check will not claim the running kernel matches
# its configuration when one configuration file was not among the ones it read.
# A lesser tool reports PASS there. Keeping a golden bundle that reaches UNKNOWN
# is how that behaviour stays load-bearing rather than becoming folklore.

FROM ubuntu:24.04

# ── services ────────────────────────────────────────────────────────────────
# --no-install-recommends because a recommend is a package nobody chose, and
# every package is a file the filesystem checks then have an opinion about.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      openssh-server \
      rsyslog \
      cron \
      libpam-pwquality \
      nftables \
      systemd-timesyncd \
 && rm -rf /var/lib/apt/lists/*

# ── sshd ────────────────────────────────────────────────────────────────────
# A drop-in rather than an edit of sshd_config, which is both what the
# distribution intends and a deliberate exercise of the collector's Include
# resolution: the effective value for every keyword below is only visible to
# something that follows `Include /etc/ssh/sshd_config.d/*.conf` in order.
#
# ClientAliveCountMax is 3 and not 0. The first draft of this file set it to 0
# on the reasoning that fewer probes is stricter, and SSHD-0007 said what that
# actually does: sshd probes every ClientAliveInterval seconds and, with a max
# of 0, never acts on the silence. The interval is set, the setting looks
# present, and there is no timeout at all. This is the recipe earning its keep.
RUN printf '%s\n' \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'PermitEmptyPasswords no' \
    'KbdInteractiveAuthentication no' \
    'X11Forwarding no' \
    'AllowTcpForwarding no' \
    'AllowAgentForwarding no' \
    'PermitUserEnvironment no' \
    'IgnoreRhosts yes' \
    'HostbasedAuthentication no' \
    'StrictModes yes' \
    'UsePAM yes' \
    'MaxAuthTries 3' \
    'MaxSessions 4' \
    'LoginGraceTime 60' \
    'ClientAliveInterval 300' \
    'ClientAliveCountMax 3' \
    'LogLevel VERBOSE' \
    'Banner /etc/issue.net' \
    'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' \
    'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com' \
    'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256' \
    > /etc/ssh/sshd_config.d/99-hardening.conf \
 && chmod 0600 /etc/ssh/sshd_config.d/99-hardening.conf

RUN printf '%s\n' \
    'Authorised users only. All activity is logged and reviewed.' \
    'Disconnect now if you have not been granted access to this system.' \
    > /etc/issue.net

# ── PAM ─────────────────────────────────────────────────────────────────────
# Hand-edited, which `plumbline explain AUTH-0001` is right to warn against on
# a host under configuration management: pam-auth-update regenerates these and
# would overwrite it. In an image built once and never updated there is nothing
# to regenerate, and the alternative — driving a debconf frontend from a
# Dockerfile — records a stack nobody could read afterwards.
#
# nullok is removed rather than left: it is Ubuntu's default and it means an
# account with an empty password field authenticates with an empty password
# (AUTH-0004).
RUN sed -i 's/[[:space:]]nullok//g' /etc/pam.d/common-auth \
 && sed -i '0,/^auth[[:space:]]/s//auth    required                        pam_faillock.so preauth\nauth    /' /etc/pam.d/common-auth \
 && printf '%s\n' 'auth    [default=die]                   pam_faillock.so authfail' >> /etc/pam.d/common-auth \
 && printf '%s\n' 'account required                        pam_faillock.so' >> /etc/pam.d/common-account \
 && sed -i '0,/^password[[:space:]].*pam_unix\.so/s//password        requisite                       pam_pwquality.so retry=3\n&/' /etc/pam.d/common-password \
 && sed -i 's/^\(password[[:space:]].*pam_unix\.so.*\)$/\1 remember=5/' /etc/pam.d/common-password

RUN printf '%s\n' \
    'deny = 5' \
    'unlock_time = 900' \
    'fail_interval = 900' \
    > /etc/security/faillock.conf

RUN printf '%s\n' \
    'minlen = 14' \
    'dcredit = -1' \
    'ucredit = -1' \
    'ocredit = -1' \
    'lcredit = -1' \
    'difok = 4' \
    'enforcing = 1' \
    > /etc/security/pwquality.conf

# ── account policy ──────────────────────────────────────────────────────────
# USERS-0004, USERS-0009 and USERS-0010 ask about accounts that can actually
# authenticate, and a stock image has none — every account is locked, so the
# three are NOT_APPLICABLE and stay uncovered. One ordinary account with a
# password makes them real questions. It is called opsuser rather than the
# obvious "operator" because Ubuntu already ships a *group* of that name and
# useradd refuses; the suffix on the generated password is there because the
# pwquality policy set above is enforcing and a base64 string is not guaranteed
# to carry a digit and a symbol.
#
# The password is generated here and never leaves the container: /etc/shadow is
# not stored as evidence, and the shadow fact records only the *properties* of
# the hash — algorithm, locked, empty — never the hash itself. The golden
# bundle therefore carries "yescrypt, unlocked, aged" and no credential. An
# audit of the recorded bundle for a crypt(3) prefix comes back empty, and
# TestGoldenBundlesCarryNoCredentialMaterial keeps it that way.
RUN sed -i \
      -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' \
      -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' \
      -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' \
      -e 's/^UMASK.*/UMASK\t\t027/' \
      -e 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' \
      /etc/login.defs \
 && useradd --create-home --user-group --shell /bin/bash opsuser \
 && printf 'opsuser:%s\n' "$(head -c 24 /dev/urandom | base64)Aa1-" | chpasswd \
 && chage --maxdays 365 --mindays 1 --warndays 7 opsuser

# ── cron ────────────────────────────────────────────────────────────────────
# An allow list with root in it and nobody else, and a schedule an unprivileged
# account cannot read. CRON-0005 is about the second: knowing when a privileged
# job runs is most of knowing when to be ready for it.
RUN printf 'root\n' > /etc/cron.allow \
 && rm -f /etc/cron.deny \
 && chown root:root /etc/cron.allow /etc/crontab \
 && chmod 0600 /etc/cron.allow /etc/crontab \
 && chown root:root /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
 && chmod 0700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

# ── logging ─────────────────────────────────────────────────────────────────
# Forwarding to a collector the host does not own is the control: an attacker
# with root can rewrite anything on this machine, and the only log they cannot
# reach is the copy that already left. @@ is TCP — a reliable transport, which
# LOGGING-0005 asks about separately, because plain UDP syslog drops under
# exactly the load an incident produces.
RUN printf '%s\n' \
    '$FileCreateMode 0640' \
    '$DirCreateMode 0750' \
    '$umask 0027' \
    '' \
    '# Reliable (TCP) forwarding with an on-disk queue, so a collector that is' \
    '# briefly unreachable delays delivery rather than losing it.' \
    '$ActionQueueType LinkedList' \
    '$ActionQueueFileName remotefwd' \
    '$ActionResumeRetryCount -1' \
    '$ActionQueueSaveOnShutdown on' \
    '*.* @@logs.example.internal:6514' \
    > /etc/rsyslog.d/99-forward.conf

# journald is present on Ubuntu whether or not systemd is PID 1 here, and its
# configuration is a file like any other. Persistent storage so a reboot does
# not take the evidence with it; ForwardToSyslog so rsyslog sees it at all.
RUN mkdir -p /etc/systemd/journald.conf.d \
 && printf '%s\n' \
    '[Journal]' \
    'Storage=persistent' \
    'ForwardToSyslog=yes' \
    'Compress=yes' \
    > /etc/systemd/journald.conf.d/99-hardening.conf

# ── firewall ────────────────────────────────────────────────────────────────
# One firewall, not two. NETWORK-0003 exists because a manager (ufw, firewalld)
# and a saved ruleset on the same host is not redundancy — the manager flushes
# what the ruleset installed, and whoever maintains the file is editing
# something with no effect. ufw is not installed here, deliberately.
RUN printf '%s\n' \
    '#!/usr/sbin/nft -f' \
    'flush ruleset' \
    '' \
    'table inet filter {' \
    '  chain input {' \
    '    type filter hook input priority 0; policy drop;' \
    '    ct state established,related accept' \
    '    iif "lo" accept' \
    '    ct state invalid drop' \
    '    tcp dport 22 ct state new accept' \
    '  }' \
    '  chain forward {' \
    '    type filter hook forward priority 0; policy drop;' \
    '  }' \
    '  chain output {' \
    '    type filter hook output priority 0; policy accept;' \
    '  }' \
    '}' \
    > /etc/nftables.conf \
 && chmod 0600 /etc/nftables.conf

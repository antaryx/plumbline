# debian-13-stock — Debian's base image, untouched.
#
# Debian and Ubuntu share an ancestry and diverge in exactly the places a
# hardening check cares about: PAM defaults, login.defs, and which accounts
# exist. Recording both is what turns "it works on Ubuntu" into a claim with
# evidence behind it.
FROM debian:13

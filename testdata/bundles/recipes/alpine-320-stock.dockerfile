# alpine-320-stock — musl, busybox, OpenRC.
#
# The most valuable bundle in the corpus and the least like the others. Alpine
# has no PAM, no systemd, no shadow(8) defaults worth the name, and a /etc that
# a Debian-shaped parser has no business assuming anything about. Every check
# that reaches NOT_APPLICABLE here is a check that declined to guess, which is
# the property this project is built around.
FROM alpine:3.20

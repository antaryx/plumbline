# ubuntu-2404-stock — the image as it is published, touched by nothing.
#
# This is the baseline every hardening claim is measured against: what an
# operator's fleet looks like on the day it is provisioned and before anyone
# has run a role over it. Nothing is installed and nothing is configured, so
# the SSHD, LOGGING and most CRON modules are correctly NOT_APPLICABLE here —
# ubuntu-2404-hardened is the bundle that covers those.
FROM ubuntu:24.04

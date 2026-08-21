# rocky-9-stock — the enterprise RPM baseline.
#
# The distribution most of this tool's users are actually audited against, and
# the one whose defaults are furthest from Fedora's despite the shared ancestry:
# a RHEL 9 rebuild is conservative where Fedora is current, which is the whole
# point of it. Recording both is what separates "works on the RPM family" from
# "works on the RPM family we happened to test".
FROM rockylinux/rockylinux:9

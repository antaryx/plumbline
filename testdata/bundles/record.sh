#!/usr/bin/env bash
# Re-record the golden bundles in this directory.
#
# A golden bundle is a real collection from a real distribution, committed and
# re-evaluated by TestGolden on every run so that a catalog change which moves a
# verdict on a real host shows up as a diff in review. See docs/FIXTURES.md §6
# and the README beside this script.
#
# Recording is a deliberate act, not part of the build. Nothing in CI runs this,
# `make verify` does not run this, and a PR that changes a .plb without saying
# why should be refused. Run it from the repository root:
#
#     testdata/bundles/record.sh                        # all bundles
#     testdata/bundles/record.sh ubuntu-2404-hardened   # one of them
#     make golden-update                                # regenerate expectations
#
# Then read the diff. Every moved verdict is either a bug you just found or a
# change you meant to make, and the diff is the only place that distinction is
# visible before a user finds it for you.
#
# -- what a bundle is recorded from ------------------------------------------
#
# One recipe per bundle, in recipes/<name>.dockerfile, naming its own base image
# and doing its own setup. The recipe is the provenance: a committed binary
# artifact whose origin is a paragraph of prose is an artifact nobody can check,
# and this way `git log recipes/` answers what changed and why.
#
# -- how it is recorded ------------------------------------------------------
#
# The binary reaches the container as an image layer and the bundle comes back
# out with `docker cp`. Both halves of that are load-bearing and both were
# arrived at the hard way.
#
# Not a bind mount, because a bind mount appears in /proc/self/mountinfo, the
# filesystem walker reads that table into the fs.mounts fact, and the recording
# then carries the absolute path of whoever's working copy produced it. The one
# recording made with -v shipped "/home/<user>/..." inside the mount table.
#
# Not `docker cp` inbound either, because cp preserves the *host* uid and gid on
# the file it writes -- with or without --archive -- so the binary landed inside
# the image owned by uid 1000. On Alpine, whose /etc/passwd has no uid 1000,
# FILESYS-0010 then correctly reported an owner it could not resolve, and the
# golden bundle recorded an UNKNOWN about the recording machine's account. COPY
# writes root:root, which is what a tool installed on a host actually looks like.
#
# The binary is therefore genuinely present in every golden bundle's filesystem
# facts, at /usr/local/bin/plumbline. That is not contamination to apologise
# for: it is what every real scan sees, because a host being audited has the
# auditor installed on it.
#
# The container keeps its default network. Collection makes no network calls --
# the zero-network CI job is what proves that, not this script -- but several
# sysctls are namespaced per interface, and KERNEL-0008 computes reverse-path
# filtering per interface while excluding loopback. Recorded with --network none
# the container has only `lo`, KERNEL-0008 correctly goes NOT_APPLICABLE, and a
# golden bundle silently stops covering it. A bridged container has eth0, so the
# check evaluates. No address reaches the bundle: the sysctl fact holds
# interface *names*, and an audit of every fact and blob for an IPv4 literal
# comes back empty.
#
# --redact because the container's hostname is its ID, and a hostname has to be
# dropped at collection time to be genuinely absent from the artifact.
#
# What is left of the recording machine after that -- the runtime's overlay
# directories and per-container bind paths -- is removed by tools/goldenrecord,
# which prints every substitution it makes.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
out="testdata/bundles"
recipes="$out/recipes"

# Named on the command line, or every recipe there is. The names follow
# docs/FIXTURES.md section 6: distro, version, and whether the host was stock or
# hardened.
if [ "$#" -gt 0 ]; then
    targets=("$@")
else
    targets=()
    for r in "$recipes"/*.dockerfile; do
        targets+=("$(basename "$r" .dockerfile)")
    done
fi

command -v docker >/dev/null || { echo "record.sh needs docker" >&2; exit 1; }

echo "building the recorder binary"
make build

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ctx"
cp dist/plumbline "$work/ctx/plumbline"

for name in "${targets[@]}"; do
    recipe="$recipes/$name.dockerfile"
    [ -f "$recipe" ] || { echo "no recipe at $recipe" >&2; exit 1; }

    echo
    echo "-- $name"

    # The recipe, then the binary. COPY last so that the binary is installed
    # after the recipe's own RUN steps rather than being visible to them.
    cat "$recipe" > "$work/ctx/Dockerfile"
    printf '\nCOPY plumbline /usr/local/bin/plumbline\n' >> "$work/ctx/Dockerfile"

    tag="plumbline-record:$name"
    docker build -q -t "$tag" "$work/ctx" >/dev/null

    # `docker create` then `start -a` rather than `docker run --rm`, because the
    # bundle has to be copied out of the container after it exits, and --rm
    # takes the filesystem away with it.
    cid="$(docker create "$tag" plumbline collect --redact -o /bundle.plb)"

    # collect exits 4 when a collector reported an error. That is a real result
    # about the image, not a failure of the recording, so it is reported and
    # accepted; anything else is a broken recording and stops the script.
    code=0
    docker start -a "$cid" || code=$?
    case "$code" in
        0) ;;
        4) echo "note: $name collected degraded (exit 4); recording it as observed" ;;
        *) docker rm "$cid" >/dev/null; echo "collect failed on $name (exit $code)" >&2; exit 1 ;;
    esac

    docker cp "$cid:/bundle.plb" "$work/$name.plb" >/dev/null
    docker rm "$cid" >/dev/null
    docker rmi "$tag" >/dev/null

    go run ./tools/goldenrecord -in "$work/$name.plb" -out "$out/$name.plb"
    echo "wrote $out/$name.plb ($(stat -c%s "$out/$name.plb") bytes)"
done

echo
echo "recorded ${#targets[@]} bundle(s). Now regenerate the expectations and read the diff:"
echo "    make golden-update && git diff $out"

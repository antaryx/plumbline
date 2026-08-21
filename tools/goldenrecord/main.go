// Command goldenrecord turns a freshly recorded bundle into a golden bundle
// fit to live in the repository forever.
//
// A golden bundle (docs/FIXTURES.md §6) is a real collection from a real
// distribution, committed and re-evaluated in CI so that a catalog change which
// moves a verdict on a real host shows up as a diff in review. That makes it a
// permanent, public artifact, and a permanent public artifact must describe the
// *image that was scanned* and nothing whatever about the *machine that did the
// scanning*.
//
// Recording inside a container leaks the second kind of detail through exactly
// one door: the kernel mount table. /proc/self/mountinfo on a containerised
// root reports the runtime's overlay directories and the per-container bind
// mounts that back /etc/hostname, /etc/hosts and /etc/resolv.conf. Those carry
// the host's storage layout and a fresh container ID on every run. None of it
// is personal data and none of it changes a verdict — no check reads the super
// options of "/" — but it is the recording laptop's fingerprint, and a security
// tool should not ship one.
//
// So this program reads a bundle, rewrites the mount table and the evidence
// blobs those paths appear in, and writes the result. Every substitution it can
// make is listed in scrubs below with the reason for it, and the program prints
// each one it actually applied, because a redaction nobody can see is a
// redaction nobody can check.
//
// Two things it deliberately does not touch:
//
//   - Timestamps, bundle_id and tool.version. They are the provenance of the
//     recording and they identify a commit in this repository, not a person.
//     Normalising them would make the artifact prettier and less true.
//   - The hostname. --redact drops that at collection time, which is where it
//     has to happen; a bundle scrubbed of a hostname afterwards was still
//     written to disk with one.
//
// Run from the repository root, or through testdata/bundles/record.sh, which
// does the docker half:
//
//	go run ./tools/goldenrecord -in recorded.plb -out testdata/bundles/name.plb
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/fact"
)

// scrub is one substitution, its pattern, and the reason it exists. The reason
// is not decoration: this is the list a reviewer reads to decide whether the
// committed bundle can be trusted to say what it claims.
type scrub struct {
	name string
	why  string
	pat  *regexp.Regexp
	with string
}

// placeholder replaces every scrubbed value. One token rather than several,
// because the point is that the value was removed, and inventing a plausible
// substitute would put a fact into the bundle that was never observed.
const placeholder = "[recording-host]"

var scrubs = []scrub{
	{
		name: "overlay directories",
		why: "lowerdir/upperdir/workdir name the container runtime's storage " +
			"tree on the recording machine, including which runtime it was.",
		pat:  regexp.MustCompile(`\b(lowerdir|upperdir|workdir)=[^,\s]*`),
		with: "$1=" + placeholder,
	},
	{
		name: "container-scoped paths",
		why: "the per-container bind mounts behind /etc/hostname, /etc/hosts " +
			"and /etc/resolv.conf are addressed by a container ID that is " +
			"fresh on every run, under a path that is the recording machine's.",
		pat:  regexp.MustCompile(`/[^\s,:]*\b[0-9a-f]{32,}\b[^\s,:]*`),
		with: placeholder,
	},
}

func main() {
	in := flag.String("in", "", "bundle to read (required)")
	out := flag.String("out", "", "golden bundle to write (required)")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: goldenrecord -in recorded.plb -out golden.plb")
		os.Exit(2)
	}
	if err := record(*in, *out); err != nil {
		fmt.Fprintf(os.Stderr, "goldenrecord: %v\n", err)
		os.Exit(1)
	}
}

func record(in, out string) error {
	src, err := os.Open(in) //nolint:gosec // an operator-named path, by design
	if err != nil {
		return err
	}
	b, err := bundle.Read(src)
	src.Close()
	if err != nil {
		return fmt.Errorf("reading %s: %w", in, err)
	}

	applied := map[string]int{}
	scrubMounts(&b, applied)
	if err := scrubEvidence(&b, applied); err != nil {
		return err
	}
	report(applied)

	// 0644 rather than the 0600 a collected bundle gets: this one is about to
	// be committed to a public repository, so treating it as a secret would be
	// a comforting lie. The scrub above is what makes that safe.
	dst, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // see above
	if err != nil {
		return err
	}
	if err := bundle.Write(dst, b); err != nil {
		dst.Close()
		return fmt.Errorf("writing %s: %w", out, err)
	}
	return dst.Close()
}

// scrubMounts rewrites the mount table fact. Options and SuperOpts are the only
// fields that can carry a path: Point and FSType are the mount point and the
// filesystem's name, and both belong to the image being scanned.
func scrubMounts(b *bundle.Bundle, applied map[string]int) {
	m, _, ok := fact.Get[fact.Mounts](b.Facts, fact.MountsID)
	if !ok {
		return
	}
	for i := range m.Entries {
		m.Entries[i].Options = scrubAll(m.Entries[i].Options, applied)
		m.Entries[i].SuperOpts = scrubAll(m.Entries[i].SuperOpts, applied)
	}
	b.Facts.Put(m)
}

// scrubEvidence rebuilds the evidence store from scrubbed bytes.
//
// It rebuilds rather than edits because the store is content-addressed: a blob
// whose bytes change has a different address, and an entry left under its old
// digest would be a blob whose name does not match its content — which is
// precisely what bundle.Read treats as tampering.
//
// Nothing cites these blobs by digest today: the mount table fact carries no
// digest field, so no finding can point at the mountinfo blob. If that ever
// changes, this function has to update the citation with the address.
func scrubEvidence(b *bundle.Bundle, applied map[string]int) error {
	if b.Evidence == nil {
		return nil
	}
	next := bundle.NewEvidenceStore()
	for _, sum := range b.Evidence.Digests() {
		blob, ok := b.Evidence.Get(sum)
		if !ok {
			return fmt.Errorf("evidence %s vanished between listing and reading", sum)
		}
		next.Add(scrubBytes(blob, applied))
	}
	for _, src := range b.Evidence.TruncatedSources() {
		next.MarkTruncated(src)
	}
	b.Evidence = next
	return nil
}

func scrubAll(in []string, applied map[string]int) []string {
	for i, s := range in {
		in[i] = string(scrubBytes([]byte(s), applied))
	}
	return in
}

func scrubBytes(in []byte, applied map[string]int) []byte {
	out := in
	for _, s := range scrubs {
		n := len(s.pat.FindAll(out, -1))
		if n == 0 {
			continue
		}
		applied[s.name] += n
		out = s.pat.ReplaceAll(out, []byte(s.with))
	}
	return out
}

// report prints what was removed. A scrub that runs silently is one nobody
// notices has stopped matching, and a scrub that has stopped matching is a leak.
func report(applied map[string]int) {
	if len(applied) == 0 {
		fmt.Println("goldenrecord: nothing matched; the bundle was already clean")
		return
	}
	names := make([]string, 0, len(applied))
	for name := range applied {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("goldenrecord: %-24s %3d replaced\n", name, applied[name])
	}
}

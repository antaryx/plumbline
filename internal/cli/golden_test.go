package cli_test

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Golden bundles are the regression tripwire for the catalog (docs/FIXTURES.md
// §6). Each one is a real collection from a real distribution, recorded once by
// testdata/bundles/record.sh and committed, and every run of `make verify`
// re-evaluates all of them with today's catalog.
//
// The fixture corpus answers "does this check reach the right verdict on a tree
// built to provoke it". That is a different question from "did anything move on
// a host nobody was thinking about when the change was written", and only the
// second one catches a check whose blast radius is wider than its author
// believed. A fixture is written by the same person, at the same time, with the
// same misconception.
//
// Two gates, deliberately different in kind:
//
//	the expectation files    per-check verdicts, regenerated with -update, so a
//	                         PR shows exactly which checks moved on which distro
//	the constants below      posture and counts, retyped by hand, so a
//	                         regeneration cannot be an unnoticed keystroke
//
// The second exists because the first is too easy to satisfy. `-update` makes
// any diff go away, and a gate that can be silenced by the same command that
// runs it is a gate that will eventually be silenced by habit. Retyping 96.6
// as 91.2 is a thing a reviewer sees.

const goldenDir = "../../testdata/bundles"

// updateGolden rewrites the expectation files instead of comparing against
// them. FIXTURES.md §6 is explicit that regenerating them is a reviewed act:
// a PR that runs this without explaining every changed line should be refused.
var updateGolden = flag.Bool("update", false,
	"rewrite testdata/bundles/*.expected.json from the current catalog")

// pinned is the hand-maintained half of the gate: what each golden bundle
// scores, typed out, against the catalog version that was verified.
//
// **Changing a number here is the point at which somebody claims a new verdict
// is correct.** Not when the check changed, and not when -update was run — here.
// If a catalog change moves one of these, the diff to read is the expectation
// file's, and the question to answer in the PR description is which host is now
// being judged differently and whether that is what was intended.
type pin struct {
	catalog       int
	pass          int
	fail          int
	notApplicable int
	unknown       int
	skipped       int
	posture       float64
	coverage      float64

	// why records what this bundle is for, so a failure prints something more
	// useful than a filename to whoever is reading it at an inconvenient hour.
	why string
}

// The corpus was re-recorded at catalog 16, so the MEMORY and CONTAINERS
// modules reach real
// verdicts on all six rather than the UNKNOWN(fact_not_collected) an old
// recording could only give them. Coverage is back to where it was before the
// module existed: 100 on the three bundles that answer everything, and the
// residual UNKNOWNs on the other three are the pre-existing AUTH and KERNEL
// ones, not MEMORY.
//
// Two of the new verdicts are FAIL, and both are the documented limits of
// reading hardening out of a symbol table rather than defects in the hosts:
//
//   - alpine, MEMORY-0004: /usr/bin/crontab and /usr/bin/passwd are both
//     symlinks to /bin/busybox — one binary, one digest, reported under the two
//     paths an operator would ask about. musl does not implement glibc's _chk
//     entry points at all, so no busybox build on Alpine can pass this check.
//   - debian, MEMORY-0003: /usr/bin/newgrp, 52 symbols, no __stack_chk_fail.
//     -fstack-protector-strong instruments only functions with local arrays,
//     and this one has none.
//
// Both are in docs/FALSE-POSITIVES.md. They are pinned here deliberately: a run
// in which either became a PASS would mean the symbol reading had started
// inventing evidence, which is a worse failure than the false positive.
var pinned = map[string]pin{
	// A stock Ubuntu server on the day it is provisioned. The 32 NOT_APPLICABLE
	// are almost entirely SSHD and LOGGING: a base image runs no sshd and no
	// syslog daemon, and a check that declines to judge an absent subject is
	// the behaviour, not a gap.
	"ubuntu-2404-stock": {
		catalog: 17, pass: 39, fail: 12, notApplicable: 35, unknown: 0, skipped: 0,
		posture: 80.50847457627118, coverage: 100,
		why: "the unhardened baseline every other number is measured against",
	},

	// Debian and Ubuntu share an ancestry and diverge in the places a hardening
	// check cares about. One PASS and one NOT_APPLICABLE separate them here,
	// and which ones is the interesting part of any diff on this pair.
	"debian-13-stock": {
		catalog: 17, pass: 37, fail: 13, notApplicable: 36, unknown: 0, skipped: 0,
		posture: 78.44827586206897, coverage: 100,
		why: "Debian's defaults, which are not Ubuntu's",
	},

	// musl, busybox, OpenRC, no PAM. The 45 NOT_APPLICABLE are the point: this
	// is the bundle that catches a check quietly assuming a Debian-shaped /etc
	// and reporting a verdict about a file that was never there.
	"alpine-320-stock": {
		catalog: 17, pass: 30, fail: 8, notApplicable: 48, unknown: 0, skipped: 0,
		posture: 84.0909090909091, coverage: 100,
		why: "the distribution least like the others, where guessing shows up",
	},

	// The RPM family. Both carry the same UNKNOWN, and it is the best short
	// argument for this project that the corpus contains: pam_pwquality is
	// enforced on a stock Fedora and a stock Rocky, but none of its parameters
	// are set in pwquality.conf or on the PAM line, so the effective minimum
	// length comes from libpwquality's compiled-in default — a property of the
	// binary, not of any file on the host. AUTH-0002 says it does not know.
	// Every other scanner reports the documented default and calls it a PASS.
	"fedora-44-stock": {
		catalog: 17, pass: 37, fail: 12, notApplicable: 36, unknown: 1, skipped: 0,
		posture: 79.13043478260869, coverage: 98,
		why: "the RPM family's leading edge, where authselect owns the PAM stack",
	},

	// A RHEL rebuild is conservative where Fedora is current, which is the whole
	// point of it. One FAIL and one NOT_APPLICABLE separate the two, and which
	// ones is the interesting part of any diff on this pair.
	"rocky-9-stock": {
		catalog: 17, pass: 37, fail: 11, notApplicable: 37, unknown: 1, skipped: 0,
		posture: 81.25, coverage: 97.95918367346938,
		why: "the enterprise RPM baseline most real audits run against",
	},

	// The bundle that carries the catalog. Every check that *can* reach a real
	// verdict on a host does so here, which no fixture and no stock image
	// manages on its own.
	//
	// The 3 NOT_APPLICABLE are the CONTAINERS module: the recipe installs no
	// Docker, so there is no daemon to judge. That is the correct answer and
	// the honest limit of a container-recorded corpus — a bundle recorded
	// inside a container cannot carry a container runtime's configuration.
	// Covering CONTAINERS against a real daemon needs a recipe that installs
	// one, which is a work package of its own.
	//
	// The 4 FAIL are the four a container cannot fix — /tmp and /home are not
	// separate mounts, and /proc/sys is read-only so dmesg_restrict and the
	// core pattern cannot be set. The 1 UNKNOWN is KERNEL-0007 declining to
	// claim the running kernel matches its configuration when one of the
	// configuration files was a symlink it would not follow. All five are
	// correct, and a run in which any of them became a PASS would be a serious
	// regression rather than an improvement.
	"ubuntu-2404-hardened": {
		catalog: 17, pass: 78, fail: 4, notApplicable: 3, unknown: 1, skipped: 0,
		posture: 96.7741935483871, coverage: 98.79518072289156,
		why: "the only bundle on which every check in the catalog evaluates",
	},
}

func TestGolden(t *testing.T) {
	for _, name := range sortedNames(pinned) {
		t.Run(name, func(t *testing.T) {
			want := pinned[name]
			doc := evaluateGolden(t, name)

			checkPins(t, name, want, doc)
			compareExpectation(t, name, doc)
		})
	}
}

// checkPins compares the summary against the hand-typed numbers.
//
// Posture and coverage are compared exactly rather than within a tolerance. A
// tolerance would be a claim that a small change in the score does not matter,
// and the whole reason this file exists is that a small change in the score is
// exactly what a wrong check looks like from the outside.
func checkPins(t *testing.T, name string, want pin, doc goldenDoc) {
	t.Helper()

	if doc.CatalogVersion != want.catalog {
		t.Errorf("catalog version = %d, pinned at %d\n"+
			"    The expectations for %s were verified against catalog %d.\n"+
			"    Re-run `make golden-update`, read the diff, and retype the numbers in pinned.",
			doc.CatalogVersion, want.catalog, name, want.catalog)
	}

	c := doc.Summary.Counts
	for _, cmp := range []struct {
		what      string
		got, want int
	}{
		{"PASS", c.Pass, want.pass},
		{"FAIL", c.Fail, want.fail},
		{"NOT_APPLICABLE", c.NotApplicable, want.notApplicable},
		{"UNKNOWN", c.Unknown, want.unknown},
		{"SKIPPED", c.Skipped, want.skipped},
	} {
		if cmp.got != cmp.want {
			t.Errorf("%s = %d, pinned at %d (%s: %s)",
				cmp.what, cmp.got, cmp.want, name, want.why)
		}
	}

	if doc.Summary.Posture == nil || *doc.Summary.Posture != want.posture {
		t.Errorf("posture = %v, pinned at %v (%s)", derefFloat(doc.Summary.Posture), want.posture, name)
	}
	if doc.Summary.Coverage == nil || *doc.Summary.Coverage != want.coverage {
		t.Errorf("coverage = %v, pinned at %v (%s)", derefFloat(doc.Summary.Coverage), want.coverage, name)
	}
}

// compareExpectation holds the per-check verdicts against the committed file,
// or rewrites it under -update.
func compareExpectation(t *testing.T, name string, doc goldenDoc) {
	t.Helper()

	path := filepath.Join(goldenDir, name+".expected.json")
	got := doc.marshal(t)

	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		t.Logf("rewrote %s", path)
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // a path this test builds
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"    A golden bundle with no expectation file is a bundle nothing is checking.\n"+
			"    Run `make golden-update` and commit the result.", path, err)
	}
	if string(got) == string(want) {
		return
	}

	var prev goldenDoc
	if err := json.Unmarshal(want, &prev); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	t.Errorf("%s no longer evaluates to its expectation.\n%s\n"+
		"    If the change is intended: `make golden-update`, then explain every\n"+
		"    moved verdict in the PR description. If it is not, a check just changed\n"+
		"    its answer on a real host.", name, whatMoved(prev, doc, string(want), string(got)))
}

// whatMoved names the checks whose verdicts changed.
//
// The summary sits above the findings in the document, so a naive first-line
// diff reports "pass: 74 became 73" — true, and no help at all with the
// question a reviewer is actually holding, which is *which check*. Joining on
// check ID answers that directly, and falls back to a line diff for the case
// where no verdict moved and only a detail string was reworded.
func whatMoved(want, got goldenDoc, wantRaw, gotRaw string) string {
	before := byCheckID(want.Findings)
	after := byCheckID(got.Findings)

	var moved []string
	for _, id := range sortedIDs(before, after) {
		w, hadBefore := before[id]
		g, hadAfter := after[id]
		switch {
		case !hadAfter:
			moved = append(moved, fmt.Sprintf("      %-14s %s -> gone from the catalog", id, w.Result))
		case !hadBefore:
			moved = append(moved, fmt.Sprintf("      %-14s new check, %s", id, g.Result))
		case w.Result != g.Result:
			moved = append(moved, fmt.Sprintf("      %-14s %s -> %s%s", id, w.Result, g.Result, reasonSuffix(g)))
		case w.Severity != g.Severity:
			moved = append(moved, fmt.Sprintf("      %-14s severity %s -> %s", id, w.Severity, g.Severity))
		case w.Fingerprint != g.Fingerprint:
			// The fingerprint is what an operator's suppression file keys on,
			// so a change here silently un-suppresses an accepted risk. It is
			// worth reporting even though the verdict did not move.
			moved = append(moved, fmt.Sprintf("      %-14s fingerprint changed; existing suppressions for it will stop matching", id))
		}
	}

	if len(moved) == 0 {
		return "    no verdict moved; the detail or evidence text changed:\n" +
			firstDifference(wantRaw, gotRaw)
	}
	return "    verdicts that moved:\n" + strings.Join(moved, "\n")
}

func byCheckID(findings []goldenFinding) map[string]goldenFinding {
	out := make(map[string]goldenFinding, len(findings))
	for _, f := range findings {
		out[f.CheckID] = f
	}
	return out
}

func sortedIDs(a, b map[string]goldenFinding) []string {
	seen := map[string]bool{}
	for id := range a {
		seen[id] = true
	}
	for id := range b {
		seen[id] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func reasonSuffix(f goldenFinding) string {
	if f.UnknownReason == "" {
		return ""
	}
	return " (" + f.UnknownReason + ")"
}

// firstDifference reports the first line that differs. `git diff` shows the
// rest; a test failure should name the thing rather than print two hundred
// lines of context.
func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		lw, lg := lineAt(w, i), lineAt(g, i)
		if lw == lg {
			continue
		}
		return fmt.Sprintf("      line %d:\n        expected: %s\n        got:      %s",
			i+1, strings.TrimSpace(lw), strings.TrimSpace(lg))
	}
	return "      (the documents differ only in length)"
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(end of file)"
}

// evaluateGolden runs the real command over the bundle. Going through
// cli.Execute rather than calling the catalog directly is the point: it is the
// evaluation path an operator gets, flag parsing, renderer and all, so a
// regression anywhere along it is caught by the same gate.
func evaluateGolden(t *testing.T, name string) goldenDoc {
	t.Helper()

	path := filepath.Join(goldenDir, name+".plb")
	code, stdout, stderr := run(t, "eval", "--json", path)
	if code != 0 {
		t.Fatalf("eval %s exited %d\nstderr: %s", name, code, stderr)
	}

	var doc goldenDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parsing the findings document for %s: %v", name, err)
	}
	doc.Bundle = name + ".plb"
	if doc.Schema == "" || len(doc.Findings) == 0 {
		t.Fatalf("%s produced no findings; the bundle is empty or unreadable", name)
	}
	return doc
}

// goldenDoc is the part of a findings document a golden bundle pins.
//
// It is deliberately not the whole document. Title, remediation, references and
// framework mappings are catalog metadata: identical on every host, already
// covered by `plumbline explain` and its own sweep test, and three copies of
// forty lines of remediation prose would bury the one line that matters on the
// day a verdict moves. What is kept is everything that is a claim about *this
// host*: the verdict, both severities, the reason an UNKNOWN is unknown, the
// subject, the fingerprint an operator's suppression file keys on, the detail
// that quotes the observed value, and the evidence cited for it.
//
// tool identity is dropped for the opposite reason: version and commit come
// from -ldflags and differ between a `go test` and a release build, so pinning
// them would pin the build rather than the finding.
type goldenDoc struct {
	Bundle         string          `json:"bundle"`
	Schema         string          `json:"schema"`
	CatalogVersion int             `json:"catalog_version"`
	Scan           json.RawMessage `json:"scan"`
	Summary        goldenSummary   `json:"summary"`
	Findings       []goldenFinding `json:"findings"`
}

type goldenSummary struct {
	Counts     goldenCounts   `json:"counts"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	Posture    *float64       `json:"posture"`
	Coverage   *float64       `json:"coverage"`
}

type goldenCounts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
	Skipped       int `json:"skipped"`
	Unknown       int `json:"unknown"`
	Total         int `json:"total"`
}

type goldenFinding struct {
	CheckID       string          `json:"check_id"`
	Module        string          `json:"module"`
	Result        string          `json:"result"`
	Severity      string          `json:"severity"`
	BaseSeverity  string          `json:"base_severity"`
	UnknownReason string          `json:"unknown_reason,omitempty"`
	Subject       string          `json:"subject,omitempty"`
	Fingerprint   string          `json:"fingerprint"`
	Detail        string          `json:"detail"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
	SkippedBy     string          `json:"skipped_by,omitempty"`
	Suppression   json.RawMessage `json:"suppression,omitempty"`
}

func (d goldenDoc) marshal(t *testing.T) []byte {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("encoding the expectation: %v", err)
	}
	return append(b, '\n')
}

// TestGoldenCorpusIsAccountedFor refuses a bundle nothing is watching.
//
// A .plb added without a pin evaluates on every run and asserts nothing, which
// is worse than not having it: the corpus looks larger than it is. A pin with
// no .plb is a test that silently stops running. A bundle with no recipe cannot
// be re-recorded, which makes it evidence of nothing in particular.
func TestGoldenCorpusIsAccountedFor(t *testing.T) {
	bundles := basenames(t, goldenDir, ".plb")
	recipes := basenames(t, filepath.Join(goldenDir, "recipes"), ".dockerfile")

	for _, name := range bundles {
		if _, ok := pinned[name]; !ok {
			t.Errorf("testdata/bundles/%s.plb has no entry in pinned; nothing checks it", name)
		}
		if !contains(recipes, name) {
			t.Errorf("testdata/bundles/%s.plb has no recipe; it cannot be re-recorded", name)
		}
		if _, err := os.Stat(filepath.Join(goldenDir, name+".expected.json")); err != nil {
			t.Errorf("testdata/bundles/%s.plb has no expectation file", name)
		}
	}
	for _, name := range sortedNames(pinned) {
		if !contains(bundles, name) {
			t.Errorf("pinned names %q but testdata/bundles/%s.plb does not exist", name, name)
		}
	}
	for _, name := range recipes {
		if !contains(bundles, name) {
			t.Errorf("recipes/%s.dockerfile records no bundle; run testdata/bundles/record.sh", name)
		}
	}
}

// TestGoldenBundlesCarryNothingOfTheRecordingHost is the redaction gate.
//
// A golden bundle is committed to a public repository forever, so it must
// describe the image that was scanned and nothing whatever about the machine
// that did the scanning. tools/goldenrecord removes the two leaks a container
// recording actually produces; this test is what catches the third, on the day
// somebody re-records through a runtime nobody here has seen.
//
// It reads the raw archive rather than the decoded facts on purpose. A decoded
// read only inspects the fields this binary understands, and the failure being
// guarded against is a value arriving somewhere nobody thought to look.
func TestGoldenBundlesCarryNothingOfTheRecordingHost(t *testing.T) {
	forbidden := []struct {
		what string
		why  string
		pat  *regexp.Regexp
	}{
		{
			"a path inside somebody's home directory",
			"the only way one reaches a bundle is a bind mount at record time; " +
				"record.sh copies the binary in as an image layer for this reason",
			// A home *directory* is ordinary content: /etc/passwd names one per
			// account and the ownership tallies cite them as examples. A path
			// *inside* one is not — no collector descends there — so the second
			// level is what separates the image's own /home/ubuntu from the
			// /home/<user>/src/plumbline that a bind mount once put in a mount
			// table. If a recording ever does produce a legitimate one, this
			// firing and a human deciding is the correct outcome for a
			// redaction gate.
			regexp.MustCompile(`/(home|Users)/[^/:"\s]+/[^/:"\s]`),
		},
		{
			"a container runtime's storage tree",
			"overlay lowerdir/upperdir/workdir name the recording machine's disk layout",
			regexp.MustCompile(`(lowerdir|upperdir|workdir)=/`),
		},
		{
			"a container runtime's private directories",
			"these paths say which runtime recorded the bundle and where it keeps state",
			regexp.MustCompile(`containerd|docker/containers|/var/lib/docker`),
		},
	}

	for _, name := range sortedNames(pinned) {
		t.Run(name, func(t *testing.T) {
			for member, data := range archiveMembers(t, name) {
				for _, f := range forbidden {
					if loc := f.pat.Find(data); loc != nil {
						t.Errorf("%s carries %s: %q\n    %s\n"+
							"    Re-record with testdata/bundles/record.sh, and if the value survives,\n"+
							"    tools/goldenrecord needs a scrub for it.",
							member, f.what, loc, f.why)
					}
				}
			}
		})
	}
}

// TestGoldenBundlesCarryNoCredentialMaterial holds the property that makes
// ubuntu-2404-hardened safe to commit.
//
// That bundle is recorded from a host with a real login account, because
// USERS-0004, USERS-0009 and USERS-0010 ask about accounts that can actually
// authenticate and no stock image has one. What makes it safe is a design
// decision two work packages older than this file: the shadow fact records the
// *properties* of a password hash — which algorithm, locked, empty — and never
// the hash, and /etc/shadow is never added to the evidence store. This test is
// that decision's alarm. If a future collector starts storing the file it
// parsed, the golden corpus is where it will be noticed, before a release.
func TestGoldenBundlesCarryNoCredentialMaterial(t *testing.T) {
	// crypt(3) prefixes, and the two header forms a private key arrives in.
	// $2$ is not listed because no crypt implementation emits it.
	secrets := regexp.MustCompile(
		`\$(1|2[aby]|5|6|7|y|gy)\$|BEGIN [A-Z ]*PRIVATE KEY|ssh-(rsa|dss|ed25519) AAAA`)

	for _, name := range sortedNames(pinned) {
		t.Run(name, func(t *testing.T) {
			for member, data := range archiveMembers(t, name) {
				if loc := secrets.Find(data); loc != nil {
					t.Errorf("%s appears to carry credential material: %q\n"+
						"    A golden bundle is public. Either a collector started storing a file\n"+
						"    it only used to parse, or a recipe put a secret somewhere it is read.",
						member, loc)
				}
			}
		})
	}
}

// archiveMembers decompresses a golden bundle and returns every member's bytes.
//
// Reading the tar directly rather than through bundle.Read is deliberate: the
// tests above are looking for a string anywhere in the artifact, including in
// members this binary would not decode, and a typed read would only show them
// the parts it already understands.
func archiveMembers(t *testing.T, name string) map[string][]byte {
	t.Helper()

	path := filepath.Join(goldenDir, name+".plb")
	f, err := os.Open(path) //nolint:gosec // a path this test builds
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("decompressing %s: %v", path, err)
	}
	defer zr.Close()

	out := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s from %s: %v", hdr.Name, path, err)
		}
		out[name+":"+hdr.Name] = data
	}
	if len(out) == 0 {
		t.Fatalf("%s contains no members", path)
	}
	return out
}

func basenames(t *testing.T, dir, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			out = append(out, strings.TrimSuffix(e.Name(), suffix))
		}
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func sortedNames(m map[string]pin) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func derefFloat(f *float64) any {
	if f == nil {
		return "undefined"
	}
	return *f
}

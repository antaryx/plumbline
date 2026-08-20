package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Plumbline claims to work offline. That claim is load-bearing: it is why a
// bundle can be collected on an air-gapped host, why no version lookup can
// leak an inventory to a vendor, and why nothing this tool does depends on a
// service being up (docs/ARCHITECTURE.md, THREAT-MODEL.md).
//
// A claim like that decays silently. One transitive dependency that phones
// home, one well-meaning "check for updates", and it is no longer true — with
// nothing failing to say so. This test runs the real binary in a network
// namespace with no interfaces and asserts a full scan still succeeds.

const fixture = "../../testdata/fixtures/cli-host"

// build compiles the binary under test. Building it rather than calling the
// package directly is the point: the offline claim is about the shipped
// artifact, including whatever its dependencies do at init.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "plumbline")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// unshareAvailable reports whether this environment can create a network
// namespace unprivileged. Containers often forbid it.
func unshareAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		return false
	}
	// -r maps the current user to root inside the namespace, which is what
	// makes CLONE_NEWNET available without real privilege.
	return exec.Command("unshare", "-n", "-r", "true").Run() == nil
}

// TestScanSucceedsWithNoNetwork is the acceptance criterion.
//
// It compares an online scan against an offline scan of the same fixture and
// requires the two documents to be identical. That is the claim being made —
// offline is not a degraded mode — asserted directly rather than through a
// proxy.
//
// The assertion used to be "every finding over cli-host is PASS". That was
// always a proxy, and it broke for a reason with nothing to do with
// networking: the CLI fixtures are read through the *live* seam, so their
// files carry the ownership of whoever checked the repository out, and git
// cannot record ownership. A check that asserts root ownership therefore fails
// over them permanently. Comparing the two runs against each other is immune
// to that, and to every future module: whatever verdicts the catalog produces,
// the network must not change them.
func TestScanSucceedsWithNoNetwork(t *testing.T) {
	if !unshareAvailable(t) {
		t.Skip("cannot create a network namespace here (unshare -n -r is unavailable or blocked). " +
			"The offline claim is enforced in CI, where the job runs this same command in a namespace " +
			"with no interfaces; a green local run without it does not prove the claim.")
	}

	bin := build(t)
	root, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity first: inside the namespace there really is no network. Without
	// this the test could pass on a machine where unshare silently did nothing.
	probe := exec.Command("unshare", "-n", "-r", "sh", "-c",
		"ip -o addr show 2>/dev/null | grep -v ' lo ' | wc -l")
	probeOut, err := probe.CombinedOutput()
	if err == nil && strings.TrimSpace(string(probeOut)) != "0" {
		t.Fatalf("the namespace has network interfaces (%s); this test would prove nothing",
			strings.TrimSpace(string(probeOut)))
	}

	// Both runs go through `unshare -r`, and only the offline one adds `-n`.
	//
	// The `-r` is what makes CLONE_NEWNET available without real privilege,
	// and it necessarily maps the calling uid to 0 inside the namespace — so a
	// bare online run would differ from the offline one in *identity* as well
	// as in networking: scan.euid changes, and every check that reads file
	// ownership sees different numbers. Wrapping both sides in `-r` leaves the
	// network namespace as the only variable, which is the one thing this test
	// is about.
	// --json, because this test compares documents byte for byte and the
	// document is the JSON one. The terminal report is not the API and is not
	// what an offline guarantee is stated over.
	online := scanDocument(t, []string{"unshare", "-r"}, bin, "scan", "--root", root, "--json")
	offline := scanDocument(t, []string{"unshare", "-n", "-r"}, bin, "scan", "--root", root, "--json")

	// The document must be complete before it is worth comparing: two empty
	// documents are also identical.
	if online["schema"] != "findings/v1" {
		t.Errorf("schema = %v", online["schema"])
	}
	if n := len(findingsOf(t, online)); n == 0 {
		t.Fatal("the online scan produced no findings; there is nothing to compare")
	}

	blankVolatile(online)
	blankVolatile(offline)

	if reflect.DeepEqual(online, offline) {
		return
	}

	// Name the top-level keys that differ before dumping anything. A raw diff
	// of two full findings documents is thousands of lines and tells the
	// reader nothing about where to look.
	var differing []string
	for _, k := range topLevelKeys(online, offline) {
		if !reflect.DeepEqual(online[k], offline[k]) {
			differing = append(differing, k)
		}
	}
	sort.Strings(differing)
	t.Errorf("the offline scan produced a different document from the online scan; "+
		"a scan must not depend on the network. Differing top-level key(s): %s",
		strings.Join(differing, ", "))
	for _, k := range differing {
		t.Errorf("  %s online:  %s", k, mustJSON(t, online[k]))
		t.Errorf("  %s offline: %s", k, mustJSON(t, offline[k]))
	}
}

// scanDocument runs the binary, optionally under a wrapper such as unshare,
// and returns the findings document as a generic map.
//
// A map rather than the renderer's own struct on purpose: this is asserting
// something about the document a consumer receives, and decoding through the
// producer's type would hide a field the producer stopped emitting.
func scanDocument(t *testing.T, wrapper []string, bin string, args ...string) map[string]any {
	t.Helper()

	argv := append(append([]string{}, wrapper...), append([]string{bin}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v failed: %v\nstderr: %s", argv, err, stderr.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not a findings document: %v\n%s", err, stdout.String())
	}
	return doc
}

// volatileScanFields are the fields that legitimately differ between two runs
// of the same scan and are therefore excluded from the comparison.
//
// They are named individually rather than by dropping the whole scan object,
// because the rest of it — euid, profile, the host block — is exactly the kind
// of thing that must NOT change when the network goes away. A hostname that
// resolves online and not offline would be a real failure of this claim, and
// blanking the whole object would hide it.
var volatileScanFields = []string{
	// Wall-clock timestamps. Two runs are never simultaneous.
	"started",
	"finished",
	// The absolute path of the fixture, which varies by checkout location.
	// It is identical between these two particular runs, but blanking it keeps
	// the test honest if the fixture is ever passed differently.
	"root",
}

// blankVolatile removes the fields that cannot be equal between two runs.
func blankVolatile(doc map[string]any) {
	scan, ok := doc["scan"].(map[string]any)
	if !ok {
		return
	}
	for _, f := range volatileScanFields {
		delete(scan, f)
	}
}

// findingsOf returns the findings array.
func findingsOf(t *testing.T, doc map[string]any) []any {
	t.Helper()
	out, _ := doc["findings"].([]any)
	return out
}

// topLevelKeys returns the union of both documents' keys, so a key present in
// only one of them is still reported.
func topLevelKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unmarshalable: %v>", err)
	}
	return string(b)
}

// TestCollectAndEvalSucceedWithNoNetwork: the two-step path is the one an
// air-gapped operator actually uses, and eval is the half that CLI-SPEC says
// must work with no network and no privileges.
func TestCollectAndEvalSucceedWithNoNetwork(t *testing.T) {
	if !unshareAvailable(t) {
		t.Skip("cannot create a network namespace here; enforced in CI")
	}

	bin := build(t)
	root, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "offline.plb")

	for _, step := range [][]string{
		{"collect", "--root", root, "-o", bundlePath},
		{"eval", bundlePath, "--json"},
	} {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command("unshare", append([]string{"-n", "-r", bin}, step...)...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v failed with no network: %v\nstderr: %s", step, err, stderr.String())
		}
		if step[0] == "eval" && !strings.Contains(stdout.String(), `"schema": "findings/v1"`) {
			t.Errorf("eval produced no document offline:\n%s", stdout.String())
		}
	}
}

// TestVersionMakesNoNetworkCall guards the specific temptation: a version
// command that checks for updates. There is no such thing here and there must
// not be, because a scanner that phones home has told a vendor which hosts it
// audits and when.
func TestVersionMakesNoNetworkCall(t *testing.T) {
	if !unshareAvailable(t) {
		t.Skip("cannot create a network namespace here; enforced in CI")
	}
	bin := build(t)

	out, err := exec.Command("unshare", "-n", "-r", bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version failed with no network: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "catalog:") {
		t.Errorf("version output looks wrong offline:\n%s", out)
	}
}

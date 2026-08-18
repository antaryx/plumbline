package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("unshare", "-n", "-r", bin, "scan", "--root", root)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if runErr != nil {
		t.Fatalf("scan failed with no network: %v\nstderr: %s", runErr, stderr.String())
	}

	// It did not merely exit 0 — it produced a complete document.
	var doc struct {
		Schema  string `json:"schema"`
		Summary struct {
			Counts struct {
				Total int `json:"total"`
				Pass  int `json:"pass"`
			} `json:"counts"`
			Coverage *float64 `json:"coverage"`
		} `json:"summary"`
		Findings []struct {
			CheckID string `json:"check_id"`
			Result  string `json:"result"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not a findings document: %v\n%s", err, stdout.String())
	}
	if doc.Schema != "findings/v1" {
		t.Errorf("schema = %q", doc.Schema)
	}
	if doc.Summary.Counts.Total == 0 {
		t.Error("the offline scan evaluated nothing")
	}
	if doc.Summary.Coverage == nil || *doc.Summary.Coverage != 100 {
		t.Errorf("coverage = %v, want 100: an offline scan of a readable host must be complete", doc.Summary.Coverage)
	}
	// The verdict is the same one the same fixture produces with a network,
	// which is the real claim: offline is not a degraded mode.
	if len(doc.Findings) != 1 || doc.Findings[0].CheckID != "SSHD-0002" || doc.Findings[0].Result != "PASS" {
		t.Errorf("findings = %+v", doc.Findings)
	}
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
		{"eval", bundlePath},
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

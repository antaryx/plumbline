package cli_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/cli"
	"github.com/antaryx/plumbline/internal/fact"
)

const (
	hostFixture    = "../../testdata/fixtures/cli-host"
	includeFixture = "../../testdata/fixtures/sshd-include"
	absentFixture  = "../../testdata/fixtures/sshd-absent"
	failFixture    = "../../testdata/fixtures/sshd-permit-yes"
)

// run executes a command line the way the process would and returns what the
// operator would see. cli.Execute returns the code rather than calling
// os.Exit, which is the only way to test an exit ladder without spawning
// processes and parsing their output.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = cli.Execute(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// document is the part of a findings document these tests reason about.
type document struct {
	Schema   string          `json:"schema"`
	Scan     json.RawMessage `json:"scan"`
	Summary  json.RawMessage `json:"summary"`
	Findings json.RawMessage `json:"findings"`
}

func parse(t *testing.T, s string) document {
	t.Helper()
	var d document
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("output is not a findings document: %v\n%s", err, s)
	}
	if d.Schema != "findings/v1" {
		t.Fatalf("schema = %q", d.Schema)
	}
	return d
}

// TestScanEqualsCollectThenEval is the acceptance criterion. scan is a
// convenience over the pipeline, never a second code path: if the two can
// disagree, then every bundle on disk is evidence for a verdict the tool would
// not reach today.
func TestScanEqualsCollectThenEval(t *testing.T) {
	for _, fixture := range []string{hostFixture, includeFixture, absentFixture} {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			bundlePath := filepath.Join(t.TempDir(), "b.plb")

			collectCode, _, _ := run(t, "collect", "--root", fixture, "-o", bundlePath)
			evalCode, evalOut, _ := run(t, "eval", bundlePath)
			scanCode, scanOut, _ := run(t, "scan", "--root", fixture)

			piped := parse(t, evalOut)
			fused := parse(t, scanOut)

			if !bytes.Equal(piped.Findings, fused.Findings) {
				t.Errorf("findings differ between eval and scan:\n eval: %s\n scan: %s", piped.Findings, fused.Findings)
			}
			if !bytes.Equal(piped.Summary, fused.Summary) {
				t.Errorf("summary differs between eval and scan:\n eval: %s\n scan: %s", piped.Summary, fused.Summary)
			}
			// The scan section legitimately differs -- timestamps move -- but
			// the exit codes must agree, because they are derived from the
			// findings both produced.
			if evalCode != scanCode {
				t.Errorf("eval exited %d, scan exited %d (collect exited %d)", evalCode, scanCode, collectCode)
			}
		})
	}
}

// TestCollectAgainstAFixtureTree is the acceptance criterion: --root works
// before any container or mounted-image work depends on it.
func TestCollectAgainstAFixtureTree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.plb")
	code, _, stderr := run(t, "collect", "--root", includeFixture, "-o", path)
	if code != cli.ExitOK {
		t.Fatalf("collect exited %d: %s", code, stderr)
	}

	b := readBundle(t, path)
	cfg, ferr, ok := fact.Get[fact.SSHDConfig](b.Facts, fact.SSHDConfigID)
	if !ok {
		t.Fatalf("no sshd.config in the bundle: %v", ferr)
	}
	// The root was actually applied: the fixture's include resolved, and its
	// drop-in won, which is only true if both files were read beneath --root.
	if len(cfg.Files) != 2 {
		t.Errorf("read %v, want the config and its drop-in", cfg.Files)
	}
	if d, found := cfg.Effective("PermitRootLogin"); !found || d.Value != "no" {
		t.Errorf("effective PermitRootLogin = %+v, want no", d)
	}
	if b.Manifest.Scan.Root != includeFixture {
		t.Errorf("bundle records root %q, want %q", b.Manifest.Scan.Root, includeFixture)
	}
}

// TestBundleIsOwnerOnly is the acceptance criterion. A bundle is a complete
// reconnaissance package -- user list, open ports, package inventory, paths --
// and a world-readable one on a shared machine hands that to the next person
// to log in.
func TestBundleIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.plb")

	// Pre-create it world-readable: overwriting yesterday's bundle must not
	// inherit yesterday's permissions, which is what O_CREATE alone would do.
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := run(t, "collect", "--root", hostFixture, "-o", path); code != cli.ExitOK {
		t.Fatalf("collect exited %d: %s", code, stderr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("bundle mode = %04o, want 0600", got)
	}
}

// TestReportIsOwnerOnly: the v0.1.0 exit criteria say bundles *and reports* are
// 0600. A findings document is less sensitive than a bundle but not public — it
// names paths, accounts and misconfigurations, which is a shopping list for
// whoever reads it next on a shared machine.
func TestReportIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")

	// Pre-create it world-readable, for the same reason the bundle test does:
	// O_CREATE's mode does not apply to a file that already exists.
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := run(t, "scan", "--root", hostFixture, "-o", path); code != cli.ExitOK {
		t.Fatalf("scan exited %d: %s", code, stderr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("report mode = %04o, want 0600", got)
	}
	// And it is the document, not an empty file: a mode assertion on nothing
	// proves nothing.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"schema": "findings/v1"`) {
		t.Errorf("the report is not a findings document:\n%s", body)
	}
	// eval writes reports through the same path.
	bundlePath := filepath.Join(dir, "b.plb")
	if code, _, _ := run(t, "collect", "--root", hostFixture, "-o", bundlePath); code != cli.ExitOK {
		t.Fatal("collect failed")
	}
	evalReport := filepath.Join(dir, "eval.json")
	if code, _, _ := run(t, "eval", bundlePath, "-o", evalReport); code != cli.ExitOK {
		t.Fatal("eval failed")
	}
	info, err = os.Stat(evalReport)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("eval report mode = %04o, want 0600", got)
	}
}

// TestRepeatedEvaluationsAreByteIdentical is a v0.1.0 exit criterion. Two
// evaluations of one bundle must not differ, or a diff between two scans of an
// unchanged host is noise and nobody reads the ones that matter.
func TestRepeatedEvaluationsAreByteIdentical(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "b.plb")
	if code, _, _ := run(t, "collect", "--root", hostFixture, "-o", bundlePath); code != cli.ExitOK {
		t.Fatal("collect failed")
	}

	_, first, _ := run(t, "eval", bundlePath)
	if first == "" {
		t.Fatal("eval produced nothing; this test would prove nothing")
	}
	for i := 0; i < 10; i++ {
		if _, got, _ := run(t, "eval", bundlePath); got != first {
			t.Fatalf("evaluation %d differs from the first", i)
		}
	}
}

// TestRedactRemovesTheHostname is the acceptance criterion, asserted over the
// whole decompressed archive rather than one member: the point of redacting at
// collection time is that the identity is not in the file anywhere, so the
// bundle can be attached to a bug report without a second pass.
func TestRedactRemovesTheHostname(t *testing.T) {
	const hostname = "plumbline-fixture-host" // testdata/fixtures/cli-host/etc/hostname

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.plb")
	redacted := filepath.Join(dir, "redacted.plb")

	if code, _, e := run(t, "collect", "--root", hostFixture, "-o", plain); code != cli.ExitOK {
		t.Fatalf("collect exited %d: %s", code, e)
	}
	if code, _, e := run(t, "collect", "--root", hostFixture, "-o", redacted, "--redact"); code != cli.ExitOK {
		t.Fatalf("collect --redact exited %d: %s", code, e)
	}

	// The control: without --redact the hostname is there. Without this the
	// test could pass against a collector that never recorded it at all.
	if !strings.Contains(string(decompress(t, plain)), hostname) {
		t.Fatal("the unredacted bundle has no hostname, so this test proves nothing")
	}
	if b := readBundle(t, plain); b.Meta.Hostname != hostname {
		t.Errorf("meta.hostname = %q, want %q", b.Meta.Hostname, hostname)
	}

	// The assertion: with --redact it is nowhere in the archive.
	if body := string(decompress(t, redacted)); strings.Contains(body, hostname) {
		t.Errorf("the redacted bundle still contains the hostname:\n%s", body)
	}
	b := readBundle(t, redacted)
	if b.Meta.Hostname != "" {
		t.Errorf("meta.hostname = %q in a redacted bundle", b.Meta.Hostname)
	}
	// And it says it is redacted, so a reader can tell a bundle with no
	// hostname from a host that had no name.
	if !b.Manifest.Redacted {
		t.Error("a redacted bundle does not record that it was redacted")
	}
	// Redaction removes identity, not evidence: the facts are still there.
	if _, _, ok := fact.Get[fact.SSHDConfig](b.Facts, fact.SSHDConfigID); !ok {
		t.Error("redaction dropped the facts along with the hostname")
	}
}

// TestGatesDriveTheExitCode wires the ladder to real runs. The fixtures are
// the ones whose verdicts are known, so a change in a check's verdict breaks
// this test rather than silently changing what CI sees.
func TestGatesDriveTheExitCode(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"a clean host with no gates", []string{"scan", "--root", hostFixture}, cli.ExitOK},
		{"a failing host with no gates is still 0", []string{"scan", "--root", failFixture}, cli.ExitOK},
		{"--fail-on high catches a HIGH failure", []string{"scan", "--root", failFixture, "--fail-on", "high"}, 2},
		{"--fail-on critical does not", []string{"scan", "--root", failFixture, "--fail-on", "critical"}, cli.ExitOK},
		{"--threshold below posture", []string{"scan", "--root", hostFixture, "--threshold", "50"}, cli.ExitOK},
		// 100 rather than a middling number: posture is a ratio over the whole
		// catalog, so any threshold below 100 stops discriminating as modules
		// are added and the one FAIL on this fixture is diluted. A host with
		// at least one FAIL can never reach 100, which makes this the only
		// threshold that keeps asserting the gate rather than the size of the
		// catalog.
		{"--threshold above posture", []string{"scan", "--root", failFixture, "--threshold", "100"}, 3},
		{"--min-coverage satisfied", []string{"scan", "--root", hostFixture, "--min-coverage", "100"}, cli.ExitOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, tc.want, stderr)
			}
			// Whatever the gate decided, the document still went to stdout: a
			// gate is a verdict on the findings, not a reason to withhold them.
			if code != cli.ExitUsage && stdout == "" {
				t.Error("no document was written")
			}
		})
	}
}

// TestDegradedRunsOutrankFindings covers the rungs that need a host the
// scanner genuinely cannot read. A fixture's "unreadable" marker is a feature
// of the fake System; the CLI runs against the live one, so the test makes a
// file that is really unreadable and asserts on what actually happens.
func TestDegradedRunsOutrankFindings(t *testing.T) {
	root := deniedRoot(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"a collector error is degraded", []string{"scan", "--root", root}, 4},
		// The acceptance criterion, end to end: a run that is both degraded
		// and failing reports 4, because a pipeline told only about failures it
		// can fix -- while not being told the host was unreadable -- believes
		// it is green.
		{"degraded outranks failing", []string{"scan", "--root", root, "--fail-on", "info"}, 4},
		{"--strict-privileges on a permission gap", []string{"scan", "--root", root, "--strict-privileges"}, 10},
		{"--min-coverage on a blind run", []string{"scan", "--root", root, "--min-coverage", "50"}, 4},
		{"collect alone reports degraded too", []string{"collect", "--root", root, "-o", filepath.Join(t.TempDir(), "b.plb")}, 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, stderr := run(t, tc.args...); code != tc.want {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, tc.want, stderr)
			}
		})
	}
}

// deniedRoot builds a scan root whose sshd_config exists but cannot be read,
// which is the ordinary unprivileged case on a real host.
func deniedRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes cannot deny this process, so there is nothing to test")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "ssh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestUsageErrors: nothing was scanned, so the exit code must say so rather
// than reporting a clean host.
func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"bare invocation", []string{}},
		{"collect with no -o", []string{"collect", "--root", hostFixture}},
		{"unknown flag", []string{"scan", "--make-it-green"}},
		{"unknown command", []string{"audit"}},
		{"a misspelled --fail-on level", []string{"scan", "--root", hostFixture, "--fail-on", "hgih"}},
		{"an unimplemented format", []string{"scan", "--root", hostFixture, "--format", "sarif"}},
		{"--config that does not exist", []string{"version", "--config", "/nonexistent/plumbline.yaml"}},
		{"eval with no bundle", []string{"eval"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := run(t, tc.args...); code != cli.ExitUsage {
				t.Errorf("exit = %d, want %d", code, cli.ExitUsage)
			}
		})
	}
}

// TestCorruptBundleIsInternal: a bundle that will not open says nothing about
// the host, so it must not be reported as a finding about the host.
func TestCorruptBundleIsInternal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.plb")
	if code, _, _ := run(t, "collect", "--root", hostFixture, "-o", path); code != cli.ExitOK {
		t.Fatal("collect failed")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run(t, "eval", path)
	if code != cli.ExitInternal {
		t.Errorf("exit = %d, want %d", code, cli.ExitInternal)
	}
	if stdout != "" {
		t.Error("a document was written from a bundle that could not be trusted")
	}
}

// TestVersion reports all three versions, because a findings document is only
// interpretable with all three.
func TestVersion(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"plumbline", "catalog:", "schema:  findings/v1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output is missing %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = run(t, "version", "--json")
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var v struct {
		Tool    string `json:"tool"`
		Catalog int    `json:"catalog_version"`
		Schema  string `json:"schema"`
	}
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, stdout)
	}
	if v.Tool != "plumbline" || v.Catalog < 1 || v.Schema != "findings/v1" {
		t.Errorf("version --json = %+v", v)
	}
}

// TestOutputDiscipline: --format json writes the document to stdout and
// nothing else. A JSON document with a progress line in it is not a JSON
// document (CLI-SPEC.md §7).
func TestOutputDiscipline(t *testing.T) {
	_, stdout, _ := run(t, "scan", "--root", hostFixture)
	var v any
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Errorf("stdout is not pure JSON: %v\n%s", err, stdout)
	}

	// collect writes its progress to stderr and leaves stdout empty: there is
	// no document, and an empty stdout is what a pipeline should see.
	_, stdout, stderr := run(t, "collect", "--root", hostFixture, "-o", filepath.Join(t.TempDir(), "b.plb"))
	if stdout != "" {
		t.Errorf("collect wrote to stdout: %q", stdout)
	}
	if stderr == "" {
		t.Error("collect said nothing at all")
	}
}

// TestSaveBundleFromScan: a scan that keeps its bundle produces one that eval
// agrees with, which is what makes --save-bundle evidence rather than a copy.
func TestSaveBundleFromScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved.plb")
	code, scanOut, _ := run(t, "scan", "--root", hostFixture, "--save-bundle", path)
	if code != cli.ExitOK {
		t.Fatalf("scan exited %d", code)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("--save-bundle wrote nothing: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("saved bundle mode = %04o, want 0600", got)
	}

	_, evalOut, _ := run(t, "eval", path)
	if !bytes.Equal(parse(t, scanOut).Findings, parse(t, evalOut).Findings) {
		t.Error("re-evaluating a saved bundle disagrees with the scan that produced it")
	}
}

func readBundle(t *testing.T, path string) bundle.Bundle {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := bundle.Read(f)
	if err != nil {
		t.Fatalf("read bundle %s: %v", path, err)
	}
	return b
}

// decompress returns the whole uncompressed archive, so a test can assert that
// a string is absent from every member at once.
func decompress(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

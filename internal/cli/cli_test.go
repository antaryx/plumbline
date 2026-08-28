package cli_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/antaryx/plumbline/internal/bundle"
	"github.com/antaryx/plumbline/internal/cli"
	"github.com/antaryx/plumbline/internal/fact"
)

// hostFixture is a realistic checkout baseline rather than a clean host, and
// the distinction matters for what the gate tests below may assert.
//
// Its files are read through the LIVE seam — `scan --root` does not use the
// fake — so they carry the ownership of whoever checked the repository out.
// Git cannot record ownership, so the CRON checks that require root-owned cron
// files fail over it permanently and by construction. That is the fixture
// being honest about a real host's files, not a defect.
//
// **"Clean" here means the scan exits 0**, not that it produces no findings.
// Coverage is still 100 because a FAIL is an evaluated check, and posture stays
// well above the threshold asserted below.
//
// That last sentence is only true because the fixture carries an
// /etc/nsswitch.conf. FILESYS-0010 sees the same checkout ownership the CRON
// checks do, but it may not call an unresolvable owner stray until it knows the
// local files are the whole account database — so without that file it returns
// UNKNOWN rather than FAIL, and an UNKNOWN is not an evaluated check.
// TestTheHostFixtureCanReachAVerdictOnOwnership holds that property in place.
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

// runJSON is run with --json, for the tests that parse the output.
//
// The flag is spelled out at every call site rather than defaulted in the
// helper, because the default output format is now the terminal report and a
// test that silently got JSON would stop noticing if that changed.
func runJSON(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return run(t, append(args, "--json")...)
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
			evalCode, evalOut, _ := runJSON(t, "eval", bundlePath)
			scanCode, scanOut, _ := runJSON(t, "scan", "--root", fixture)

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

	if code, _, stderr := runJSON(t, "scan", "--root", hostFixture, "-o", path); code != cli.ExitOK {
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
	if code, _, _ := runJSON(t, "eval", bundlePath, "-o", evalReport); code != cli.ExitOK {
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

	// Both renderers, because both are things a person diffs against last
	// week's run. The terminal report is not the API and is still not allowed
	// to be noisy: a nightly scan whose output churns is one nobody reads.
	for _, format := range []string{"json", "terminal"} {
		t.Run(format, func(t *testing.T) {
			_, first, _ := run(t, "eval", bundlePath, "--format", format)
			if first == "" {
				t.Fatal("eval produced nothing; this test would prove nothing")
			}
			for i := 0; i < 10; i++ {
				if _, got, _ := run(t, "eval", bundlePath, "--format", format); got != first {
					t.Fatalf("evaluation %d differs from the first", i)
				}
			}
		})
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
		// No gates were requested, so findings alone must not change the exit
		// code — that is the whole point of --fail-on being opt-in.
		{"a baseline host with no gates", []string{"scan", "--root", hostFixture}, cli.ExitOK},
		{"a failing host with no gates is still 0", []string{"scan", "--root", failFixture}, cli.ExitOK},
		{"--fail-on high catches a HIGH failure", []string{"scan", "--root", failFixture, "--fail-on", "high"}, 2},
		{"--fail-on critical catches a CRITICAL failure", []string{"scan", "--root", failFixture, "--fail-on", "critical"}, 2},
		// The "does not fire" half of the gate needs a host whose worst
		// failure is below the threshold. sshd-permit-yes stopped being that
		// host when SSHD-0004 (PermitEmptyPasswords, CRITICAL) was added to
		// the catalog, so this case moved to a fixture that fails at HIGH and
		// no higher — which is the property the case is actually asserting.
		{"--fail-on critical does not fire below it", []string{"scan", "--root", includeFixture, "--fail-on", "critical"}, cli.ExitOK},
		// Measured at 91.96 on this fixture with catalog 7. 50 keeps a wide
		// margin over the CRON failures that are structural here, so the case
		// asserts the gate rather than tracking the catalog.
		{"--threshold below posture", []string{"scan", "--root", hostFixture, "--threshold", "50"}, cli.ExitOK},
		// 100 rather than a middling number: posture is a ratio over the whole
		// catalog, so any threshold below 100 stops discriminating as modules
		// are added and the one FAIL on this fixture is diluted. A host with
		// at least one FAIL can never reach 100, which makes this the only
		// threshold that keeps asserting the gate rather than the size of the
		// catalog.
		{"--threshold above posture", []string{"scan", "--root", failFixture, "--threshold", "100"}, 3},
		// 100 still holds despite the CRON failures: coverage counts checks
		// that reached a verdict, and a FAIL is a verdict. It would only drop
		// if a check went UNKNOWN or the collector could not see the host.
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
		{"an unknown format", []string{"scan", "--root", hostFixture, "--format", "yaml"}},
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
	_, stdout, _ := runJSON(t, "scan", "--root", hostFixture)
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
	code, scanOut, _ := runJSON(t, "scan", "--root", hostFixture, "--save-bundle", path)
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

	_, evalOut, _ := runJSON(t, "eval", path)
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

// ---------------------------------------------------------------------------
// output format (WP-26)
// ---------------------------------------------------------------------------

// TestTerminalIsTheDefaultFormat. The default is what an engineer gets when
// they type the command they were going to type anyway, and a wall of JSON is
// not a report. The JSON is still there, behind a flag, and it is still the
// only thing anything may parse.
func TestTerminalIsTheDefaultFormat(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--root", hostFixture},
		{"eval", collectTo(t, hostFixture)},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, stdout, _ := run(t, args...)

			if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
				t.Fatalf("the default output is still JSON:\n%s", stdout[:min(len(stdout), 200)])
			}
			for _, want := range []string{"[+] ", "[ OK ]", "[=] Scan summary", "posture", "coverage"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("the default report omits %q", want)
				}
			}
		})
	}
}

// TestJSONFlagAndFormatJSONAgree: --json is shorthand, so the two spellings
// must produce the same bytes. A shorthand that renders differently is a
// second code path wearing the first one's name.
func TestJSONFlagAndFormatJSONAgree(t *testing.T) {
	bundlePath := collectTo(t, hostFixture)

	_, viaFlag, _ := run(t, "eval", bundlePath, "--json")
	_, viaFormat, _ := run(t, "eval", bundlePath, "--format", "json")

	if viaFlag != viaFormat {
		t.Error("--json and --format json produced different documents")
	}
	parse(t, viaFlag)
}

// TestContradictoryFormatFlagsAreAUsageError.
//
// --json is shorthand over the *default*, not an override of an explicit
// choice. Silently discarding a --format the operator typed is the same class
// of bug as silently accepting `--fail-on hgih`: they stated something, the
// tool did something else, and nothing said so.
func TestContradictoryFormatFlagsAreAUsageError(t *testing.T) {
	code, stdout, stderr := run(t, "scan", "--root", hostFixture, "--format", "terminal", "--json")
	if code != cli.ExitUsage {
		t.Errorf("exit = %d, want %d (usage)", code, cli.ExitUsage)
	}
	if stdout != "" {
		t.Errorf("a usage error still wrote a report to stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "contradict") {
		t.Errorf("stderr does not explain the contradiction: %q", stderr)
	}

	// But --json alongside --format json is not a contradiction, and refusing
	// it would break the obvious belt-and-braces invocation.
	if code, _, _ := run(t, "eval", collectTo(t, hostFixture), "--format", "json", "--json"); code != cli.ExitOK {
		t.Errorf("--format json --json exited %d, want 0", code)
	}
}

func TestUnknownFormatIsRefusedByName(t *testing.T) {
	for _, format := range []string{"yaml", "html", "TERMINAL!"} {
		code, _, stderr := run(t, "scan", "--root", hostFixture, "--format", format)
		if code != cli.ExitUsage {
			t.Errorf("--format %s exited %d, want %d", format, code, cli.ExitUsage)
		}
		if !strings.Contains(stderr, "unknown --format") {
			t.Errorf("--format %s: stderr does not name the problem: %q", format, stderr)
		}
	}

	// sarif is a real format as of WP-31, and the message for an unknown one
	// has to name it so an operator who mistypes learns what is available.
	if code, _, _ := run(t, "scan", "--root", hostFixture, "--format", "sarif"); code != cli.ExitOK {
		t.Errorf("--format sarif exited %d, want %d", code, cli.ExitOK)
	}
	if _, _, stderr := run(t, "scan", "--root", hostFixture, "--format", "yaml"); !strings.Contains(stderr, "sarif") {
		t.Errorf("the unknown-format message does not list sarif among the choices: %q", stderr)
	}
}

// TestFormatIsCaseInsensitive: an operator typing --format JSON has been
// unambiguous, and rejecting them teaches nothing.
func TestFormatIsCaseInsensitive(t *testing.T) {
	if code, stdout, stderr := run(t, "eval", collectTo(t, hostFixture), "--format", "JSON"); code != cli.ExitOK {
		t.Fatalf("--format JSON exited %d: %s", code, stderr)
	} else {
		parse(t, stdout)
	}
}

// TestNoAnsiReachesANonTerminal is the rule that matters most in practice.
//
// Every one of these writes somewhere that is not a terminal — a test buffer,
// a file — and an escape sequence in any of them is corruption of an artefact
// somebody reads later in something that is not a terminal.
func TestNoAnsiReachesANonTerminal(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.txt")

	cases := []struct {
		name string
		args []string
	}{
		{"a buffer", []string{"scan", "--root", hostFixture}},
		{"--no-color", []string{"scan", "--root", hostFixture, "--no-color"}},
		{"-o a file", []string{"scan", "--root", hostFixture, "-o", reportPath}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stdout, _ := run(t, tc.args...)
			if strings.Contains(stdout, "\033") {
				t.Errorf("an escape sequence reached stdout:\n%q", stdout)
			}
		})
	}

	body, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("-o wrote an empty file; the assertion below would prove nothing")
	}
	if bytes.Contains(body, []byte{0x1b}) {
		t.Errorf("an escape sequence was written into --output:\n%s", body)
	}
	if !bytes.Contains(body, []byte("Scan summary")) {
		t.Errorf("--output did not receive the terminal report:\n%s", body)
	}
}

// TestReportsWrittenWithOutputAreOwnerOnly. The terminal report names paths,
// accounts and misconfigurations; it is the same reconnaissance material the
// JSON is, and it goes through the same owner-only create.
func TestReportsWrittenWithOutputAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
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
}

// TestTheFormatDoesNotMoveTheExitCode.
//
// Rendering is display and gating is a verdict, and the two must not be able
// to influence one another. If they could, `--json` would be a way to change
// what CI concluded about a host.
func TestTheFormatDoesNotMoveTheExitCode(t *testing.T) {
	cases := [][]string{
		{"scan", "--root", failFixture, "--fail-on", "high"},
		{"scan", "--root", hostFixture, "--min-coverage", "100"},
		{"scan", "--root", hostFixture},
	}
	for _, base := range cases {
		t.Run(strings.Join(base[1:], " "), func(t *testing.T) {
			terminal, _, _ := run(t, base...)
			asJSON, _, _ := run(t, append(append([]string{}, base...), "--json")...)
			if terminal != asJSON {
				t.Errorf("exit code depends on the output format: terminal %d, json %d", terminal, asJSON)
			}
		})
	}
}

// TestTheTerminalReportNamesWhatItCouldNotDetermine. A report that lists
// failures and buries unknowns describes a cleaner host than the one it saw,
// and this is the end-to-end assertion of that.
func TestTheTerminalReportNamesWhatItCouldNotDetermine(t *testing.T) {
	root := deniedRoot(t)

	_, stdout, _ := run(t, "scan", "--root", root)
	for _, want := range []string{
		"Could not determine",
		"not passes",
		"Collection gaps",
		"[ UNKNOWN ]",
		"/etc/ssh/sshd_config",
		"degraded",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("a scan that could not read the host omits %q from its report:\n%s", want, stdout)
		}
	}
}

// collectTo runs collect against a fixture and returns the bundle path.
func collectTo(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "b.plb")
	if code, _, stderr := run(t, "collect", "--root", fixture, "-o", path); code != cli.ExitOK {
		t.Fatalf("collect exited %d: %s", code, stderr)
	}
	return path
}

// ---------------------------------------------------------------------------
// edge-case resilience (WP-27)
// ---------------------------------------------------------------------------

// TestACorruptedHostProducesNoConfidentVerdict is the work package's
// acceptance criterion, asserted end to end through the real binary path.
//
// edge-binary-everything replaces every file the collectors parse with the
// same kilobyte of pseudo-random bytes. That is not a contrived input: it is
// what a failed restore, a filesystem that lost its journal, or a half-written
// image looks like. Three things must hold, and the third is the one that
// matters.
//
//  1. The scan completes. No panic, no hang, and an exit code that says
//     something.
//  2. Every fact the collectors could not parse is named in fact_errors, so an
//     operator knows which files to go and look at.
//  3. **No check reports PASS or FAIL from any of those files.** A parser that
//     silently yields an empty configuration turns every negative assertion in
//     the catalog into a false PASS, and that is the single failure mode this
//     project exists to prevent.
func TestACorruptedHostProducesNoConfidentVerdict(t *testing.T) {
	const fixture = "../../testdata/fixtures/edge-binary-everything"

	code, stdout, stderr := runJSON(t, "scan", "--root", fixture)
	if code == cli.ExitInternal {
		t.Fatalf("the scan exited %d (internal error): %s", code, stderr)
	}
	doc := parse(t, stdout)

	var parsed struct {
		Findings []struct {
			CheckID       string `json:"check_id"`
			Module        string `json:"module"`
			Result        string `json:"result"`
			UnknownReason string `json:"unknown_reason"`
			Detail        string `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatal(err)
	}
	var factErrors struct {
		FactErrors []struct {
			Fact string `json:"fact"`
			Kind string `json:"kind"`
			Path string `json:"path"`
		} `json:"fact_errors"`
	}
	if err := json.Unmarshal([]byte(stdout), &factErrors); err != nil {
		t.Fatal(err)
	}

	if len(factErrors.FactErrors) == 0 {
		t.Fatal("a host whose every configuration file is binary produced no fact errors at all; every parser swallowed the garbage")
	}
	for _, e := range factErrors.FactErrors {
		if e.Kind == "parse" && e.Path == "" {
			t.Errorf("fact error for %s names no path", e.Fact)
		}
	}

	// These modules read file *contents*. FILESYS, SERVICES and CRON read
	// metadata — modes, ownership, symlinks — which the fixture's bytes cannot
	// corrupt, so their verdicts are legitimate and are not listed here.
	contentModules := map[string]bool{
		"SSHD": true, "USERS": true, "AUTH": true, "LOGGING": true, "NETWORK": true,
	}
	for _, f := range parsed.Findings {
		if !contentModules[f.Module] {
			continue
		}
		if f.Result == "PASS" || f.Result == "FAIL" {
			t.Errorf("%s = %s from a file of random bytes. A parser that yields an empty configuration turns every absence claim into a false verdict:\n  %s",
				f.CheckID, f.Result, f.Detail)
		}
		if f.Result == "UNKNOWN" && f.UnknownReason == "" {
			t.Errorf("%s is UNKNOWN with no reason code", f.CheckID)
		}
	}

	if len(doc.Findings) == 0 {
		t.Error("the document carries no findings at all")
	}
}

// TestEveryEdgeFixtureScansWithoutCrashing. The blunt half of resilience: the
// binary must come back. An auditing tool that panics on a damaged host has
// told its operator nothing about the host and something alarming about
// itself.
func TestEveryEdgeFixtureScansWithoutCrashing(t *testing.T) {
	entries, err := os.ReadDir("../../testdata/fixtures")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "edge-") {
			continue
		}
		seen++
		t.Run(e.Name(), func(t *testing.T) {
			root := filepath.Join("../../testdata/fixtures", e.Name())
			for _, format := range []string{"json", "terminal"} {
				code, stdout, stderr := run(t, "scan", "--root", root, "--format", format)
				if code == cli.ExitInternal {
					t.Fatalf("--format %s exited %d (internal error): %s", format, code, stderr)
				}
				if stdout == "" {
					t.Errorf("--format %s produced no output", format)
				}
			}
		})
	}
	if seen == 0 {
		t.Fatal("no edge-* fixture was found; this test would pass on an empty corpus")
	}
}

// TestACorruptedBundleIsRefusedRatherThanEvaluated. A bundle is an archive with
// an integrity manifest, and a damaged one must not become a report: nothing
// can be said about a host from a file we cannot trust.
func TestACorruptedBundleIsRefusedRatherThanEvaluated(t *testing.T) {
	good := collectTo(t, hostFixture)
	body, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		make func() []byte
	}{
		{"truncated to half", func() []byte { return body[:len(body)/2] }},
		{"truncated to nothing", func() []byte { return nil }},
		{"a flipped byte in the middle", func() []byte {
			b := append([]byte(nil), body...)
			b[len(b)/2] ^= 0xff
			return b
		}},
		{"not an archive at all", func() []byte { return []byte("this is not a bundle\n") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "damaged.plb")
			if err := os.WriteFile(path, tc.make(), 0o600); err != nil {
				t.Fatal(err)
			}

			code, stdout, stderr := run(t, "eval", path)
			if code == cli.ExitOK {
				t.Fatalf("a damaged bundle evaluated cleanly:\n%s", stdout)
			}
			if code != cli.ExitInternal {
				t.Errorf("exit = %d, want %d: a bundle that will not open is an internal error, not a findings exit",
					code, cli.ExitInternal)
			}
			if stdout != "" {
				t.Errorf("a report was written from a bundle that could not be read:\n%s", stdout)
			}
			if stderr == "" {
				t.Error("nothing was said about why the bundle was refused")
			}
		})
	}
}

// TestTheHostFixtureCanReachAVerdictOnOwnership guards the one property of
// hostFixture that no other test can observe on the machine that runs it.
//
// `scan --root` uses the live seam, so every inode under the fixture carries
// the uid of whoever checked the repository out. That uid is 1000 on the
// author's machine, where it happens to match `alice` in the fixture's
// /etc/passwd and FILESYS-0010 returns PASS. It is 1001 on a GitHub runner and
// 0 in a container, where the owner does not resolve — and there the check must
// decide whether the local files are the whole account database before it may
// call that owner stray. Without /etc/nsswitch.conf it correctly refuses to
// decide and returns UNKNOWN(ambiguous_system_state), which drops coverage
// below 100 and fails the --min-coverage gate above on every machine except
// the author's. That is exactly how it reached CI unnoticed.
//
// The gate below asserts the fixture's side of that, not the check's, because
// the check is right either way. It fails on every machine if the file is
// removed, rather than only on the machines the author does not use.
func TestTheHostFixtureCanReachAVerdictOnOwnership(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(hostFixture, "etc", "nsswitch.conf"))
	if err != nil {
		t.Fatalf("hostFixture must carry /etc/nsswitch.conf so FILESYS-0010 can reach a verdict "+
			"under any checkout ownership: %v", err)
	}

	ns := fact.NSSwitch{State: fact.FilePresent, Path: "/etc/nsswitch.conf"}
	for _, line := range strings.Split(string(raw), "\n") {
		if db, sources, ok := fact.ParseNSSwitchLine(line); ok {
			ns.Databases = append(ns.Databases, fact.NSSwitchDB{Name: db, Sources: sources})
		}
	}

	for _, db := range []string{fact.NSSDBPasswd, fact.NSSDBGroup} {
		if !ns.LocalFilesAuthoritative(db) {
			sources, _ := ns.Sources(db)
			t.Errorf("nsswitch routes %q to %v; the fixture needs local files to be authoritative, "+
				"or FILESYS-0010 goes UNKNOWN on any checkout whose uid is absent from the fixture's passwd",
				db, sources)
		}
	}
}

// ---------------------------------------------------------------------------
// suppressions (WP-29)
// ---------------------------------------------------------------------------

// writeSuppressions puts a suppression file somewhere the CLI can read it and
// returns the path.
func writeSuppressions(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accepted.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the suppression file: %v", err)
	}
	return path
}

// failuresOf scans a fixture and returns the fingerprint and check ID of every
// failing finding, which is what an operator would copy into their file.
//
// Every one of them, not the first: sshd-permit-yes fails several checks at
// HIGH and above, so a test that suppressed one and then asserted --fail-on
// had gone quiet would be asserting nothing.
func failuresOf(t *testing.T, root string) (fingerprints, checkIDs []string) {
	t.Helper()
	_, stdout, _ := runJSON(t, "scan", "--root", root)
	var doc struct {
		Findings []struct {
			CheckID     string `json:"check_id"`
			Result      string `json:"result"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parsing the scan document: %v", err)
	}
	for _, f := range doc.Findings {
		if f.Result == "FAIL" {
			fingerprints = append(fingerprints, f.Fingerprint)
			checkIDs = append(checkIDs, f.CheckID)
		}
	}
	if len(fingerprints) == 0 {
		t.Fatalf("%s produced no FAIL, so there is nothing to suppress", root)
	}
	return fingerprints, checkIDs
}

// suppressAll builds a file accepting every fingerprint given, with an
// optional expiry applied to all of them.
func suppressAll(t *testing.T, fingerprints []string, justification, expiresAt string) string {
	t.Helper()
	rules := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		r := fmt.Sprintf(`{"fingerprint":%q,"justification":%q`, fp, justification)
		if expiresAt != "" {
			r += fmt.Sprintf(`,"expires_at":%q`, expiresAt)
		}
		rules = append(rules, r+"}")
	}
	return writeSuppressions(t, fmt.Sprintf(`{"schema":"suppressions/v1","suppressions":[%s]}`,
		strings.Join(rules, ",")))
}

// TestSuppressingAFailureSilencesTheGateButNotTheReport is the end-to-end
// acceptance criterion. --fail-on stops firing, which is the point of
// accepting a risk; the finding is still in the document, which is the point
// of this project.
func TestSuppressingAFailureSilencesTheGateButNotTheReport(t *testing.T) {
	fps, checkIDs := failuresOf(t, failFixture)
	checkID := checkIDs[0]

	// Without the file, the gate fires.
	if code, _, _ := run(t, "scan", "--root", failFixture, "--fail-on", "high"); code != 2 {
		t.Fatalf("exit = %d, want 2 before suppression — this test proves nothing otherwise", code)
	}

	path := suppressAll(t, fps, "break-glass bastion, reviewed by platform-sec, SEC-4471", "")

	code, stdout, _ := run(t, "scan", "--root", failFixture, "--fail-on", "high", "--suppress", path)
	if code != cli.ExitOK {
		t.Errorf("exit = %d, want 0: an accepted risk must not fire --fail-on\n%s", code, stdout)
	}
	for _, want := range []string{checkID, "SEC-4471", "Accepted risks", "[ SUPPRESSED ]"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report omits %q; a suppression must not hide the finding:\n%s", want, stdout)
		}
	}
}

// TestSuppressionSurvivesTheBundleRoundTrip. scan and eval share one funnel,
// so a suppression applied to a live scan and to a bundle of that same scan
// have to agree — otherwise the answer depends on which command you typed.
func TestSuppressionSurvivesTheBundleRoundTrip(t *testing.T) {
	fps, _ := failuresOf(t, failFixture)
	path := suppressAll(t, fps, "accepted", "")

	bundlePath := filepath.Join(t.TempDir(), "b.plb")
	if code, _, e := run(t, "collect", "--root", failFixture, "-o", bundlePath); code != cli.ExitOK {
		t.Fatalf("collect failed: %s", e)
	}

	_, scanOut, _ := runJSON(t, "scan", "--root", failFixture, "--suppress", path)
	_, evalOut, _ := runJSON(t, "eval", bundlePath, "--suppress", path)

	if parse(t, scanOut).Findings == nil {
		t.Fatal("scan produced no findings")
	}
	if !bytes.Equal(parse(t, scanOut).Findings, parse(t, evalOut).Findings) {
		t.Errorf("scan and eval disagree once suppressions are applied:\n scan: %s\n eval: %s",
			parse(t, scanOut).Findings, parse(t, evalOut).Findings)
	}
}

// TestAnExpiredSuppressionStillFailsTheGate, end to end. The expiry is
// measured against the scan's own timestamp, and a fixture scan happens now,
// so a rule that lapsed in the past is spent.
func TestAnExpiredSuppressionStillFailsTheGate(t *testing.T) {
	fps, _ := failuresOf(t, failFixture)
	path := suppressAll(t, fps, "was temporary", "2020-01-01T00:00:00Z")

	code, stdout, stderr := run(t, "scan", "--root", failFixture, "--fail-on", "high", "--suppress", path)
	if code != 2 {
		t.Errorf("exit = %d, want 2: a lapsed acceptance must stop protecting the finding\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "expired") {
		t.Errorf("the lapse was not reported on stderr, so it is invisible: %q", stderr)
	}
}

// TestABadSuppressionFileIsAHardError. Continuing without the file would print
// a report full of findings the operator has already accepted, which they
// would reasonably read as the suppressions having applied and nothing having
// been accepted.
func TestABadSuppressionFileIsAHardError(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"a blank justification", `{"schema":"suppressions/v1","suppressions":[{"fingerprint":"00112233445566778899aabbccddeeff","justification":""}]}`},
		{"the wrong schema", `{"schema":"suppressions/v2","suppressions":[]}`},
		{"not JSON", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSuppressions(t, tc.body)
			code, _, stderr := run(t, "scan", "--root", hostFixture, "--suppress", path)
			if code != cli.ExitInternal {
				t.Errorf("exit = %d, want %d", code, cli.ExitInternal)
			}
			if !strings.Contains(stderr, "--suppress") {
				t.Errorf("the error does not name the flag that caused it: %q", stderr)
			}
		})
	}
}

// TestAMissingSuppressionFileIsAHardError. Silently scanning with no
// suppressions because the path was mistyped is the same failure as above,
// arrived at more easily.
func TestAMissingSuppressionFileIsAHardError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if code, _, _ := run(t, "scan", "--root", hostFixture, "--suppress", missing); code != cli.ExitInternal {
		t.Errorf("exit = %d, want %d for a missing --suppress file", code, cli.ExitInternal)
	}
}

// TestTheSuppressionPathIsNotRootPrefixed. A suppression file is a path the
// *operator* named, like the bundle, so --root must never be prefixed onto it
// (ADR-0011). Getting this wrong is silent: the file is simply not found
// inside the audited tree, and the scan runs with nothing suppressed.
func TestTheSuppressionPathIsNotRootPrefixed(t *testing.T) {
	fps, _ := failuresOf(t, failFixture)
	path := suppressAll(t, fps, "accepted", "")

	// The path is absolute and far outside failFixture. If --root were applied
	// to it the open would fail and the exit code would be ExitInternal.
	code, stdout, _ := run(t, "scan", "--root", failFixture, "--fail-on", "high", "--suppress", path)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d, want 0; --root was applied to an operator-named path", code)
	}
	if !strings.Contains(stdout, "Accepted risks") {
		t.Error("the suppression did not apply, so --root probably reached the operator's file")
	}
}

// TestAStaleSuppressionIsReported. Fingerprints change when a subject changes,
// so a suppression file rots. A rule that matches nothing is either a finding
// that got fixed or a rule that has quietly stopped covering what its author
// thought it covered.
func TestAStaleSuppressionIsReported(t *testing.T) {
	path := writeSuppressions(t, `{"schema":"suppressions/v1","suppressions":[
		{"fingerprint":"00112233445566778899aabbccddeeff","justification":"matches nothing on this host"}]}`)

	code, _, stderr := run(t, "scan", "--root", hostFixture, "--suppress", path)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stderr, "matched no failing finding") {
		t.Errorf("a stale rule was not reported: %q", stderr)
	}
}

// ---------------------------------------------------------------------------
// diff (WP-30)
// ---------------------------------------------------------------------------

// bundleOf collects a fixture into a bundle and returns the path.
func bundleOf(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "b.plb")
	// The exit code is not asserted: several fixtures collect degraded (exit
	// 4) because a collector cannot read something the fixture deliberately
	// withholds, and a degraded collection still produces a bundle worth
	// diffing. What matters is that the file exists.
	run(t, "collect", "--root", root, "-o", path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("collect %s produced no bundle: %v", root, err)
	}
	return path
}

// TestDiffReportsTheTransitionAndBothItsEnds is the acceptance criterion.
// Comparing a hardened host to a broken one must name the checks that moved,
// show what each was as well as what it became, and put a posture delta beside
// a coverage delta.
func TestDiffReportsTheTransitionAndBothItsEnds(t *testing.T) {
	oldB := bundleOf(t, "../../testdata/fixtures/sshd-hardened")
	newB := bundleOf(t, failFixture)

	code, stdout, stderr := run(t, "diff", oldB, newB)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	for _, want := range []string{
		"NEW FAILURE",
		"SSHD-0002",
		"PASS → FAIL", // both ends of the transition, not just the new one
		"posture",
		"coverage", // posture is never shown without it
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the diff omits %q:\n%s", want, stdout)
		}
	}
}

// TestDiffOfABundleWithItselfIsEmpty. The strongest statement of determinism
// available: the same facts through the same catalog must move nothing.
func TestDiffOfABundleWithItselfIsEmpty(t *testing.T) {
	b := bundleOf(t, hostFixture)

	code, stdout, _ := run(t, "diff", b, b)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "No change") {
		t.Errorf("a bundle diffed against itself reported changes:\n%s", stdout)
	}
	for _, mustNot := range []string{"NEW FAILURE", "RESOLVED", "REGRESSED"} {
		if strings.Contains(stdout, mustNot) {
			t.Errorf("the diff of a bundle with itself contains %q:\n%s", mustNot, stdout)
		}
	}
}

// TestDiffIsDeterministic, end to end. A nightly job that produces a different
// diff each run for an unchanged pair is a job people stop reading.
func TestDiffIsDeterministic(t *testing.T) {
	oldB := bundleOf(t, "../../testdata/fixtures/sshd-hardened")
	newB := bundleOf(t, failFixture)

	_, first, _ := run(t, "diff", oldB, newB)
	for i := 0; i < 5; i++ {
		if _, got, _ := run(t, "diff", oldB, newB); got != first {
			t.Fatalf("run %d differs from the first", i)
		}
	}
}

// TestDiffRefusesAMissingBundle, and says which of the two it was. "no such
// file" is not a useful message from a command that took two paths.
func TestDiffRefusesAMissingBundle(t *testing.T) {
	real := bundleOf(t, hostFixture)
	missing := filepath.Join(t.TempDir(), "nope.plb")

	for _, tc := range []struct{ name, a, b, want string }{
		{"the old one", missing, real, "OLD"},
		{"the new one", real, missing, "NEW"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, "diff", tc.a, tc.b)
			if code != cli.ExitInternal {
				t.Errorf("exit = %d, want %d", code, cli.ExitInternal)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("the error does not say which bundle was missing: %q", stderr)
			}
		})
	}
}

// TestDiffNeedsExactlyTwoArguments.
func TestDiffNeedsExactlyTwoArguments(t *testing.T) {
	b := bundleOf(t, hostFixture)
	for _, args := range [][]string{{"diff"}, {"diff", b}, {"diff", b, b, b}} {
		if code, _, _ := run(t, args...); code != cli.ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, cli.ExitUsage)
		}
	}
}

// TestDiffSeesASuppressionLapseBetweenTwoRuns is the transition that only
// exists because expiry is measured against each bundle's own scan time. One
// suppression file, two moments, two answers — and the diff shows the second
// one as a regression rather than as somebody having broken something.
func TestDiffSeesASuppressionLapseBetweenTwoRuns(t *testing.T) {
	oldB := bundleOf(t, failFixture)
	newB := bundleOf(t, failFixture)

	// Rewrite the OLD bundle's scan time to before the expiry and the NEW
	// bundle's to after it. Both bundles hold identical facts, so any change
	// the diff reports can only have come from the acceptance lapsing.
	rewriteScanTime(t, oldB, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rewriteScanTime(t, newB, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))

	fps, _ := failuresOf(t, failFixture)
	path := suppressAll(t, fps, "accepted until the June window", "2026-06-30T00:00:00Z")

	code, stdout, _ := run(t, "diff", oldB, newB, "--suppress", path)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "REGRESSED") {
		t.Errorf("a lapsed acceptance did not show as a regression:\n%s", stdout)
	}
	if !strings.Contains(stdout, "expired 2026-06-30T00:00:00Z") {
		t.Errorf("the diff does not say the acceptance expired, so the change looks like a break:\n%s", stdout)
	}
	if strings.Contains(stdout, "NEW FAILURE") {
		t.Errorf("a lapsed acceptance was reported as a new failure:\n%s", stdout)
	}
}

// TestDiffHasNoJsonOutputYet. Rendering the comparison as a document would be
// a second public API, and findings/v1 does not describe one. Refusing beats
// emitting a shape nothing has agreed to and that a pipeline would depend on.
func TestDiffHasNoJsonOutputYet(t *testing.T) {
	b := bundleOf(t, hostFixture)
	if code, _, _ := run(t, "diff", b, b, "--json"); code != cli.ExitUsage {
		t.Errorf("exit = %d, want %d", code, cli.ExitUsage)
	}
}

// rewriteScanTime rewrites a bundle's recorded scan start, which is the moment
// suppression expiry is measured against.
//
// It goes through bundle.Read and bundle.Write rather than editing bytes, so
// the integrity digests are recomputed and the result is a bundle the reader
// will accept. Two bundles that differ only in their timestamp is not a state
// a test can reach by collecting twice — the clock does not cooperate — and it
// is exactly the state the lapse transition needs.
func rewriteScanTime(t *testing.T, path string, at time.Time) {
	t.Helper()
	b := readBundle(t, path)
	b.Manifest.Scan.Started = at
	b.Manifest.Scan.Finished = at.Add(time.Second)

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("reopening %s: %v", path, err)
	}
	defer f.Close()
	if err := bundle.Write(f, b); err != nil {
		t.Fatalf("rewriting %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// findings document handed to a command that wants a bundle
// ---------------------------------------------------------------------------

// TestAFindingsDocumentIsRejectedInTermsTheOperatorUsed is the fix for the
// commonest mistake anyone makes with this tool. `scan --json > out.json` and
// `scan --save-bundle out.plb` are both "the output of a scan" from the
// outside, and handing the first to eval or diff used to produce
// `malformed bundle: reading tar: invalid input: magic number mismatch` — an
// accurate description of the sixth thing that went wrong and no help with the
// first.
func TestAFindingsDocumentIsRejectedInTermsTheOperatorUsed(t *testing.T) {
	_, doc, _ := runJSON(t, "scan", "--root", hostFixture)
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"eval", path},
		{"diff", path, path},
	} {
		t.Run(args[0], func(t *testing.T) {
			code, _, stderr := run(t, args...)
			if code != cli.ExitInternal {
				t.Errorf("exit = %d, want %d", code, cli.ExitInternal)
			}
			for _, want := range []string{
				"findings/v1 document", // what it actually is
				"not an evidence bundle",
				"--save-bundle", // and how to make the right thing
				"collect -o",
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("the error omits %q:\n%s", want, stderr)
				}
			}
			if strings.Contains(stderr, "magic number mismatch") {
				t.Errorf("the tar error leaked to the operator:\n%s", stderr)
			}
		})
	}
}

// TestABundleIsReadWhateverItIsNamed. The sniff is on content, not on the
// file's extension: a bundle an operator chose to call .json is still a
// bundle, and refusing it because of its name would replace one wrong answer
// with another.
func TestABundleIsReadWhateverItIsNamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "misleading-name.json")
	if code, _, stderr := run(t, "collect", "--root", hostFixture, "-o", path); code != cli.ExitOK {
		t.Fatalf("collect: %s", stderr)
	}
	if code, _, stderr := run(t, "eval", path); code != cli.ExitOK {
		t.Errorf("a bundle named .json was refused: exit %d, %s", code, stderr)
	}
}

// TestAnEmptyFileIsNotMistakenForAFindingsDocument. The sniff must not fire on
// anything that merely fails to be a bundle, or the advice it gives becomes
// wrong for every other kind of broken input.
func TestAnEmptyFileIsNotMistakenForAFindingsDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"whitespace", []byte("   \n\t ")},
		{"binary rubbish", []byte{0x00, 0x01, 0x02, 0x03, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "broken.plb")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			code, _, stderr := run(t, "eval", path)
			if code != cli.ExitInternal {
				t.Errorf("exit = %d, want %d", code, cli.ExitInternal)
			}
			if strings.Contains(stderr, "findings/v1 document") {
				t.Errorf("a non-JSON file was reported as a findings document:\n%s", stderr)
			}
		})
	}
}

// TestScanHelpNamesTheBundleFlag. The trap this fixes is one an operator falls
// into while reading --help, so the answer has to be there too.
func TestScanHelpNamesTheBundleFlag(t *testing.T) {
	_, stdout, _ := run(t, "scan", "--help")
	for _, want := range []string{"--save-bundle", "host.plb", "eval", "diff"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("scan --help does not mention %q", want)
		}
	}
}

// TestSarifIsAvailableFromBothCommands. scan and eval share one render funnel;
// a third format that only one of them could emit would mean the answer
// depended on which command was typed.
func TestSarifIsAvailableFromBothCommands(t *testing.T) {
	bundlePath := bundleOf(t, failFixture)

	for _, args := range [][]string{
		{"scan", "--root", failFixture, "--format", "sarif"},
		{"eval", bundlePath, "--format", "sarif"},
	} {
		t.Run(args[0], func(t *testing.T) {
			code, stdout, stderr := run(t, args...)
			if code != cli.ExitOK {
				t.Fatalf("exit = %d: %s", code, stderr)
			}
			var d struct {
				Version string `json:"version"`
				Runs    []struct {
					Results []struct {
						RuleID              string            `json:"ruleId"`
						Level               string            `json:"level"`
						PartialFingerprints map[string]string `json:"partialFingerprints"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal([]byte(stdout), &d); err != nil {
				t.Fatalf("output is not JSON: %v\n%s", err, stdout)
			}
			if d.Version != "2.1.0" {
				t.Errorf("version = %q, want 2.1.0", d.Version)
			}
			if len(d.Runs) != 1 || len(d.Runs[0].Results) == 0 {
				t.Fatalf("a failing fixture produced no SARIF results:\n%s", stdout)
			}
			for _, r := range d.Runs[0].Results {
				if r.PartialFingerprints["plumblineFingerprint/v1"] == "" {
					t.Errorf("%s carries no fingerprint", r.RuleID)
				}
			}
		})
	}
}

// TestSarifFingerprintsMatchTheFindingsDocument, end to end. The SARIF
// fingerprint and the one a suppression file matches on are the same string,
// or a team's GitHub dismissals and their suppression file drift apart.
func TestSarifFingerprintsMatchTheFindingsDocument(t *testing.T) {
	_, jsonOut, _ := runJSON(t, "scan", "--root", failFixture)
	_, sarifOut, _ := run(t, "scan", "--root", failFixture, "--format", "sarif")

	var findings struct {
		Findings []struct {
			Result      string `json:"result"`
			Fingerprint string `json:"fingerprint"`
			CheckID     string `json:"check_id"`
		} `json:"findings"`
	}
	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				RuleID              string            `json:"ruleId"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &findings); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(sarifOut), &sarifDoc); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{}
	for _, f := range findings.Findings {
		if f.Result == "FAIL" || f.Result == "UNKNOWN" {
			want[f.CheckID] = f.Fingerprint
		}
	}
	for _, r := range sarifDoc.Runs[0].Results {
		if got := r.PartialFingerprints["plumblineFingerprint/v1"]; got != want[r.RuleID] {
			t.Errorf("%s: SARIF %q != findings %q", r.RuleID, got, want[r.RuleID])
		}
	}
}

// TestSarifOmitsPassesThatTheFindingsDocumentCarries. The two formats are
// deliberately not the same document: SARIF results are things to act on.
func TestSarifOmitsPassesThatTheFindingsDocumentCarries(t *testing.T) {
	_, sarifOut, _ := run(t, "scan", "--root", hostFixture, "--format", "sarif")
	if strings.Contains(sarifOut, `"plumbline/result": "PASS"`) {
		t.Error("a PASS was emitted as a SARIF result")
	}
	if !strings.Contains(sarifOut, `"plumbline/counts"`) {
		t.Error("the passing checks were not counted in the invocation either — they vanished")
	}
}

// ---------------------------------------------------------------------------
// explain (WP-32)
// ---------------------------------------------------------------------------

// TestExplainPrintsTheWholeCatalogEntry. The command exists because the scan
// report deliberately omits remediation steps and commands; if they are not
// here they are nowhere an operator can reach from a terminal.
func TestExplainPrintsTheWholeCatalogEntry(t *testing.T) {
	code, stdout, stderr := run(t, "explain", "FILESYS-0010")
	if code != cli.ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	for _, want := range []string{
		"FILESYS-0010",
		"Every uid and gid owning a file resolves", // the title
		"FILESYS", // module
		"MEDIUM",  // base severity
		"What this checks",
		"uids are\n  reused", // description prose, reflowed
		"Facts it reads",
		"users.nsswitch", // a required fact
		"Remediation",
		"effort MEDIUM",
		"steps",
		"commands",
		"find / -xdev", // a command, verbatim
		"CAUTION",
		"References",
		"nist-800-53-r5",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("explain omits %q:\n%s", want, stdout)
		}
	}
}

// TestExplainNeedsNoHostAndNoBundle. A question about what a check asks is a
// question about this binary. Requiring a scan first would make the catalog
// unreadable on the machine where somebody is deciding whether to run one.
func TestExplainNeedsNoHostAndNoBundle(t *testing.T) {
	if code, _, _ := run(t, "explain", "SSHD-0002"); code != cli.ExitOK {
		t.Errorf("exit = %d; explain must not need a host or a bundle", code)
	}
}

// TestExplainRejectsAnUnknownCheckAndHelps. A bare "not found" is correct and
// unkind: the operator has a real check in mind and mistyped it.
func TestExplainRejectsAnUnknownCheckAndHelps(t *testing.T) {
	code, _, stderr := run(t, "explain", "FOO-0001")
	if code != cli.ExitUsage {
		t.Errorf("exit = %d, want %d", code, cli.ExitUsage)
	}
	for _, want := range []string{"FOO-0001", "not found"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the error omits %q: %q", want, stderr)
		}
	}

	// A wrong number in a real module gets that module's IDs back.
	_, _, stderr = run(t, "explain", "SSHD-9999")
	if !strings.Contains(stderr, "did you mean") || !strings.Contains(stderr, "SSHD-0002") {
		t.Errorf("a near miss in a real module was not suggested: %q", stderr)
	}
}

// TestExplainAcceptsTheIdAsTyped. Check IDs are upper-case by convention and
// lower-case to type; rejecting the latter would be the tool being right and
// useless at once.
func TestExplainAcceptsTheIdAsTyped(t *testing.T) {
	for _, id := range []string{"filesys-0010", "FileSys-0010", "  FILESYS-0010  "} {
		code, stdout, stderr := run(t, "explain", id)
		if code != cli.ExitOK {
			t.Errorf("explain %q exited %d: %s", id, code, stderr)
			continue
		}
		if !strings.Contains(stdout, "FILESYS-0010") {
			t.Errorf("explain %q did not resolve to the check", id)
		}
	}
}

// TestExplainNeedsExactlyOneArgument.
func TestExplainNeedsExactlyOneArgument(t *testing.T) {
	for _, args := range [][]string{{"explain"}, {"explain", "A-1", "B-2"}} {
		if code, _, _ := run(t, args...); code != cli.ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, code, cli.ExitUsage)
		}
	}
}

// TestEveryCheckInTheCatalogExplains is the sweep, and it is the test that
// earns its keep. A check added with an empty description or a remediation
// that overflows the grid is invisible until somebody asks about that one
// check — which is exactly when they most need it to be right.
func TestEveryCheckInTheCatalogExplains(t *testing.T) {
	for _, id := range catalogIDs(t) {
		code, stdout, stderr := run(t, "explain", id)
		if code != cli.ExitOK {
			t.Errorf("explain %s exited %d: %s", id, code, stderr)
			continue
		}
		if !strings.Contains(stdout, "What this checks") {
			t.Errorf("%s has no description", id)
		}
		if !strings.Contains(stdout, "Remediation") {
			t.Errorf("%s has no remediation", id)
		}
		for _, line := range strings.Split(stdout, "\n") {
			if n := len([]rune(line)); n > 78 && !isAtomic(line) {
				t.Errorf("%s: prose overflows the grid at %d columns:\n%s", id, n, line)
			}
		}
	}
}

// isAtomic reports whether a line is a single unbreakable value — a command, a
// URL, a cipher list — rather than prose.
//
// Such a line is allowed past the right edge, and that is the renderer working
// as designed rather than a gap in it. A KexAlgorithms list wrapped across two
// lines is one an operator cannot paste, and a wrapped URL is one they cannot
// click; both are values copied out of the report, and breaking them to keep a
// margin tidy trades the reader's actual task for the page's appearance.
// Prose has no such excuse, which is what this test is really asserting.
func isAtomic(line string) bool {
	trimmed := strings.TrimSpace(line)
	// A command is exempt whatever it contains. `chmod 700 a b c` broken
	// across two lines is a command that does something else when pasted, and
	// this is the one place in the tool whose output an operator is expected
	// to run.
	if strings.HasPrefix(trimmed, "$ ") {
		return true
	}
	return !strings.Contains(trimmed, " ")
}

// catalogIDs reads every check ID out of a scan, which is the only listing the
// CLI currently exposes. It doubles as an assertion that the two agree.
func catalogIDs(t *testing.T) []string {
	t.Helper()
	_, stdout, _ := runJSON(t, "scan", "--root", hostFixture)
	var doc struct {
		Findings []struct {
			CheckID string `json:"check_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parsing the scan document: %v", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range doc.Findings {
		if !seen[f.CheckID] {
			seen[f.CheckID] = true
			out = append(out, f.CheckID)
		}
	}
	if len(out) == 0 {
		t.Fatal("no check IDs found")
	}
	return out
}

// ---------------------------------------------------------------------------
// profiles (WP-33)
// ---------------------------------------------------------------------------

// TestProfilesListsTheBuiltins with the count each one selects, which is the
// number an operator is choosing between.
func TestProfilesListsTheBuiltins(t *testing.T) {
	code, stdout, stderr := run(t, "profiles")
	if code != cli.ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	for _, want := range []string{"default", "106/106", "cis-l1", "not a certified benchmark"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("profiles omits %q:\n%s", want, stdout)
		}
	}
}

// TestAProfileScalesThePostureDenominator is the acceptance criterion. A
// narrow baseline must not read as poor coverage: the profile declares what
// applies, so the applicable set is the profile.
func TestAProfileScalesThePostureDenominator(t *testing.T) {
	_, wide, _ := runJSON(t, "scan", "--root", hostFixture, "--profile", "default")
	_, narrow, _ := runJSON(t, "scan", "--root", hostFixture, "--profile", "cis-l1")

	w, n := summaryOf(t, wide), summaryOf(t, narrow)

	if n.Counts.Skipped == 0 {
		t.Fatal("cis-l1 skipped nothing, so this test proves nothing")
	}
	if n.Coverage < w.Coverage {
		t.Errorf("coverage fell from %.1f to %.1f when the question was scoped; "+
			"an excluded check must leave the denominator, not reduce it", w.Coverage, n.Coverage)
	}
	if n.Counts.Total != w.Counts.Total {
		t.Errorf("a profile changed the number of findings from %d to %d; "+
			"excluded checks must be reported as SKIPPED, never dropped",
			w.Counts.Total, n.Counts.Total)
	}
}

type profileSummary struct {
	Counts struct {
		Pass, Fail, NotApplicable, Skipped, Unknown, Total int
	} `json:"counts"`
	Posture  float64 `json:"posture"`
	Coverage float64 `json:"coverage"`
}

func summaryOf(t *testing.T, doc string) profileSummary {
	t.Helper()
	var d struct {
		Summary profileSummary `json:"summary"`
		Scan    struct {
			Profile string `json:"profile"`
		} `json:"scan"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("parsing the document: %v", err)
	}
	return d.Summary
}

// TestAnExcludedCheckIsSkippedAndSaysWhy. Never omitted, never
// NOT_APPLICABLE: the first would make a narrow profile look like a clean
// host, and the second would claim the subject is absent when it is the
// question that was withdrawn.
func TestAnExcludedCheckIsSkippedAndSaysWhy(t *testing.T) {
	_, doc, _ := runJSON(t, "scan", "--root", hostFixture, "--profile", "cis-l1")
	var d struct {
		Findings []struct {
			CheckID   string `json:"check_id"`
			Result    string `json:"result"`
			SkippedBy string `json:"skipped_by"`
			Detail    string `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range d.Findings {
		if f.CheckID != "SERVICES-0001" { // a module cis-l1 does not name
			continue
		}
		found = true
		if f.Result != "SKIPPED" {
			t.Errorf("result = %s, want SKIPPED", f.Result)
		}
		if f.SkippedBy != "cis-l1" {
			t.Errorf("skipped_by = %q, want cis-l1", f.SkippedBy)
		}
		if !strings.Contains(f.Detail, "cis-l1") {
			t.Errorf("the detail does not name the profile: %q", f.Detail)
		}
	}
	if !found {
		t.Error("an out-of-profile check was dropped from the document entirely")
	}
}

// TestTheActiveProfileIsInEveryOutput. A score that means something different
// depending on a flag has to say which flag was in force.
func TestTheActiveProfileIsInEveryOutput(t *testing.T) {
	_, jsonOut, _ := runJSON(t, "scan", "--root", hostFixture, "--profile", "cis-l1")
	if !strings.Contains(jsonOut, `"profile": "cis-l1"`) {
		t.Error("the findings document does not name the active profile")
	}
	_, textOut, _ := run(t, "scan", "--root", hostFixture, "--profile", "cis-l1")
	if !strings.Contains(textOut, "cis-l1") {
		t.Error("the terminal report does not name the active profile")
	}
	_, sarifOut, _ := run(t, "scan", "--root", hostFixture, "--format", "sarif", "--profile", "cis-l1")
	if !strings.Contains(sarifOut, `"plumbline/profile": "cis-l1"`) {
		t.Error("the SARIF run does not name the active profile")
	}
}

// TestACustomProfileFileIsAccepted, and is read through the operator-named
// seam so --root can never be prefixed onto it.
func TestACustomProfileFileIsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mine.json")
	body := `{"schema":"profile/v1","id":"mine","title":"Only sshd",
		"included_checks":["SSHD-*"],"severity_overrides":{"SSHD-0002":"LOW"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	code, doc, stderr := runJSON(t, "scan", "--root", failFixture, "--profile", path)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(doc, `"profile": "mine"`) {
		t.Error("the custom profile's id is not recorded")
	}

	var d struct {
		Findings []struct {
			CheckID      string `json:"check_id"`
			Severity     string `json:"severity"`
			BaseSeverity string `json:"base_severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Findings {
		if f.CheckID != "SSHD-0002" {
			continue
		}
		if f.Severity != "LOW" {
			t.Errorf("the override did not apply: severity = %s", f.Severity)
		}
		// The base is never moved, so an operator can always see that a
		// number was changed and from what.
		if f.BaseSeverity == "LOW" {
			t.Error("the override moved base_severity; adjustment must stay visible")
		}
	}
}

// TestABadProfileFailsFast. Falling back to the whole catalog would score a
// host against a baseline nobody asked for, and the operator would read the
// number as though their profile had applied.
func TestABadProfileFailsFast(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"profile/v9","id":"x","title":"x","included_checks":["*"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "nope.json")

	for _, tc := range []struct{ name, arg, want string }{
		{"an unknown name", "no-such-profile", "built-in profiles"},
		{"a malformed file", bad, "this build understands"},
		{"a missing file", missing, "--profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, "scan", "--root", hostFixture, "--profile", tc.arg)
			if code != cli.ExitUsage {
				t.Errorf("exit = %d, want %d", code, cli.ExitUsage)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("the error does not explain the problem: %q", stderr)
			}
		})
	}
}

// TestProfileAppliesToEvalToo. scan and eval share one funnel; a baseline that
// only one of them honoured would mean the score depended on which command was
// typed.
func TestProfileAppliesToEvalToo(t *testing.T) {
	bundlePath := bundleOf(t, hostFixture)

	_, scanOut, _ := runJSON(t, "scan", "--root", hostFixture, "--profile", "cis-l1")
	_, evalOut, _ := runJSON(t, "eval", bundlePath, "--profile", "cis-l1")

	if !bytes.Equal(parse(t, scanOut).Findings, parse(t, evalOut).Findings) {
		t.Error("scan and eval disagree once a profile is applied")
	}
}

// TestABundleFromASecretBearingHostCarriesNoSecret is the end-to-end form of
// the argument scrubber's promise, asserted where it actually matters.
//
// Every other test of that scrubber looks at a fact. This one runs the whole
// pipeline — collect, serialise, compress — over a fixture whose docker.service
// drop-in configures the splunk logging driver with its authentication token,
// and then searches every member of the resulting archive as bytes. A fact
// that was clean and a bundle that was not would be the only failure mode that
// matters, because the bundle is the thing that travels.
//
// The token is checked alongside a value that is not a secret at all. The
// scrubber does not keep a list of sensitive words: a log option's key is
// policy and its value is not, so max-size goes with splunk-token, and a
// future driver's credential option is covered before anybody has heard of it.
func TestABundleFromASecretBearingHostCarriesNoSecret(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "containers-docker-log-secret")
	path := filepath.Join(t.TempDir(), "secret.plb")

	// ExitDegraded is the expected code and not a problem here: a fixture root
	// holding a Docker host and nothing else has no /etc/passwd for the USERS
	// collector to read. The bundle is written either way, and the bundle is
	// what this test is about.
	if code, _, stderr := run(t, "collect", "--root", fixture, "-o", path); code != cli.ExitOK && code != cli.ExitDegraded {
		t.Fatalf("collect exit = %d: %s", code, stderr)
	}

	f, err := os.Open(path) //nolint:gosec // a path this test builds
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var found []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading archive: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s: %v", hdr.Name, err)
		}
		for _, secret := range []string{"secret123", "splunk.example.internal", "10m"} {
			if bytes.Contains(data, []byte(secret)) {
				found = append(found, hdr.Name+": "+secret)
			}
		}
		// The keys are meant to be there, and the marker with them: a reader
		// has to be able to tell "set, and not carried" from "not set".
		if hdr.Name == "facts/containers.docker_service.json" {
			if !bytes.Contains(data, []byte("splunk-token=[REDACTED]")) {
				t.Errorf("the fact does not show the option was set and withheld:\n%s", data)
			}
		}
	}
	if len(found) > 0 {
		t.Errorf("a bundle carries values from dockerd's command line: %v\n"+
			"    ExecStart is the one command line a bundle keeps, and --log-opt is\n"+
			"    where a logging driver's credentials are configured.", found)
	}
}

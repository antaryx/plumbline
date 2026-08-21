package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/cli"
	"github.com/antaryx/plumbline/internal/system"
)

// An interrupted run is tested by handing the command an already-cancelled
// context rather than by sending a signal, because those are two different
// claims and only one of them belongs here.
//
// internal/system's tests prove that SIGINT and SIGTERM produce a context
// cancelled with cause ErrInterrupted, and that the cause survives the two
// levels of derivation a scan puts beneath it. What is left to prove is what
// the CLI *does* with such a context, and that is ordinary data: no signal
// needs to be sent, nothing can escape into `go test`'s own process, and the
// test is deterministic rather than dependent on delivery timing.

// interruptedContext is what the process context looks like a moment after
// somebody pressed Ctrl-C.
func interruptedContext() context.Context {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(system.ErrInterrupted)
	return ctx
}

// TestAnInterruptedScanProducesNoReport.
//
// A findings document from a half-finished collection is the worst output this
// tool can emit. Every check whose facts never arrived resolves to UNKNOWN or
// NOT_APPLICABLE, the posture score is computed over whatever did arrive, and
// nothing on the page says a human stopped it — so it reads as a verdict on the
// host rather than as an abandoned run.
func TestAnInterruptedScanProducesNoReport(t *testing.T) {
	for _, format := range []string{"--json", "--format=terminal", "--format=sarif"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.ExecuteContext(interruptedContext(),
				[]string{"scan", format, "--root", hostFixture}, &stdout, &stderr)

			if code != cli.ExitInterrupted {
				t.Errorf("exit = %d, want %d (interrupted)\nstderr: %s", code, cli.ExitInterrupted, stderr.String())
			}
			if got := stdout.String(); got != "" {
				t.Errorf("an interrupted scan wrote %d byte(s) to stdout:\n%s", len(got), truncateForTest(got))
			}
			if !strings.Contains(stderr.String(), "interrupted") {
				t.Errorf("stderr does not say the run was interrupted: %q", stderr.String())
			}
		})
	}
}

// TestAnInterruptedScanSavesNoBundle. --save-bundle is a request for the
// evidence a report was drawn from, and there was no report.
func TestAnInterruptedScanSavesNoBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.plb")

	var stdout, stderr bytes.Buffer
	code := cli.ExecuteContext(interruptedContext(),
		[]string{"scan", "--json", "--root", hostFixture, "--save-bundle", path}, &stdout, &stderr)

	if code != cli.ExitInterrupted {
		t.Errorf("exit = %d, want %d\nstderr: %s", code, cli.ExitInterrupted, stderr.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("an interrupted scan saved a bundle; it holds half a host and says so nowhere")
	}
}

// TestAnInterruptedCollectWritesNoBundle.
//
// This is the stricter of the two artifact rules and deliberately so. A bundle
// assembled from a collection that stopped half way carries no mark saying it
// is partial: the manifest lists the facts that made it and is silent about the
// ones that did not, so months later it re-evaluates to a posture score drawn
// from half a host. The --timeout path does keep its bundle, because a budget
// is a decision to accept whatever fits inside it. An interrupt is not.
func TestAnInterruptedCollectWritesNoBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.plb")

	var stdout, stderr bytes.Buffer
	code := cli.ExecuteContext(interruptedContext(),
		[]string{"collect", "--root", hostFixture, "-o", path}, &stdout, &stderr)

	if code != cli.ExitInterrupted {
		t.Errorf("exit = %d, want %d\nstderr: %s", code, cli.ExitInterrupted, stderr.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Errorf("an interrupted collect wrote %s", path)
	}
	// And it says which file it did not write, because an operator who asked
	// for one and got neither a file nor an explanation will look for the file.
	if !strings.Contains(stderr.String(), path) {
		t.Errorf("stderr does not name the bundle that was not written: %q", stderr.String())
	}
}

// TestAnUninterruptedRunIsUnaffected. The gate above is a new early return on
// the hot path of both commands, and a guard that fires when it should not is
// a worse bug than the one it prevents.
func TestAnUninterruptedRunIsUnaffected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.plb")

	var stdout, stderr bytes.Buffer
	code := cli.ExecuteContext(context.Background(),
		[]string{"collect", "--root", hostFixture, "-o", path}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("an ordinary collect wrote no bundle: %v", err)
	}
}

// TestACancelledParentIsNotAnInterrupt. Only a signal exits 130. A context
// cancelled for any other reason is a collection that could not finish, which
// is a different thing and must not borrow the operator's exit code.
func TestACancelledParentIsNotAnInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := cli.ExecuteContext(ctx, []string{"scan", "--json", "--root", hostFixture}, &stdout, &stderr)

	if code == cli.ExitInterrupted {
		t.Error("a plainly cancelled context exited 130; 130 means the operator stopped the run")
	}
}

func truncateForTest(s string) string {
	if len(s) <= 300 {
		return s
	}
	return s[:300] + "…"
}

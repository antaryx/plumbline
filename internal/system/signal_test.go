package system_test

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/system"
)

// These tests send real signals to the test process, which is safe because
// signal.Notify is registered before the signal is sent and released by stop
// afterwards. The window in which SIGINT would reach the default handler and
// kill `go test` therefore never opens.
//
// A buffered channel is what makes that true even if the goroutine has not been
// scheduled yet: the runtime drops a signal it cannot deliver, and a Ctrl-C
// that does nothing is worse than no handler at all.

// waitDone fails rather than hangs. A signal test that blocks forever is a CI
// job that has to be cancelled by hand twenty minutes later.
func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the context was not cancelled within the deadline")
	}
}

// TestWithInterruptCancelsWithACause is the property the exit ladder rests on.
//
// A scan that ran out of its --timeout and a scan the operator stopped both
// arrive as a cancelled context, and they exit 11 and 130 respectively. If the
// reason were inferred from a flag set somewhere else, the two would eventually
// be read in the wrong order and a Ctrl-C would report a budget problem.
func TestWithInterruptCancelsWithACause(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, stop := system.WithInterrupt(context.Background())
			defer stop()

			if system.Interrupted(ctx) {
				t.Fatal("a fresh context reported itself interrupted")
			}
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatalf("sending %v to this process: %v", sig, err)
			}

			waitDone(t, ctx)
			if !errors.Is(context.Cause(ctx), system.ErrInterrupted) {
				t.Errorf("cause = %v, want ErrInterrupted", context.Cause(ctx))
			}
			if !system.Interrupted(ctx) {
				t.Error("Interrupted said no about a context cancelled by a signal")
			}
		})
	}
}

// TestInterruptedIsVisibleThroughADerivedContext.
//
// scan and collect do not use the process context directly: they derive a
// --timeout context from it, and the runner derives a per-collector budget
// below that. The exit code is decided at the top, from the context the command
// holds. So the reason has to survive two levels of derivation or the whole
// design collapses into threading a boolean through every layer.
func TestInterruptedIsVisibleThroughADerivedContext(t *testing.T) {
	ctx, stop := system.WithInterrupt(context.Background())
	defer stop()

	scanCtx, cancelScan := context.WithTimeout(ctx, time.Hour)
	defer cancelScan()
	collectorCtx, cancelCollector := context.WithTimeout(scanCtx, time.Minute)
	defer cancelCollector()

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("sending SIGINT to this process: %v", err)
	}
	waitDone(t, collectorCtx)

	for _, c := range []struct {
		name string
		ctx  context.Context
	}{
		{"the process context", ctx},
		{"the scan's --timeout context", scanCtx},
		{"a collector's budget context", collectorCtx},
	} {
		if !system.Interrupted(c.ctx) {
			t.Errorf("%s did not report the interrupt (cause %v)", c.name, context.Cause(c.ctx))
		}
		// The derived contexts carry deadlines that never fired. Reporting
		// DeadlineExceeded here is how a Ctrl-C would exit 11 and tell the
		// operator to raise a budget they did not exhaust.
		if errors.Is(c.ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("%s reported a deadline it never reached", c.name)
		}
	}
}

// TestADeadlineIsNotAnInterrupt is the other half of the same property.
func TestADeadlineIsNotAnInterrupt(t *testing.T) {
	ctx, stop := system.WithInterrupt(context.Background())
	defer stop()

	scanCtx, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	waitDone(t, scanCtx)

	if system.Interrupted(scanCtx) {
		t.Error("an expired budget was reported as an interrupt; it would exit 130 instead of 11")
	}
	if !errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", scanCtx.Err())
	}
}

// TestStopReleasesTheHandlerWithoutClaimingAnInterrupt. stop is called when the
// work is finished, which must not look retrospectively like a Ctrl-C.
func TestStopReleasesTheHandlerWithoutClaimingAnInterrupt(t *testing.T) {
	ctx, stop := system.WithInterrupt(context.Background())
	stop()
	waitDone(t, ctx)

	if system.Interrupted(ctx) {
		t.Error("a normal stop was reported as an interrupt")
	}
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Errorf("cause = %v, want context.Canceled", context.Cause(ctx))
	}
	// Idempotent: main calls stop once, but a caller who also defers it must
	// not panic on the second call.
	stop()
}

// TestAParentCancellationIsNotAnInterrupt. WithInterrupt wraps whatever it is
// given, and a caller that cancels the parent has not pressed anything.
func TestAParentCancellationIsNotAnInterrupt(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, stop := system.WithInterrupt(parent)
	defer stop()

	cancelParent()
	waitDone(t, ctx)

	if system.Interrupted(ctx) {
		t.Error("a cancelled parent was reported as an interrupt")
	}
}

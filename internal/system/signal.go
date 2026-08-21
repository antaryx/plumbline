package system

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// ErrInterrupted is the cancellation cause when a run was stopped by a signal.
//
// It exists because "the context is done" is not enough to answer the only
// question that matters afterwards: which exit code. A scan that ran out of
// its --timeout exits 11 and a scan the operator stopped exits 130, and both
// arrive as a cancelled context. Attaching the reason to the cancellation —
// rather than inferring it from a flag somewhere else — means the two can
// never be confused by a caller that checked in the wrong order.
var ErrInterrupted = errors.New("interrupted by signal")

// WithInterrupt returns a context that is cancelled, with cause
// ErrInterrupted, when the process receives SIGINT or SIGTERM.
//
// It lives in this package for the reason IsTerminal does: installing a signal
// handler is asking the operating system for something, and this package is
// the only one allowed to. Like IsTerminal it is deliberately *not* on the
// System interface — a signal is a property of this process, not an
// observation about the host being audited, and running it beneath --root
// would be meaningless.
//
// **The second signal kills.** The handler is uninstalled the moment the first
// one arrives, which restores the default disposition, so a second Ctrl-C
// terminates the process immediately. That is the behaviour an operator
// expects and it is the safety valve for the case this function cannot cover:
// a collector wedged in a syscall that never returns. The first press asks the
// scan to stop and get the terminal back into a sane state; the second press
// does not ask.
//
// The returned stop function releases the handler and cancels the context. Call
// it when the work is finished, the way signal.NotifyContext's does.
func WithInterrupt(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)

	// Buffered, because signal delivery must never block. An unbuffered
	// channel here would mean a signal arriving before the goroutine is
	// scheduled is dropped by the runtime, and a Ctrl-C that does nothing is
	// worse than no handler at all.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		defer signal.Stop(ch)
		select {
		case <-ch:
			cancel(ErrInterrupted)
		case <-ctx.Done():
			// Finished normally, or the caller called stop. Either way there
			// is nothing left to interrupt, and the deferred Stop hands the
			// signals back to the runtime.
		}
	}()

	return ctx, func() { cancel(context.Canceled) }
}

// Interrupted reports whether ctx was cancelled by a signal rather than by a
// deadline or by its caller.
//
// context.Cause walks up the chain, so this stays true for the derived
// contexts a scan builds beneath the process one — the per-scan --timeout
// context and the per-collector budget below it. That is what lets the answer
// be asked at the top, where the exit code is decided, rather than threaded
// down through every layer that might have been the one to notice.
func Interrupted(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrInterrupted)
}

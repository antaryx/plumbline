// Command plumbline audits a Linux host and reports what it found, what it
// could not determine, and why.
//
// This file is deliberately almost empty. Everything testable lives in
// internal/cli, which returns an exit code rather than calling os.Exit, so the
// exit-code ladder can be asserted in a unit test instead of by spawning
// processes and parsing output.
package main

import (
	"context"
	"os"

	"github.com/antaryx/plumbline/internal/cli"
	"github.com/antaryx/plumbline/internal/system"
	"github.com/antaryx/plumbline/internal/version"
)

// Stamped by the Makefile's -ldflags. The catalog version is not stamped: it is
// compiled in, and asking the catalog is the only answer that cannot drift from
// what actually runs.
var (
	buildVersion = ""
	commit       = ""
	date         = ""
)

func main() {
	version.Set(buildVersion, commit, date)

	// The signal handler is installed here rather than inside cli.Execute
	// because this is the only place in the program that is a process. A test
	// calling Execute must not divert SIGINT away from `go test`, and a
	// package that installed a handler as a side effect of being called would
	// do exactly that. What the handler produces — a cancelled context — is
	// ordinary data, and every decision made from it is in internal/cli where
	// it can be tested without sending anyone a signal.
	ctx, stop := system.WithInterrupt(context.Background())
	code := cli.ExecuteContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

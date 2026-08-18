// Command plumbline audits a Linux host and reports what it found, what it
// could not determine, and why.
//
// This file is deliberately almost empty. Everything testable lives in
// internal/cli, which returns an exit code rather than calling os.Exit, so the
// exit-code ladder can be asserted in a unit test instead of by spawning
// processes and parsing output.
package main

import (
	"os"

	"github.com/antaryx/plumbline/internal/cli"
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
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}

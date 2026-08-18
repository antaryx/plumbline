package sshd_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antaryx/plumbline/internal/collect/collectors/sshd"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system/live"
)

// These cases are about the parser rather than the seam: a configuration file
// that is legal on disk but hostile to read. They run the real collector over a
// generated tree through the live System, so an Include actually globs and
// actually opens files.

// hostileConfig writes files into a temp scan root and returns the root.
// Contents are keyed by simulated absolute path.
func hostileConfig(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// collectFrom runs the collector and returns the fact, failing on any error and
// on any hang. A collector that does not return is the failure mode these tests
// exist to catch.
func collectFrom(t *testing.T, root string) (fact.SSHDConfig, *fact.Error) {
	t.Helper()

	type result struct {
		cfg fact.SSHDConfig
		err *fact.Error
	}
	done := make(chan result, 1)

	go func() {
		facts := fact.NewSet()
		if err := sshd.New().Collect(context.Background(), live.New(root), facts); err != nil {
			t.Errorf("Collect returned an unclassified error: %v", err)
		}
		cfg, ferr, _ := fact.Get[fact.SSHDConfig](facts, fact.SSHDConfigID)
		done <- result{cfg, ferr}
	}()

	select {
	case r := <-done:
		return r.cfg, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("the collector did not return; a bound that should have fired is not firing")
		return fact.SSHDConfig{}, nil
	}
}

// TestSelfIncludingConfig: a file that includes itself. sshd's own Include
// handling is recursive, so a scanner that mirrors it without a guard recurses
// until the stack goes.
func TestSelfIncludingConfig(t *testing.T) {
	root := hostileConfig(t, map[string]string{
		"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\nPermitRootLogin no\n",
	})

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}

	// The seen-set stops the cycle, and the directive after the Include is
	// still parsed: refusing the cycle must not mean abandoning the file.
	if len(cfg.Files) != 1 {
		t.Errorf("read %v; a self-include was followed", cfg.Files)
	}
	if d, ok := cfg.Effective("PermitRootLogin"); !ok || d.Value != "no" {
		t.Errorf("effective PermitRootLogin = %+v, want no", d)
	}
}

// TestMutuallyIncludingConfigs: a and b include each other.
func TestMutuallyIncludingConfigs(t *testing.T) {
	root := hostileConfig(t, map[string]string{
		"/etc/ssh/sshd_config": "Include /etc/ssh/b.conf\nPort 22\n",
		"/etc/ssh/b.conf":      "Include /etc/ssh/sshd_config\nPermitRootLogin no\n",
	})

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}
	if len(cfg.Files) != 2 {
		t.Errorf("read %v, want each file exactly once", cfg.Files)
	}
	if d, ok := cfg.Effective("PermitRootLogin"); !ok || d.Value != "no" {
		t.Errorf("effective PermitRootLogin = %+v", d)
	}
}

// TestIncludeChainHitsTheDepthLimit: twelve distinct files, each including the
// next. No cycle, so the seen-set never fires — the depth bound is the only
// thing that stops it, and the fact records that it stopped rather than
// pretending it read everything.
func TestIncludeChainHitsTheDepthLimit(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": "Include /etc/ssh/chain01.conf\n",
	}
	const depth = 12
	for i := 1; i <= depth; i++ {
		body := fmt.Sprintf("Port %d\n", 2200+i)
		if i < depth {
			body += fmt.Sprintf("Include /etc/ssh/chain%02d.conf\n", i+1)
		}
		files[fmt.Sprintf("/etc/ssh/chain%02d.conf", i)] = body
	}

	cfg, ferr := collectFrom(t, hostileConfig(t, files))
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}

	if len(cfg.UnresolvedIncludes) == 0 {
		t.Fatalf("a %d-deep include chain reported no unresolved includes; the depth bound did not fire", depth)
	}
	var marked bool
	for _, u := range cfg.UnresolvedIncludes {
		if strings.Contains(u, "include depth limit reached") {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the depth limit fired without saying so: %v", cfg.UnresolvedIncludes)
	}
	// It stopped, and it stopped at the bound rather than somewhere arbitrary.
	if len(cfg.Files) > depth {
		t.Errorf("read %d files from a chain the bound should have cut short", len(cfg.Files))
	}
	// A check reading this must not conclude anything from what is missing:
	// the unresolved include is exactly the signal that makes it say UNKNOWN.
	if _, ok := cfg.Effective("PermitRootLogin"); ok {
		t.Error("PermitRootLogin was resolved from a truncated include chain")
	}
}

// TestZeroByteConfig: an empty file is a legal configuration, and it means
// "every default applies" rather than "no sshd here".
func TestZeroByteConfig(t *testing.T) {
	root := hostileConfig(t, map[string]string{"/etc/ssh/sshd_config": ""})

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}
	if !cfg.Installed {
		t.Error("a zero-byte config was reported as sshd not being configured")
	}
	if len(cfg.Directives) != 0 {
		t.Errorf("a zero-byte config produced %d directives", len(cfg.Directives))
	}
	if _, ok := cfg.Effective("PermitRootLogin"); ok {
		t.Error("a directive was found in an empty file")
	}
}

// TestCRLFLineEndings: a config edited on Windows, or written by a
// configuration-management tool that does not know better. The carriage return
// must not become part of the value — "no\r" is not "no", and a check comparing
// strings would report a hardened host as misconfigured.
func TestCRLFLineEndings(t *testing.T) {
	root := hostileConfig(t, map[string]string{
		"/etc/ssh/sshd_config": "# comment\r\nPort 22\r\nPermitRootLogin no\r\n\r\nX11Forwarding yes\r\n",
	})

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}

	d, ok := cfg.Effective("PermitRootLogin")
	if !ok {
		t.Fatal("PermitRootLogin was not found in a CRLF file")
	}
	if d.Value != "no" {
		t.Errorf("value = %q, want %q; the carriage return was not stripped", d.Value, "no")
	}
	for _, got := range cfg.Directives {
		if strings.ContainsAny(got.Value+got.Keyword, "\r\n") {
			t.Errorf("directive %+v carries a line ending", got)
		}
	}
	if len(cfg.Directives) != 3 {
		t.Errorf("parsed %d directives, want 3", len(cfg.Directives))
	}
}

// TestConfigWithHostileContent: the file parses, and nothing in it is
// interpreted as anything but data. Sanitisation happens on the way out of a
// check (THREAT-MODEL.md T-03); the collector's job is to record faithfully.
func TestConfigWithHostileContent(t *testing.T) {
	esc := string(rune(0x1b))
	root := hostileConfig(t, map[string]string{
		"/etc/ssh/sshd_config": "Banner /etc/" + esc + "[2J" + esc + "[H-all-checks-passed\n" +
			"PermitRootLogin no\n" +
			strings.Repeat("# padding\n", 1000),
	})

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}
	if d, ok := cfg.Effective("PermitRootLogin"); !ok || d.Value != "no" {
		t.Errorf("effective PermitRootLogin = %+v, want no", d)
	}
	// Recorded as written: the collector does not sanitise, because a fact is
	// what the host says. The escape is neutralised where it would otherwise
	// reach a terminal, which is asserted in internal/catalog.
	b, ok := cfg.Effective("Banner")
	if !ok {
		t.Fatal("Banner was not parsed")
	}
	if !strings.Contains(b.Value, esc) {
		t.Error("the collector altered the value it observed")
	}
}

// TestUnreadableIncludeIsRecordedNotIgnored: a drop-in that cannot be read
// might hold the keyword a check is looking for, so it has to be recorded as
// unresolved. Ignoring it would let a check assert a default it cannot see.
func TestUnreadableIncludeIsRecordedNotIgnored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes cannot deny this process")
	}
	root := hostileConfig(t, map[string]string{
		"/etc/ssh/sshd_config":                  "Include /etc/ssh/sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/50-denied.conf": "PermitRootLogin yes\n",
	})
	denied := filepath.Join(root, "etc", "ssh", "sshd_config.d", "50-denied.conf")
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}

	cfg, ferr := collectFrom(t, root)
	if ferr != nil {
		t.Fatalf("collect: %v", ferr)
	}
	if len(cfg.UnresolvedIncludes) != 1 {
		t.Errorf("unresolved includes = %v, want the file that could not be read", cfg.UnresolvedIncludes)
	}
	if _, ok := cfg.Effective("PermitRootLogin"); ok {
		t.Error("a value was taken from a file that could not be read")
	}
}

package remediate_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/finding"
	"github.com/antaryx/plumbline/internal/remediate"
)

// TestThePAMFixStripsOnlyTheRulesItShould.
//
// **nullok is removed from pam_unix.so lines and from nothing else.** The same
// argument on pam_ldap or pam_sss is a different decision about a different
// credential store, and AUTH-0004 says nothing about it — an unaddressed
// substitution would silently make that decision too, on a host where the
// directory server is the thing actually authenticating people.
//
// The file is edited in place, so the check that it is copied aside first is
// part of the same claim: what the host looked like before must survive.
func TestThePAMFixStripsOnlyTheRulesItShould(t *testing.T) {
	sh := needSh(t)

	dir := t.TempDir()
	pam := filepath.Join(dir, "common-auth")
	const before = "# Debian common-auth\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		"auth\t[success=2 default=ignore]\tpam_unix.so obscure nullok_secure sha512\n" +
		"auth\t[success=1 default=ignore]\tpam_ldap.so nullok\n" +
		"auth\trequisite\t\t\tpam_deny.so\n"
	write(t, pam, before)

	script := runnable(t, sh, planFor(t, evidenceFinding("AUTH-0004", pam)))

	first := runScript(t, sh, dir, script, 1)
	second := runScript(t, sh, dir, script, 2)
	if first != second {
		t.Errorf("running twice changed the file again:\n%s\n---\n%s", first, second)
	}

	for _, want := range []string{
		"pam_unix.so\n",                // the bare rule, argument gone
		"pam_unix.so obscure sha512\n", // stripped from the middle
		"pam_ldap.so nullok\n",         // and left entirely alone
		"# Debian common-auth\n",       // comments untouched
		"pam_deny.so\n",                // unrelated rules untouched
	} {
		if !strings.Contains(first, want) {
			t.Errorf("the edited file is missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "pam_unix.so nullok") || strings.Contains(first, "nullok_secure") {
		t.Errorf("nullok survived on a pam_unix.so rule:\n%s", first)
	}

	// The backup is the original, not the previous run's output — which is the
	// whole point of the once-only guard, and what a naive `cp` on every run
	// would have destroyed on pass two.
	bak := read(t, pam+".bak")
	if bak != before {
		t.Errorf("the backup is not the original file:\n%s", bak)
	}
}

// TestThePermissionFixesUseTheRightCommandForTheirSubject.
//
// FILESYS-0003 is about world-writable **files** and FILESYS-0004 about
// world-writable **directories**, and they take opposite remedies. Removing the
// write bit from /tmp breaks the host; setting the sticky bit on a shared
// spool file does nothing at all. Getting these the wrong way round produces a
// script that is either useless or an outage, so the pairing is asserted.
func TestThePermissionFixesUseTheRightCommandForTheirSubject(t *testing.T) {
	sh := needSh(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "shared.conf")
	sub := filepath.Join(dir, "spool")
	write(t, file, "shared\n")
	if err := os.Mkdir(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o777); err != nil {
		t.Fatal(err)
	}

	plan := planFor(t,
		evidenceFinding("FILESYS-0003", file),
		evidenceFinding("FILESYS-0004", sub))
	script := remediate.Script(plan)

	if !strings.Contains(script, "chmod o-w -- "+file) {
		t.Errorf("FILESYS-0003 does not remove the world-write bit from the file:\n%s", script)
	}
	if !strings.Contains(script, "chmod a+t -- "+sub) {
		t.Errorf("FILESYS-0004 does not set the sticky bit on the directory:\n%s", script)
	}
	if strings.Contains(script, "chmod o-w -- "+sub) {
		t.Errorf("FILESYS-0004 removes the write permission from a shared directory:\n%s", script)
	}

	runScript(t, sh, dir, runnable(t, sh, plan), 1)
	runScript(t, sh, dir, runnable(t, sh, plan), 2)

	if mode := stat(t, file); mode&0o002 != 0 {
		t.Errorf("the file is still world-writable: %04o", mode)
	}
	if mode := stat(t, sub); mode&os.ModeSticky == 0 {
		t.Errorf("the directory has no sticky bit: %v", mode)
	}
	if mode := stat(t, sub); mode&0o002 == 0 {
		t.Errorf("the directory's shared write permission was taken away: %04o", mode)
	}
}

// TestTheCronFixRestoresOwnershipAndMode.
func TestTheCronFixRestoresOwnershipAndMode(t *testing.T) {
	sh := needSh(t)

	dir := t.TempDir()
	crontab := filepath.Join(dir, "crontab")
	write(t, crontab, "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n")
	if err := os.Chmod(crontab, 0o666); err != nil {
		t.Fatal(err)
	}

	plan := planFor(t, subjectFinding("CRON-0001", crontab))
	if script := remediate.Script(plan); !strings.Contains(script, "chown root:root -- "+crontab) {
		t.Errorf("the cron fix does not restore ownership:\n%s", script)
	}

	runScript(t, sh, dir, runnable(t, sh, plan), 1)
	runScript(t, sh, dir, runnable(t, sh, plan), 2)

	if mode := stat(t, crontab).Perm(); mode != 0o600 {
		t.Errorf("mode is %04o, want 0600", mode)
	}
}

// TestTheDockerFixMergesRatherThanRewrites.
//
// **daemon.json is JSON the daemon refuses to start on if it is malformed**, so
// a substitution that got a comma wrong takes Docker down at the next restart —
// which on many hosts is every workload on the machine. The fix parses it, sets
// one key, and leaves the rest alone.
//
// The second run is asserted to be a *complete* no-op rather than merely
// convergent: a run that found the key already correct rewrites nothing, so the
// operator's own formatting of the keys plumbline did not touch survives.
func TestTheDockerFixMergesRatherThanRewrites(t *testing.T) {
	sh := needSh(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("no python3: %v", err)
	}

	dir := t.TempDir()
	daemon := filepath.Join(dir, "daemon.json")
	const before = `{"log-driver": "json-file", "storage-driver": "overlay2"}`
	write(t, daemon, before)

	plan := planFor(t, subjectFinding("CONTAINERS-0001", daemon))
	script := runnable(t, sh, plan)

	first := runScript(t, sh, dir, script, 1)
	second := runScript(t, sh, dir, script, 2)
	if first != second {
		t.Errorf("a second run rewrote the file:\n%s\n---\n%s", first, second)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(first), &got); err != nil {
		t.Fatalf("the fix produced invalid JSON (%v):\n%s", err, first)
	}
	if got["userns-remap"] != "default" {
		t.Errorf("userns-remap = %v, want \"default\":\n%s", got["userns-remap"], first)
	}
	for k, want := range map[string]string{"log-driver": "json-file", "storage-driver": "overlay2"} {
		if got[k] != want {
			t.Errorf("the merge lost %s = %s:\n%s", k, want, first)
		}
	}
	if bak := read(t, daemon+".bak"); bak != before {
		t.Errorf("the backup is not the original:\n%s", bak)
	}

	// **Nothing from the host's daemon.json is in the script.** The collector
	// records this file's top-level key names and never their values, because
	// it holds registry mirrors, proxy URLs and storage paths and a bundle
	// travels — and a generated script that pasted the contents in would put
	// exactly that into a file an operator might attach to a ticket.
	for _, secret := range []string{"json-file", "overlay2"} {
		if strings.Contains(remediate.Script(plan), secret) {
			t.Errorf("the script embeds the host's daemon.json content (%q)", secret)
		}
	}
}

// TestADaemonJSONThatIsNotJSONIsRefused.
//
// The failure mode this rules out is the expensive one: a malformed file
// overwritten with a well-formed one that has lost whatever the operator meant
// to say, on a daemon that will not start either way.
func TestADaemonJSONThatIsNotJSONIsRefused(t *testing.T) {
	sh := needSh(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("no python3: %v", err)
	}

	dir := t.TempDir()
	daemon := filepath.Join(dir, "daemon.json")
	const broken = "{\"log-driver\": \"json-file\",,}\n"
	write(t, daemon, broken)

	plan := planFor(t, subjectFinding("CONTAINERS-0001", daemon))
	cmd := exec.Command(sh, "-c", runnable(t, sh, plan))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Errorf("the script rewrote a malformed daemon.json instead of refusing:\n%s", read(t, daemon))
	}
	if !strings.Contains(string(out), "not valid JSON") {
		t.Errorf("the refusal does not say why:\n%s", out)
	}
	if got := read(t, daemon); got != broken {
		t.Errorf("the file was changed despite the refusal:\n%s", got)
	}
}

// TestAScriptWithNoDockerCarriesNoJSONHelper.
//
// The helpers are emitted only where they are called. A script that defined a
// JSON merge for a host with no Docker on it would be three-quarters
// scaffolding an operator has to read past to reach the two lines that matter.
func TestAScriptWithNoDockerCarriesNoJSONHelper(t *testing.T) {
	sysctlOnly := remediate.Script(remediate.Generate(failures("KERNEL-0004"), remediate.Options{}))
	for _, unwanted := range []string{"plumbline_json_set", "plumbline_backup", "python3"} {
		if strings.Contains(sysctlOnly, unwanted) {
			t.Errorf("a sysctl-only script defines %q:\n%s", unwanted, sysctlOnly)
		}
	}

	// And the dependency is pulled in: plumbline_json_set calls
	// plumbline_backup, so a Docker-only script needs both even though nothing
	// in the body calls the backup directly.
	docker := remediate.Script(remediate.Generate(
		[]finding.Finding{subjectFinding("CONTAINERS-0001", "/etc/docker/daemon.json")},
		remediate.Options{}))
	for _, want := range []string{"plumbline_json_set()", "plumbline_backup()"} {
		if !strings.Contains(docker, want) {
			t.Errorf("the Docker script is missing %q:\n%s", want, docker)
		}
	}
	if strings.Contains(docker, "plumbline_sysctl_set()") {
		t.Errorf("a Docker-only script defines the sysctl helper:\n%s", docker)
	}
}

// TestEveryFixSaysWhatItDoesNotCover.
//
// A finding's evidence is capped, so a script built from it can be a partial
// list of a much larger problem — four hundred world-writable files reduced to
// five chmods. A partial list that does not say so reads as a complete one.
func TestEveryFixSaysWhatItDoesNotCover(t *testing.T) {
	script := remediate.Script(planFor(t, evidenceFinding("FILESYS-0003", "/srv/a", "/srv/b")))

	for _, want := range []string{
		"came from this scan's evidence, which is capped",
		"find / -xdev -type f -perm -0002 -ls",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script does not admit its list may be partial (%q):\n%s", want, script)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func needSh(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this machine: %v", err)
	}
	return sh
}

// evidenceFinding is a FAILing finding citing paths the way a real one does.
func evidenceFinding(checkID string, paths ...string) finding.Finding {
	f := failures(checkID)[0]
	for _, p := range paths {
		f.Evidence = append(f.Evidence, finding.NewEvidence(p, 0, "cited", ""))
	}
	// The synthetic "and N more" entry a capped evidence list ends with. It
	// carries no source and must never become a chmod target.
	f.Evidence = append(f.Evidence, finding.NewEvidence("", 0, "… and 397 more", ""))
	return f
}

// subjectFinding is a FAILing finding whose subject is the path to act on.
func subjectFinding(checkID, path string) finding.Finding {
	f := failures(checkID)[0]
	f.Subject = path
	return f
}

func planFor(t *testing.T, findings ...finding.Finding) remediate.Plan {
	t.Helper()
	plan := remediate.Generate(findings, remediate.Options{})
	if len(plan.Actions) != len(findings) {
		t.Fatalf("built %d action(s) from %d finding(s): %+v", len(plan.Actions), len(findings), plan.Unfixable)
	}
	return plan
}

// runnable strips the steps a unit test must not run.
//
// `sysctl` writes to the machine running the tests and `chown` needs root. Both
// are asserted as text instead; what is left is every step that operates on the
// temporary tree, which is what these tests are about.
func runnable(t *testing.T, _ string, plan remediate.Plan) string {
	t.Helper()
	var keep []string
	for _, l := range strings.Split(remediate.Script(plan), "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "sysctl ") || strings.HasPrefix(trimmed, "chown ") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

// runScript runs the script and returns what the file it edited now holds.
func runScript(t *testing.T, sh, dir, script string, pass int) string {
	t.Helper()
	cmd := exec.Command(sh, "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pass %d: %v\n%s\nscript:\n%s", pass, err, out, script)
	}
	return editedFile(t, dir)
}

// editedFile returns the one non-backup file in the temp tree that the script
// was pointed at. Each test builds exactly one.
func editedFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".bak") {
			continue
		}
		return read(t, filepath.Join(dir, e.Name()))
	}
	return ""
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stat(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// TestTheAppArmorFixStartsTheServiceAndEnforces.
//
// Two steps for two findings the check reports as one: a host with AppArmor
// switched off needs the service, a host with every profile in complain needs
// aa-enforce. Each is a no-op on the host that had only the other problem,
// which is what lets one action be correct for both.
func TestTheAppArmorFixStartsTheServiceAndEnforces(t *testing.T) {
	plan := planFor(t, failures("SERVICES-0010")...)
	script := remediate.Script(plan)

	for _, want := range []string{
		"systemctl enable --now apparmor",
		"aa-enforce /etc/apparmor.d/*",
		// The kernel command line is the one thing neither command can fix,
		// and a script that left the host silently unconfined would be worse
		// than one that says so.
		"apparmor=0",
		"/proc/cmdline",
		"update-grub",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the AppArmor fix omits %q:\n%s", want, script)
		}
	}

	// **It checks the command line and does not edit it.** Rewriting a boot
	// configuration from a heuristic is how a machine stops booting.
	for _, forbidden := range []string{"sed -i /etc/default/grub", "update-grub\n"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("the AppArmor fix edits the boot configuration (%q):\n%s", forbidden, script)
		}
	}
	if !strings.Contains(script, "systemctl enable --now") || strings.Contains(script, "systemctl start apparmor") {
		t.Errorf("the service is started without being enabled, so it dies at the next reboot:\n%s", script)
	}
}

// TestTheFirewallFixDeclinesAHostThatAlreadyHasAManager.
//
// **This is the refusal that matters more than the fix.** A host whose firewall
// is nftables or firewalld already has a ruleset; `ufw enable` beside it
// produces the two-managers state NETWORK-0003 exists to report, where the one
// that ran last flushes what the other installed and whoever maintains the
// loser's file is editing something with no effect. It cannot be made safe with
// a comment, so the finding goes to Unfixable instead.
func TestTheFirewallFixDeclinesAHostThatAlreadyHasAManager(t *testing.T) {
	// **The first case is the one this was wrong about.** A "no firewall
	// anywhere" finding cites *every* candidate the collector probed, each
	// saying it does not exist — so a rule that matched /etc/nftables.conf in
	// the path list declined the one host the ufw fix is unambiguously right
	// for. Presence has to be read out of the excerpt, not inferred from the
	// collector having looked.
	probedEverything := []finding.Evidence{
		finding.NewEvidence("/etc/nftables.conf", 0, "does not exist", ""),
		finding.NewEvidence("/etc/iptables/rules.v4", 0, "does not exist", ""),
		finding.NewEvidence("/etc/ufw/ufw.conf", 0, "does not exist", ""),
	}

	for _, c := range []struct {
		name    string
		cited   []finding.Evidence
		wantFix bool
	}{
		{"nothing cited at all", nil, true},
		{"every candidate probed and none found", probedEverything, true},
		{"ufw, switched off", []finding.Evidence{
			finding.NewEvidence("/etc/ufw/ufw.conf", 0, "ufw configuration, 3 statement(s); ENABLED=no", ""),
		}, true},
		{"an nftables ruleset", []finding.Evidence{
			finding.NewEvidence("/etc/nftables.conf", 0, "nftables configuration, 12 statement(s)", ""),
		}, false},
		{"saved iptables rules", []finding.Evidence{
			finding.NewEvidence("/etc/iptables/rules.v4", 0, "iptables configuration, 40 statement(s)", ""),
		}, false},
		{"firewalld", []finding.Evidence{
			finding.NewEvidence("/etc/firewalld/zones/public.xml", 0, "firewalld configuration, 2 statement(s)", ""),
		}, false},
		{
			// An excerpt shape this build has never seen counts as a firewall
			// in play. Declining is the harmless direction; proposing ufw
			// beside a live nftables ruleset is not.
			name: "an unrecognised excerpt is treated as present",
			cited: []finding.Evidence{
				finding.NewEvidence("/etc/nftables.conf", 0, "something new", ""),
			},
			wantFix: false,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := failures("NETWORK-0002")[0]
			f.Evidence = c.cited

			plan := remediate.Generate([]finding.Finding{f}, remediate.Options{})
			if got := len(plan.Actions) == 1; got != c.wantFix {
				t.Errorf("proposed a ufw fix = %v, want %v", got, c.wantFix)
			}
			if !c.wantFix && len(plan.Unfixable) != 1 {
				t.Errorf("the declined finding was dropped instead of carried: %+v", plan)
			}
		})
	}
}

// TestTheFirewallFixAllowsSSHBeforeItDenies.
//
// **Order is the whole safety of this action.** `ufw default deny incoming`
// followed by `ufw enable`, on a host being administered over SSH, ends the
// session that ran it and locks the operator out — which is precisely the
// outcome PROJECT-BRIEF.md §1.3 names as the reason this tool does not apply
// its own scripts. The allow rule has to come first, and the script has to say
// that the port is a guess.
func TestTheFirewallFixAllowsSSHBeforeItDenies(t *testing.T) {
	script := remediate.Script(planFor(t, failures("NETWORK-0002")...))

	allow := strings.Index(script, "ufw allow 22/tcp")
	deny := strings.Index(script, "ufw default deny incoming")
	enable := strings.Index(script, "ufw --force enable")

	switch {
	case allow < 0 || deny < 0 || enable < 0:
		t.Fatalf("the ufw fix is incomplete:\n%s", script)
	case allow > deny, deny > enable:
		t.Errorf("the order locks the operator out: allow at %d, deny at %d, enable at %d\n%s",
			allow, deny, enable, script)
	}

	for _, want := range []string{
		"will disconnect you if you are on SSH",
		"22/tcp is a guess",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script does not warn about the port (%q):\n%s", want, script)
		}
	}
	// --force, because `ufw enable` prompts and a script that blocks on a
	// prompt inside a pipeline hangs rather than fails.
	if !strings.Contains(script, "ufw --force enable") {
		t.Errorf("ufw enable would prompt:\n%s", script)
	}
}

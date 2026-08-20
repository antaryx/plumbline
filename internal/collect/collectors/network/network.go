// Package network collects the host firewall configuration.
//
// It reads files and nothing else. There is no `nft list ruleset`, no
// `iptables -S` and no `ufw status`, because a scan must work against a
// mounted image and a bundle collected months ago as well as against a live
// host — and because running a firewall tool as root to ask it a question is a
// larger operation than reading the file it was configured from.
//
// The consequence is stated in every check that depends on it: this module
// reports what is **configured**, not what is loaded in the kernel right now.
// A host whose nftables.conf is perfect and whose nftables.service is disabled
// has no firewall, and only the SERVICES module can see that half. Neither
// module claims the other's half.
//
// **No ruleset contents reach the fact.** A firewall configuration is a map of
// the network — internal ranges, which hosts reach which ports, where the
// management network is — and a bundle designed to travel would carry it to
// wherever the bundle is filed. Only the derived properties the checks read
// are kept, plus the single policy line a finding has to quote.
package network

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "network"

// Candidate paths, in record order.
const (
	NFTablesPath      = "/etc/nftables.conf"
	NFTablesRHELPath  = "/etc/sysconfig/nftables.conf"
	IPTablesRHELPath  = "/etc/sysconfig/iptables"
	IP6TablesRHELPath = "/etc/sysconfig/ip6tables"
	IPTablesDebPath   = "/etc/iptables/rules.v4"
	IP6TablesDebPath  = "/etc/iptables/rules.v6"
	UFWConfPath       = "/etc/ufw/ufw.conf"
	UFWDefaultPath    = "/etc/default/ufw"
	FirewalldPath     = "/etc/firewalld/firewalld.conf"
)

type candidate struct {
	path string
	kind fact.FirewallKind
}

// candidates is every path probed, in a fixed order so the fact is
// deterministic and every detail string built from it reads the same way.
func candidates() []candidate {
	return []candidate{
		{NFTablesPath, fact.FirewallNFTables},
		{NFTablesRHELPath, fact.FirewallNFTables},
		{IPTablesRHELPath, fact.FirewallIPTables},
		{IP6TablesRHELPath, fact.FirewallIPTables},
		{IPTablesDebPath, fact.FirewallIPTables},
		{IP6TablesDebPath, fact.FirewallIPTables},
		{UFWConfPath, fact.FirewallUFW},
		{FirewalldPath, fact.FirewallFirewalld},
	}
}

// maxRead bounds one configuration file. A hand-written ruleset is kilobytes;
// a generated one on a busy host can be a few megabytes, and anything past
// this cap is not a ruleset a person is maintaining.
const maxRead = 4 << 20 // 4 MiB

// Collector implements collect.Collector for the host firewall configuration.
type Collector struct{}

// New returns the network collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.FirewallID} }

// DependsOn is nil. Reading configuration files needs nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// Most of these files are world-readable, and the ones that are not degrade to
// a single SourceDenied record rather than to a module that never ran. An
// unprivileged scan can still tell that a firewall is configured, which is
// most of what this module asserts.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: nine bounded reads, no walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is ten seconds.
func (Collector) Timeout() time.Duration { return 10 * time.Second }

// Collect reads each candidate and derives what the checks need from it.
//
// It returns nil in every case. A file is present, absent, refused, or broken
// in a way worth recording verbatim, and all four are observations about the
// host rather than failures of the collector.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	f := fact.Firewall{}

	for _, c := range candidates() {
		// The deadline stopped us. Record what was gathered rather than
		// returning the context error: internal/collect.runner discards the
		// partial facts of a collector that errors while its context is done.
		//nolint:nilerr // error deliberately swallowed for graceful degradation; the records already collected are kept in the FactSet
		if err := ctx.Err(); err != nil {
			fs.Put(f)
			return nil
		}
		f.Sources = append(f.Sources, read(s, c))
	}

	fs.Put(f)
	return nil
}

// read turns one candidate into a record.
func read(s system.System, c candidate) fact.FirewallSource {
	rec := fact.FirewallSource{Kind: c.kind, Path: c.path}

	res, err := s.ReadFile(c.path, maxRead)
	switch {
	case err == nil && collect.NotText(res.Data) != "":
		// A ruleset file that is not text is not a ruleset. SourceError rather
		// than SourcePresent is the whole point: NETWORK-0001 counts present
		// sources, and a file of random bytes reported as present would be a
		// host told it has a firewall configured when nftables would refuse
		// to load that file.
		rec.State = fact.SourceError
		rec.Msg = collect.NotText(res.Data)
		return rec
	case err == nil:
		rec.State = fact.SourcePresent
		rec.Digest = res.SHA256
	case errors.Is(err, system.ErrNotExist):
		rec.State = fact.SourceAbsent
		return rec
	case errors.Is(err, system.ErrPermission):
		rec.State = fact.SourceDenied
		rec.Msg = "permission denied; run as root to read this file"
		return rec
	default:
		rec.State = fact.SourceError
		rec.Msg = err.Error()
		return rec
	}

	lines := strings.Split(string(res.Data), "\n")
	rec.Statements = countStatements(lines)

	switch c.kind {
	case fact.FirewallNFTables:
		parseNFTables(&rec, lines)
	case fact.FirewallIPTables:
		parseIPTables(&rec, lines)
	case fact.FirewallUFW:
		parseUFW(&rec, lines)
		// ufw's default policy lives in a second file, and a manager that is
		// switched on with an accept default is the case this exists to catch.
		if def, err := s.ReadFile(UFWDefaultPath, maxRead); err == nil && collect.NotText(def.Data) == "" {
			parseUFWDefaults(&rec, strings.Split(string(def.Data), "\n"))
		}
	case fact.FirewallFirewalld:
		parseFirewalld(&rec, lines)
	}
	return rec
}

// countStatements counts lines that are neither blank nor a comment.
//
// It is what distinguishes a configured firewall from an installed package.
// Debian's nftables package writes /etc/nftables.conf whether or not anybody
// has put a rule in it, and a check that treated the file's existence as a
// firewall would report every such host as protected.
func countStatements(lines []string) int {
	n := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n++
	}
	return n
}

// parseNFTables finds the input chain's policy.
//
// A chain declaration is written across one or two lines —
//
//	chain input {
//	    type filter hook input priority 0; policy drop;
//
// — so the search starts at the hook and continues to the end of the
// statement, which is the next semicolon-terminated `policy` or the closing
// brace. Stopping at the end of the hook's own line would miss the common
// formatting where the policy is placed underneath it.
func parseNFTables(rec *fact.FirewallSource, lines []string) {
	for i, raw := range lines {
		l := strings.TrimSpace(stripComment(raw))
		if !strings.Contains(l, "hook input") {
			continue
		}
		for j := i; j < len(lines) && j < i+8; j++ {
			seg := strings.TrimSpace(stripComment(lines[j]))
			if p, ok := policyWord(seg); ok {
				rec.Policy, rec.PolicyLine, rec.PolicyRaw = p, j+1, seg
				return
			}
			if strings.Contains(seg, "}") && j > i {
				break
			}
		}
	}
}

// policyWord extracts an nftables `policy <word>` from a fragment.
func policyWord(seg string) (fact.InputPolicy, bool) {
	idx := strings.Index(seg, "policy ")
	if idx < 0 {
		return fact.PolicyUndetermined, false
	}
	word := strings.Trim(strings.Fields(seg[idx+len("policy "):])[0], ";,")
	switch strings.ToLower(word) {
	case "drop", "reject":
		return fact.PolicyDeny, true
	case "accept":
		return fact.PolicyAllow, true
	default:
		return fact.PolicyUndetermined, false
	}
}

// parseIPTables reads the INPUT chain's policy out of an iptables-save file,
// where it is the second field of the `:INPUT` line.
func parseIPTables(rec *fact.FirewallSource, lines []string) {
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if !strings.HasPrefix(l, ":INPUT ") {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[1]) {
		case "DROP", "REJECT":
			rec.Policy = fact.PolicyDeny
		case "ACCEPT":
			rec.Policy = fact.PolicyAllow
		default:
			continue
		}
		rec.PolicyLine, rec.PolicyRaw = i+1, l
		return
	}
}

// parseUFW reads ENABLED= out of ufw.conf.
func parseUFW(rec *fact.FirewallSource, lines []string) {
	for _, raw := range lines {
		k, v, ok := shellAssignment(raw)
		if !ok || !strings.EqualFold(k, "ENABLED") {
			continue
		}
		switch strings.ToLower(v) {
		case "yes", "true", "1":
			rec.Enabled = fact.EnabledYes
		case "no", "false", "0":
			rec.Enabled = fact.EnabledNo
		}
		return
	}
}

// parseUFWDefaults reads DEFAULT_INPUT_POLICY out of /etc/default/ufw.
//
// The line number and path deliberately stay pointed at ufw.conf: the record
// is one source, and a finding that cited two files for one verdict would be
// harder to act on than one that names the manager and says what its default
// is. The raw text carries the file it came from.
func parseUFWDefaults(rec *fact.FirewallSource, lines []string) {
	for _, raw := range lines {
		k, v, ok := shellAssignment(raw)
		if !ok || !strings.EqualFold(k, "DEFAULT_INPUT_POLICY") {
			continue
		}
		switch strings.ToUpper(v) {
		case "DROP", "REJECT":
			rec.Policy = fact.PolicyDeny
		case "ACCEPT":
			rec.Policy = fact.PolicyAllow
		default:
			return
		}
		rec.PolicyRaw = UFWDefaultPath + ": " + strings.TrimSpace(raw)
		return
	}
}

// parseFirewalld derives the input policy from the default zone.
//
// firewalld has no policy keyword. Every shipped zone rejects what it does not
// explicitly allow except `trusted`, whose target is ACCEPT — so the default
// zone's name *is* the policy, and it is the one firewalld setting an operator
// can get catastrophically wrong in a single word.
func parseFirewalld(rec *fact.FirewallSource, lines []string) {
	for i, raw := range lines {
		k, v, ok := shellAssignment(raw)
		if !ok || !strings.EqualFold(k, "DefaultZone") {
			continue
		}
		if strings.EqualFold(v, "trusted") {
			rec.Policy = fact.PolicyAllow
		} else {
			rec.Policy = fact.PolicyDeny
		}
		rec.PolicyLine, rec.PolicyRaw = i+1, strings.TrimSpace(raw)
		return
	}
}

// shellAssignment splits a KEY=value line, dropping comments and quotes.
func shellAssignment(raw string) (string, string, bool) {
	l := strings.TrimSpace(stripComment(raw))
	idx := strings.Index(l, "=")
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(l[:idx])
	val := strings.TrimSpace(l[idx+1:])
	if unquoted, err := strconv.Unquote(val); err == nil {
		val = unquoted
	}
	return key, strings.Trim(val, `"'`), true
}

// stripComment removes a trailing comment. It does not try to respect quoting:
// none of the keys read here takes a value containing a '#', and a parser that
// guessed at shell quoting would be wrong in more cases than it was right.
func stripComment(l string) string {
	if i := strings.Index(l, "#"); i >= 0 {
		return l[:i]
	}
	return l
}

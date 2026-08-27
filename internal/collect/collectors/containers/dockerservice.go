package containers

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ServiceID is the identifier of the collector that reads docker.service.
//
// It is a second collector rather than another read inside the first one
// because the two answer to different failures. daemon.json is one file and
// either parses or does not; a systemd unit is assembled from a unit file and
// an unbounded set of drop-ins, any one of which can be unreadable while the
// rest are fine. Keeping them apart means a denied override.conf resolves
// CONTAINERS-0006 to UNKNOWN without touching the five checks that read the
// JSON, which have nothing to do with it and are perfectly answerable.
const ServiceID = "containers-service"

// unitRoots are systemd's unit search directories, highest precedence first.
//
// They are the SERVICES collector's roots, deliberately the same list: two
// collectors disagreeing about where systemd looks for units would be a bug
// that only shows up on the distribution neither author ran. As there, the
// duplicate between /usr/lib and /lib on a usr-merged host is detected by
// inode rather than by guessing which layout this host uses.
//
// /usr/local/lib/systemd/system is a search path too and is not listed, for
// the same reason SERVICES omits it: nothing packages Docker there, and adding
// a root to one collector and not the other is how the two lists start to
// drift.
var unitRoots = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	vendorRoot,
	"/lib/systemd/system",
}

// vendorRoot is where a package installs docker.service. It is named because
// it is also what an absent unit reports as the path it was looked for at: a
// reader told only that nothing was found does not know what was looked for.
const vendorRoot = "/usr/lib/systemd/system"

const (
	// maxUnitRead bounds one unit file or drop-in. The largest docker.service
	// any distribution ships is under 2 KiB; anything near this cap is not a
	// unit file.
	maxUnitRead = 1 << 20 // 1 MiB
	// maxDropIns bounds one docker.service.d listing. A busy host has three or
	// four drop-ins. A directory with thousands of them is not something to
	// read in a root process, and the truncation is recorded so that no
	// absence is concluded from the part that was read.
	maxDropIns = 1024
	// maxLinkHops bounds symlink following. systemctl link writes one hop;
	// more than a few is a loop or an attempt at one.
	maxLinkHops = 4
)

// ServiceCollector reads how systemd starts the Docker daemon.
//
// **The interesting file is usually not the unit file.** Every distribution
// ships the same vendor docker.service and it binds -H fd://, so a collector
// that read only the unit would report the stock answer on a host whose API is
// wide open — because the documented, and effectively the only, way to change
// a vendor unit's command line is a drop-in:
//
//	/etc/systemd/system/docker.service.d/override.conf
//	    [Service]
//	    ExecStart=
//	    ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375
//
// That is what `systemctl edit docker` writes and what every "expose the
// Docker API" tutorial on the internet tells an operator to create. Reading
// the drop-ins is therefore not a refinement of this collector; it is the
// collector. See applyDropIns for the precedence rules, which are systemd's
// and are not obvious.
//
// It reads through ReadOpaque, so the bytes of these files stay out of the
// bundle and only the ExecStart arguments travel. fact.DockerService explains
// why: a Docker host's override.conf is where proxy credentials live.
type ServiceCollector struct{}

// NewService returns the docker.service collector.
func NewService() ServiceCollector { return ServiceCollector{} }

func init() { collect.Register(NewService()) }

var _ collect.Collector = ServiceCollector{}

func (ServiceCollector) ID() string { return ServiceID }

func (ServiceCollector) Produces() []fact.ID { return []fact.ID{fact.DockerServiceID} }

// DependsOn is nil. This reads unit files and needs nothing observed first —
// in particular it does not depend on the daemon collector, because a unit
// that exposes the API is worth recording whether or not dockerd was found
// where that collector looks for it.
func (ServiceCollector) DependsOn() []string { return nil }

// Requires is CapNone. Unit directories and unit files are world-readable on
// every distribution — systemd --user and every unprivileged systemctl status
// depend on it. A drop-in an administrator wrote 0600 is refused, and that
// refusal is recorded against the one fragment rather than skipping the whole
// collector.
func (ServiceCollector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: a handful of stats, at most four small directory listings and
// a few bounded reads.
func (ServiceCollector) Cost() collect.Cost { return collect.Cheap }

// Timeout is five seconds, matching the daemon collector for the same reason.
func (ServiceCollector) Timeout() time.Duration { return 5 * time.Second }

// Collect observes docker.service and its drop-ins and records them in fs.
//
// It returns nil in every circumstance, for the reason the daemon collector
// does: the commonest cause of not reading a unit is that this host does not
// have one, which is an observation rather than a failure.
func (ServiceCollector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	u := fact.DockerService{Unit: fact.DockerServiceUnit}

	if ctx.Err() != nil {
		u.State = fact.DockerUnitError
		u.Msg = "the scan was abandoned before the unit was read"
		fs.Put(u)
		return nil
	}

	readService(s, &u)
	fs.Put(u)
	return nil
}

// readService fills u from the unit file and its drop-ins.
func readService(s system.System, u *fact.DockerService) {
	unitPath, found := findUnit(s, fact.DockerServiceUnit)
	if !found {
		// No unit file anywhere. Drop-ins alone start nothing — systemd will
		// not assemble a unit that has no unit file — so there is nothing
		// further to read and nothing to fold them onto.
		u.State = fact.DockerUnitAbsent
		// Path names where a package would have installed one, so a reader is
		// told what was looked for rather than only that nothing was found.
		u.Path = path.Join(vendorRoot, fact.DockerServiceUnit)
		u.Msg = "no docker.service in any systemd unit directory"
		return
	}

	u.Path = unitPath
	frag, data := readFragment(s, unitPath, fact.FragmentUnit)
	u.Fragments = append(u.Fragments, frag)
	u.Digest = frag.Digest
	u.State = frag.State
	u.Msg = frag.Msg

	if frag.State != fact.DockerUnitPresent {
		// Masked, denied, or unreadable. The drop-ins are not read: on a
		// masked unit they are irrelevant, and on an unreadable one the fold
		// they modify is already unknown, so reading them would produce an
		// ExecStart list assembled from a base nobody saw.
		return
	}

	execs := foldExecStart(nil, unitPath, data)
	execs = applyDropIns(s, u, execs)
	u.ExecStart = execs
}

// findUnit returns the highest-precedence unit file that exists.
//
// A path that cannot be stat'ed is treated as not present here and the probe
// moves on, which is the daemon collector's rule and has the same
// justification: a refused stat on one of four guesses must not stop the other
// three from answering. The consequence of being wrong is that a lower-
// precedence unit is read instead of a higher one — visible in Fragments,
// rather than a silent wrong answer.
func findUnit(s system.System, unit string) (string, bool) {
	for _, root := range unitRoots {
		p := path.Join(root, unit)
		if _, err := s.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// applyDropIns folds every drop-in systemd would apply onto execs.
//
// **The precedence rules are systemd's and they are two rules, not one.**
// Drop-ins are gathered from <root>/docker.service.d for every unit search
// root; a file whose *name* appears in more than one of them is taken from the
// highest-precedence root and the others are ignored entirely — which is how
// an administrator overrides a vendor drop-in without editing it. The surviving
// set is then applied in lexical order *by filename*, across all roots
// together, so 10-foo.conf from /usr/lib is applied before 20-bar.conf from
// /etc even though /etc outranks /usr/lib as a directory.
//
// Getting either rule wrong changes verdicts rather than details, because the
// last ExecStart to be applied is the one that runs.
func applyDropIns(s system.System, u *fact.DockerService, execs []fact.DockerExec) []fact.DockerExec {
	type candidate struct {
		name string
		path string
	}

	var winners []candidate
	seenName := make(map[string]string) // basename -> winning path
	seenDir := make(map[[2]uint64]bool) // dev+ino -> already listed

	for _, root := range unitRoots {
		dir := path.Join(root, fact.DockerServiceUnit+".d")

		fi, err := s.Stat(dir)
		if err != nil {
			if errors.Is(err, system.ErrNotExist) {
				continue
			}
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: unitStateFor(err),
				Msg:   "the drop-in directory could not be examined, so a drop-in in it may be unaccounted for",
			})
			continue
		}
		if !fi.IsDir {
			continue
		}
		// /lib/systemd/system and /usr/lib/systemd/system are one directory on
		// a usr-merged host. Listing it twice would make every drop-in in it
		// shadow itself, which is harmless for the fold and confusing in the
		// evidence.
		if fi.Ino != 0 {
			key := [2]uint64{fi.Dev, fi.Ino}
			if seenDir[key] {
				continue
			}
			seenDir[key] = true
		}

		res, err := s.ReadDir(dir, maxDropIns)
		if err != nil {
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: unitStateFor(err),
				Msg:   "the drop-in directory could not be listed, so a drop-in in it may be unaccounted for",
			})
			continue
		}
		if res.Truncated {
			u.Fragments = append(u.Fragments, fact.UnitFragment{
				Path:  dir,
				Kind:  fact.FragmentDropInDir,
				State: fact.DockerUnitTruncated,
				Msg:   "the drop-in directory listing hit the entry cap, so nothing may be concluded from what is missing from it",
			})
		}

		for _, e := range res.Entries {
			name := path.Base(e.Path)
			if !strings.HasSuffix(name, ".conf") || e.IsDir {
				continue
			}
			if won, dup := seenName[name]; dup {
				u.Fragments = append(u.Fragments, fact.UnitFragment{
					Path:       e.Path,
					Kind:       fact.FragmentDropIn,
					State:      fact.DockerUnitPresent,
					Shadowed:   true,
					ShadowedBy: won,
					Msg:        "systemd ignores this file: a higher-precedence directory holds a drop-in of the same name",
				})
				continue
			}
			seenName[name] = e.Path
			winners = append(winners, candidate{name: name, path: e.Path})
		}
	}

	// Lexical by filename across all roots, which is systemd's order and not
	// the order the roots were walked in.
	sort.Slice(winners, func(i, j int) bool { return winners[i].name < winners[j].name })

	for _, w := range winners {
		frag, data := readFragment(s, w.path, fact.FragmentDropIn)
		u.Fragments = append(u.Fragments, frag)
		if frag.State != fact.DockerUnitPresent {
			// Recorded and not folded. DockerService.Complete is what a check
			// consults before calling an empty host list a pass.
			continue
		}
		execs = foldExecStart(execs, w.path, data)
	}
	return execs
}

// readFragment reads one unit file or drop-in, following symlinks by hand.
//
// The seam opens with O_NOFOLLOW, so a symlinked unit — which is what
// `systemctl link` writes, and what a mask writes — comes back as
// ErrNotRegular rather than as its target. Following it here, one hop at a
// time and back through the seam, is what keeps --root governing where the
// read lands; a seam that resolved links itself would have dereferenced them
// against the real host.
func readFragment(s system.System, p string, kind fact.UnitFragmentKind) (fact.UnitFragment, []byte) {
	f := fact.UnitFragment{Path: p, Kind: kind}

	target := p
	for hop := 0; ; hop++ {
		fi, err := s.Stat(target)
		if err != nil {
			f.State, f.Msg = unitStateFor(err), errMsg(err)
			return f, nil
		}
		if !fi.IsSymlink {
			if !fi.IsRegular {
				f.State = fact.DockerUnitNotRegular
				f.Msg = "the path is neither a regular file nor a link to one"
				return f, nil
			}
			break
		}
		if hop >= maxLinkHops {
			f.State = fact.DockerUnitNotRegular
			f.Msg = "the symlink chain is too long to follow, which is a loop or an attempt at one"
			return f, nil
		}

		dest, err := s.Readlink(target)
		if err != nil {
			f.State, f.Msg = unitStateFor(err), errMsg(err)
			return f, nil
		}
		target = resolveLink(target, dest)
		f.Resolved = target

		// `systemctl mask` replaces the unit with a link to /dev/null, and
		// systemd then refuses to start it at all. Whatever the vendor unit
		// underneath says is not in force, so it must not be read as though it
		// were.
		if target == "/dev/null" {
			f.State = fact.DockerUnitMasked
			f.Msg = "the unit is masked: it is a symbolic link to /dev/null, so systemd will not start it"
			return f, nil
		}
	}

	res, err := s.ReadOpaque(target, maxUnitRead)
	if err != nil {
		f.State, f.Msg = unitStateFor(err), errMsg(err)
		return f, nil
	}
	f.Digest = res.SHA256
	if res.Truncated {
		f.State = fact.DockerUnitTruncated
		f.Msg = "the file exceeded the read cap, so directives past the cut were not read"
		return f, res.Data
	}
	if why := collect.NotText(res.Data); why != "" {
		// A regular file that is not text. Not DockerUnitNotRegular: the inode
		// is exactly what it claimed to be, and saying otherwise would send an
		// operator looking for a socket or a directory at the path.
		f.State = fact.DockerUnitError
		f.Msg = why
		return f, nil
	}

	f.State = fact.DockerUnitPresent
	return f, res.Data
}

// resolveLink makes a link target absolute against the link's own directory.
// A relative target read as absolute names a completely different file.
func resolveLink(link, dest string) string {
	if path.IsAbs(dest) {
		return path.Clean(dest)
	}
	return path.Clean(path.Join(path.Dir(link), dest))
}

func unitStateFor(err error) fact.DockerUnitState {
	switch {
	case errors.Is(err, system.ErrPermission):
		return fact.DockerUnitDenied
	case errors.Is(err, system.ErrNotExist):
		return fact.DockerUnitAbsent
	case errors.Is(err, system.ErrNotRegular), errors.Is(err, system.ErrNotSymlink):
		return fact.DockerUnitNotRegular
	default:
		return fact.DockerUnitError
	}
}

func errMsg(err error) string {
	if errors.Is(err, system.ErrPermission) {
		return "the file exists and could not be read"
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// the unit file format
// ---------------------------------------------------------------------------

// execDirective is one ExecStart= assignment in the [Service] section.
type execDirective struct {
	line  int
	value string // empty means a reset
}

// foldExecStart applies one fragment's ExecStart directives to the list so far.
//
// systemd folds rather than replaces: a non-empty assignment appends to the
// list and an empty one clears it. That is why every documented Docker
// override begins with a bare `ExecStart=` — without it the drop-in adds a
// second command line, and for a Type=notify unit like this one systemd
// refuses to load a unit with two.
func foldExecStart(execs []fact.DockerExec, origin string, data []byte) []fact.DockerExec {
	for _, d := range execStarts(data) {
		if d.value == "" {
			execs = nil
			continue
		}
		prefixes, argv := splitExec(d.value)
		if len(argv) == 0 {
			continue
		}
		// The single point at which a command line becomes fact data, and so
		// the single place the scrubber has to run. See scrubArgs.
		argv = scrubArgs(argv)
		execs = append(execs, fact.DockerExec{
			Origin:   origin,
			Line:     d.line,
			Prefixes: prefixes,
			Argv:     argv,
		})
	}
	return execs
}

// execStarts returns the ExecStart directives in a unit fragment's [Service]
// section, in file order.
//
// Only [Service] is read. A unit's other sections are none of this collector's
// business, and in particular Environment= and EnvironmentFile= are not read:
// they are where a Docker host's proxy credentials live, and a $VARIABLE left
// unexpanded in an ExecStart is reported as an ambiguity, which is the honest
// outcome, rather than resolved by reading a file full of secrets.
func execStarts(data []byte) []execDirective {
	var out []execDirective

	section := ""
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		first := i + 1
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)

		// A comment continues too, and a continuation of a comment is still a
		// comment. Consuming it here is what stops the second physical line of
		// a commented-out ExecStart from being read as a live one.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			for continues(raw) && i+1 < len(lines) {
				i++
				raw = strings.TrimRight(lines[i], "\r")
			}
			continue
		}

		for continues(raw) && i+1 < len(lines) {
			raw = strings.TrimRight(raw, " \t")
			raw = raw[:len(raw)-1] + " "
			i++
			raw += strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		}

		stmt := strings.TrimSpace(raw)
		if strings.HasPrefix(stmt, "[") && strings.HasSuffix(stmt, "]") {
			section = stmt[1 : len(stmt)-1]
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, ok := strings.Cut(stmt, "=")
		// systemd directive names are case sensitive: execstart= is not a
		// directive and is a unit systemd would refuse to load.
		if !ok || strings.TrimSpace(key) != "ExecStart" {
			continue
		}
		out = append(out, execDirective{line: first, value: strings.TrimSpace(value)})
	}
	return out
}

// continues reports whether a physical line is joined to the next one.
//
// The test counts trailing backslashes rather than looking at the last one,
// because `\\` is an escaped backslash and ends the line, while `\\\` is an
// escaped backslash followed by a continuation.
func continues(s string) bool {
	s = strings.TrimRight(s, " \t\r")
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// opaqueFlags names the dockerd flags whose *values* must never reach a
// bundle, by their long name without dashes.
//
// It is a table rather than a special case for one flag because the question
// recurs: any flag whose value is an arbitrary key/value pair set by an
// operator is a place a credential can end up, and adding one here is the
// whole of the change. What qualifies is a flag whose value this build does
// not need in order to reach a verdict — if a check has to read the value, the
// answer is to model it as a typed field and decide there, not to record the
// raw text and hope.
//
// --log-opt is the one that matters today and it is not hypothetical.
// "splunk-token" is an authentication token, "awslogs-credentials-endpoint" is
// the path to one, and both are documented ways to configure a logging driver.
// The same options written in /etc/docker/daemon.json have had their values
// dropped since the log-opts key names were modelled; a bundle must not depend
// on which of the two files an operator happened to use.
var opaqueFlags = map[string]bool{
	"log-opt": true,
}

// redactedValue is what stands in for a value that was read and not kept.
//
// It is a visible marker rather than an omission on purpose. A reader has to
// be able to tell "this option was set and its value is not in this artifact"
// from "this option was not set", because those are different facts about the
// host and only one of them is a finding.
const redactedValue = "[REDACTED]"

// scrubArgs removes the values of opaque flags from a command line, keeping
// everything else exactly as systemd would have passed it.
//
// **This is the one place in the tree that deliberately records something
// other than what the file says**, and the trade is worth stating. An evidence
// excerpt drawn from a scrubbed ExecStart no longer matches `systemctl show -p
// ExecStart docker.service` byte for byte, which costs an auditor a moment of
// confusion. A credential in an artifact designed to travel costs rather more,
// and cannot be taken back once the bundle is shared. The fragment digest is
// unaffected — it is the sha256 of the file's bytes, computed at the seam —
// so verifying a finding against the live host still works.
//
// Both of pflag's spellings are handled, plus the single-dash long form that
// pflag does not actually accept. Being wrong in the permissive direction here
// costs a redacted token that was never a flag; being wrong in the other
// direction costs a secret.
func scrubArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		tok := argv[i]

		dashes, name, value, inline := splitFlag(tok)
		if !opaqueFlags[name] {
			out = append(out, tok)
			continue
		}

		if inline {
			// --log-opt=key=value, all in one token.
			out = append(out, dashes+name+"="+scrubValue(value))
			continue
		}

		// --log-opt key=value, where the value is the next token. A trailing
		// flag with nothing after it has no value to scrub; dockerd would
		// refuse to start on it.
		out = append(out, tok)
		if i+1 < len(argv) {
			i++
			out = append(out, scrubValue(argv[i]))
		}
	}
	return out
}

// splitFlag takes a token apart into its leading dashes, its flag name, and an
// inline value if it carries one.
//
// The dashes are counted rather than assumed so the token can be rebuilt as it
// was written: an operator who typed -log-opt gets -log-opt back, not
// --log-opt, because a fact that silently corrected the command line would be
// a fact that disagreed with the host for a second reason.
func splitFlag(tok string) (dashes, name, value string, inline bool) {
	rest := strings.TrimLeft(tok, "-")
	if rest == "" || len(rest) == len(tok) {
		// Not a flag at all, or nothing but dashes.
		return "", "", "", false
	}
	dashes = tok[:len(tok)-len(rest)]
	if i := strings.IndexByte(rest, '='); i >= 0 {
		return dashes, rest[:i], rest[i+1:], true
	}
	return dashes, rest, "", false
}

// scrubValue keeps a log option's key and discards what it was set to.
//
// The key is policy and worth having: "max-size" being present is the whole of
// what CONTAINERS-0008 needs, and an operator reading "log-opt
// splunk-token=[REDACTED]" can see both that they configured it and that this
// tool did not carry it. The value is the part that is sometimes a credential
// and is never needed.
//
// A token with no "=" has no key to keep, so all of it goes — unless it is an
// unexpanded variable, which is a *name* rather than a value. The secret a
// $SPLUNK_TOKEN refers to lives in the EnvironmentFile this collector
// deliberately does not read, so the token itself discloses nothing, and
// DockerService.Ambiguities has to still be able to see it: systemd expands a
// variable into however many words it holds, so an unexpanded one is a reason
// the command line cannot be claimed to have been read in full.
func scrubValue(v string) string {
	if v == "" {
		return v
	}
	if i := strings.IndexByte(v, '='); i >= 0 {
		return v[:i+1] + redactedValue
	}
	if strings.Contains(v, "$") {
		return v
	}
	return redactedValue
}

// splitExec separates systemd's modifier prefixes from the command line and
// splits the rest into arguments.
//
// The prefixes are "@", "-", ":", "+", "!" and "!!", in any combination, and
// they precede the executable path. They are kept rather than discarded
// because two of them change what the line means: "-" makes a non-zero exit
// non-fatal, and "+" runs the command outside the unit's sandboxing.
func splitExec(value string) (prefixes string, argv []string) {
	i := 0
	for i < len(value) && strings.IndexByte("@-:+!", value[i]) >= 0 {
		i++
	}
	return value[:i], splitArgs(value[i:])
}

// splitArgs splits a command line the way systemd does: on whitespace, with
// single quotes taken literally, double quotes honouring backslash escapes,
// and a bare backslash escaping the character after it.
//
// It does not expand $VARIABLE or systemd's % specifiers. Neither can be
// resolved from the fragment in hand, and a splitter that dropped them would
// turn "dockerd $DOCKER_OPTS" into a command line with no options — an
// unreadable line silently rendered as a safe-looking one, which is the worst
// answer available. They survive as tokens, and fact.DockerService.Ambiguities
// is what a check consults before trusting the result.
func splitArgs(s string) []string {
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		quote byte
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == '\\' && quote == '"' && i+1 < len(s):
				i++
				cur.WriteByte(unescape(s[i]))
			default:
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, inArg = c, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(unescape(s[i]))
			inArg = true
		case c == ' ' || c == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg || quote != 0 {
		args = append(args, cur.String())
	}
	return args
}

// unescape maps the escape sequences systemd recognises inside a command line.
// An unrecognised escape stands for the character itself, which is what
// systemd does and what makes `\ ` a space rather than an error.
func unescape(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 's':
		return ' '
	default:
		return c
	}
}

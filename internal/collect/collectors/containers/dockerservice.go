package containers

import (
	"context"
	"strings"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/collect/unit"
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
// collector — and the precedence rules for doing it, which are systemd's and
// are not obvious, live in collect/unit so that this collector and the
// SERVICES sandboxing collector cannot come to different answers about which
// files are in force.
//
// What stays here is everything about *dockerd*: the fold of ExecStart into a
// command line, the split into arguments, and the scrubber that keeps log
// option values out of the bundle. collect/unit reads through ReadOpaque, so
// the bytes of these files never reach the evidence store either.
// fact.DockerService explains why both halves matter: a Docker host's
// override.conf is where proxy credentials live.
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
		u.State = fact.UnitError
		u.Msg = "the scan was abandoned before the unit was read"
		fs.Put(u)
		return nil
	}

	// The assembly — which of the four roots wins, which drop-ins systemd
	// would apply and in what order, what became of each file — is
	// collect/unit's, because the rules are systemd's rather than Docker's and
	// a second implementation of them would be a second set of verdicts.
	//
	// **ExecStart is the only directive asked for**, and that is the privacy
	// boundary rather than an optimisation: unit.Assemble discards everything
	// else during the parse, so an Environment= carrying a fleet's proxy
	// credentials is never held at all. What comes back is the raw text after
	// the "=", and turning that into argv — and scrubbing the log-option
	// values out of it — stays here, in the collector that knows what a
	// dockerd command line is.
	asm := unit.Assemble(s, unit.Request{
		Name:       fact.DockerServiceUnit,
		Section:    "Service",
		Directives: []string{"ExecStart"},
	})

	u.State = asm.State
	u.Path = asm.Path
	u.Digest = asm.Digest
	u.Msg = asm.Msg
	u.Fragments = asm.Fragments
	u.ExecStart = execStarts(asm)

	fs.Put(u)
	return nil
}

// ---------------------------------------------------------------------------
// the unit file format
// ---------------------------------------------------------------------------

// execStarts turns the assembled ExecStart directives into command lines.
//
// unit.List applies systemd's fold — a non-empty assignment appends and an
// empty one clears the list — which is why every documented Docker override
// begins with a bare `ExecStart=`: without it the drop-in adds a second command
// line, and for a Type=notify unit like this one systemd refuses to load a unit
// with two.
//
// Everything after the fold is Docker's and stays here. The split into
// arguments follows systemd's quoting rules, the modifier prefixes come off
// the front, and **the log-option scrubber runs at the single point where a
// command line becomes fact data** — which is this function and nowhere else.
// Putting the scrubber in collect/unit was considered and rejected: it is a
// statement about dockerd's flag grammar, not about unit files, and a generic
// redaction hook would have been a place for a later caller to forget to pass
// one.
func execStarts(asm unit.Unit) []fact.DockerExec {
	var out []fact.DockerExec
	for _, d := range asm.List("ExecStart") {
		prefixes, argv := splitExec(d.Value)
		if len(argv) == 0 {
			continue
		}
		out = append(out, fact.DockerExec{
			Origin:   d.Origin,
			Line:     d.Line,
			Prefixes: prefixes,
			Argv:     scrubArgs(argv),
		})
	}
	return out
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

// Package cron collects ownership and permissions for the system cron paths.
//
// It reads no crontab. Every check in the CRON module asks who may *write* the
// schedule, not what the schedule says, and a crontab's contents are operator
// data — command lines, script paths, and often credentials passed as
// arguments. Collecting them would put all of that into a bundle designed to
// travel, for a set of checks that never look at it. The same reasoning as
// ADR-0015, applied before the mistake rather than after it.
//
// This is the first collector whose facts turn on file *ownership*, which is
// why ADR-0016 exists: uid 0 is a legitimate value, so it cannot double as
// "not recorded", and every record here carries an explicit state saying
// whether the numbers beside it mean anything.
package cron

import (
	"context"
	"errors"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

// ID is the collector's identifier.
const ID = "cron"

// The single-file paths this module governs.
const (
	CrontabPath = "/etc/crontab"
	AllowPath   = "/etc/cron.allow"
	DenyPath    = "/etc/cron.deny"
)

// DropInDirs are the directories cron runs jobs from. Write access to any of
// them is arbitrary code execution as root on a schedule.
var DropInDirs = []string{
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

// paths is every path probed, in record order.
//
// The order is fixed rather than sorted at use, so the fact is deterministic
// and every detail string built from it reads the same way on every run.
func paths() []string {
	out := make([]string, 0, 3+len(DropInDirs))
	out = append(out, CrontabPath)
	out = append(out, DropInDirs...)
	out = append(out, AllowPath, DenyPath)
	return out
}

// Collector implements collect.Collector for the cron file metadata.
type Collector struct{}

// New returns the cron collector.
func New() Collector { return Collector{} }

func init() { collect.Register(New()) }

var _ collect.Collector = Collector{}

func (Collector) ID() string { return ID }

func (Collector) Produces() []fact.ID { return []fact.ID{fact.CronID} }

// DependsOn is nil. Eight stat calls need nothing observed first.
func (Collector) DependsOn() []string { return nil }

// Requires is CapNone.
//
// Every path here lives in /etc and is stat-able by any user: the metadata is
// world-readable even where the contents are not. Declaring CapRoot would make
// an unprivileged scan skip the collector and report the whole module as never
// collected, when in fact it can answer every question this module asks. Where
// a stat genuinely is refused — a parent directory with mode 0700 — that one
// path records CronDenied and only the checks reading it degrade.
func (Collector) Requires() collect.Capability { return collect.CapNone }

// Cost is Cheap: eight stat calls, no read, no walk, no exec.
func (Collector) Cost() collect.Cost { return collect.Cheap }

// Timeout is five seconds. Eight stats on local storage; if this does not
// complete, the filesystem is not answering, and an audit that hangs on
// /etc/crontab is worse than one that records why it stopped.
func (Collector) Timeout() time.Duration { return 5 * time.Second }

// Collect stats each path, translating every outcome into a typed state.
//
// It returns nil in every case. There is no failure here that is not itself an
// observation about the host: a path is present, absent, refused, or broken in
// a way worth recording verbatim, and all four belong in the fact rather than
// in an error that would discard the other seven records with it.
func (Collector) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	c := fact.Cron{}

	for _, p := range paths() {
		// The deadline stopped us. Record what was gathered rather than
		// returning the context error: internal/collect.runner discards the
		// partial facts of a collector that errors while its context is done,
		// which would throw away the records already made.
		//nolint:nilerr // error deliberately swallowed for graceful degradation; the records already collected are kept in the FactSet
		if err := ctx.Err(); err != nil {
			c.Installed = installed(c.Paths)
			fs.Put(c)
			return nil
		}
		c.Paths = append(c.Paths, statPath(s, p))
	}

	c.Installed = installed(c.Paths)
	fs.Put(c)
	return nil
}

// installed derives whether this host has a system cron at all.
//
// It is derived rather than probed because there is no single file whose
// presence means "cron is installed" across distributions. A path we were
// refused counts as present: we could not read it, but something is there, and
// treating a refusal as absence would turn an unprivileged scan into a report
// that the host has no cron.
func installed(ps []fact.CronPath) bool {
	for _, p := range ps {
		if p.State == fact.CronObserved || p.State == fact.CronDenied {
			return true
		}
	}
	return false
}

// statPath translates one Stat into a record.
func statPath(s system.System, path string) fact.CronPath {
	fi, err := s.Stat(path)
	switch {
	case err == nil:
		return fact.CronPath{
			Path:      path,
			State:     fact.CronObserved,
			Mode:      fi.Mode,
			UID:       fi.UID,
			GID:       fi.GID,
			IsDir:     fi.IsDir,
			IsRegular: fi.IsRegular,
			IsSymlink: fi.IsSymlink,
		}

	case errors.Is(err, system.ErrNotExist):
		return fact.CronPath{Path: path, State: fact.CronAbsent}

	case errors.Is(err, system.ErrPermission):
		return fact.CronPath{
			Path: path, State: fact.CronDenied,
			Msg: "permission denied; a parent directory refuses traversal",
		}

	default:
		return fact.CronPath{Path: path, State: fact.CronError, Msg: err.Error()}
	}
}

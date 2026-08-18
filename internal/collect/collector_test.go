package collect_test

import (
	"context"
	"sync"
	"time"

	"github.com/antaryx/plumbline/internal/collect"
	"github.com/antaryx/plumbline/internal/fact"
	"github.com/antaryx/plumbline/internal/system"
)

const fixtureRoot = "../../testdata/fixtures"

// stub is a collector whose whole behaviour is supplied by the test. Every
// runner property is proved with these rather than with real collectors,
// because a real collector cannot be made to panic or hang on demand.
type stub struct {
	id       string
	deps     []string
	requires collect.Capability
	cost     collect.Cost
	run      func(ctx context.Context, s system.System, fs *fact.Set) error
}

func (c stub) ID() string                   { return c.id }
func (c stub) DependsOn() []string          { return c.deps }
func (c stub) Requires() collect.Capability { return c.requires }
func (c stub) Cost() collect.Cost           { return c.cost }
func (c stub) Collect(ctx context.Context, s system.System, fs *fact.Set) error {
	if c.run == nil {
		return nil
	}
	return c.run(ctx, s, fs)
}

// span is when one collector was inside Collect. Ordering and overlap are the
// only way to observe a scheduler from outside, so the tests measure both.
type span struct {
	start time.Time
	end   time.Time
}

// journal records spans from many goroutines.
type journal struct {
	mu    sync.Mutex
	spans map[string]span
	ran   map[string]bool
}

func newJournal() *journal {
	return &journal{spans: map[string]span{}, ran: map[string]bool{}}
}

// mark returns a collector body that records its span and sleeps for d, so
// that concurrency is observable rather than inferred.
func (j *journal) mark(id string, d time.Duration) func(context.Context, system.System, *fact.Set) error {
	return func(ctx context.Context, _ system.System, _ *fact.Set) error {
		j.begin(id)
		if d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
			}
		}
		j.end(id)
		return nil
	}
}

func (j *journal) begin(id string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ran[id] = true
	j.spans[id] = span{start: time.Now()}
}

func (j *journal) end(id string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := j.spans[id]
	s.end = time.Now()
	j.spans[id] = s
}

func (j *journal) span(id string) (span, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	s, ok := j.spans[id]
	return s, ok
}

func (j *journal) didRun(id string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.ran[id]
}

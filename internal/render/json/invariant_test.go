package json

import (
	"bytes"
	"errors"
	"testing"
)

// TestPostureWithoutCoverageIsRefused exercises the guard directly.
//
// The exported API cannot reach this state: Render takes a score.Score, which
// computes posture and coverage together and cannot define one without the
// other. That structural guarantee is what the invariant rests on — and it is
// also why the guard needs an internal test, because a document in the
// forbidden shape can only be built from inside the package.
//
// If a later change lets the forbidden shape through the front door, this test
// still holds the line.
func TestPostureWithoutCoverageIsRefused(t *testing.T) {
	posture := 100.0
	d := document{
		Schema:  Schema,
		Summary: summary{Posture: &posture, Coverage: nil},
	}
	if err := d.check(); !errors.Is(err, ErrPostureWithoutCoverage) {
		t.Errorf("check() = %v, want ErrPostureWithoutCoverage", err)
	}

	// Both undefined is legitimate: a host nothing applied to.
	d.Summary.Posture = nil
	if err := d.check(); err != nil {
		t.Errorf("a document with neither figure was refused: %v", err)
	}

	// Coverage without posture is the ordinary unprivileged case.
	coverage := 30.0
	d.Summary.Coverage = &coverage
	if err := d.check(); err != nil {
		t.Errorf("coverage without posture was refused: %v", err)
	}
}

// TestRenderRefusesBeforeWriting: a refused document must not leave a partial
// one behind. Half a findings document on disk is worse than none, because it
// parses far enough to look real.
func TestRenderRefusesBeforeWriting(t *testing.T) {
	var buf bytes.Buffer
	posture := 100.0
	d := document{Schema: Schema, Summary: summary{Posture: &posture}}
	if err := d.check(); err == nil {
		t.Fatal("guard did not fire")
	}
	if buf.Len() != 0 {
		t.Error("bytes were written before the guard ran")
	}
}

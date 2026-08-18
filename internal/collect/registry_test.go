package collect_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/antaryx/plumbline/internal/collect"
	_ "github.com/antaryx/plumbline/internal/collect/collectors/sshd"
)

func mustPanic(t *testing.T, want string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic mentioning %q, got none", want)
		}
		if got := fmt.Sprint(r); !strings.Contains(got, want) {
			t.Errorf("panic = %q, want it to mention %q", got, want)
		}
	}()
	f()
}

// TestOrderIsTopologicalAndDeterministic uses the acceptance criterion's
// four-node DAG. b and c are independent, so only their order relative to a
// and d is fixed; the tie between them is broken lexicographically so that one
// registry always yields one plan.
//
//	a → b ─┐
//	 └→ c ─┴→ d
func TestOrderIsTopologicalAndDeterministic(t *testing.T) {
	r := collect.NewRegistry()
	// Registered out of order on purpose: the plan comes from the graph, not
	// from whoever imported which package first.
	r.Register(stub{id: "d", deps: []string{"b", "c"}})
	r.Register(stub{id: "c", deps: []string{"a"}})
	r.Register(stub{id: "b", deps: []string{"a"}})
	r.Register(stub{id: "a"})

	want := []string{"a", "b", "c", "d"}
	for i := 0; i < 20; i++ {
		if got := r.Order(); !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v (iteration %d)", got, want, i)
		}
	}
}

func TestRegisterPanicsOnCycle(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{id: "a", deps: []string{"c"}})
	r.Register(stub{id: "b", deps: []string{"a"}})
	// Closing the loop is what makes the cycle exist, so this is where it must
	// be caught — at init, in a test, never in a scan.
	mustPanic(t, "dependency cycle", func() {
		r.Register(stub{id: "c", deps: []string{"b"}})
	})

	// The registry stays usable, so a test that recovers can keep going.
	if _, ok := r.Get("c"); ok {
		t.Error("the collector that closed the cycle was left registered")
	}
}

func TestRegisterPanicsOnMisuse(t *testing.T) {
	cases := []struct {
		name  string
		want  string
		setup func(*collect.Registry)
	}{
		{"empty ID", "empty ID", func(r *collect.Registry) {
			r.Register(stub{id: ""})
		}},
		{"duplicate ID", "duplicate collector ID", func(r *collect.Registry) {
			r.Register(stub{id: "dup"})
			r.Register(stub{id: "dup"})
		}},
		{"self dependency", "depends on itself", func(r *collect.Registry) {
			r.Register(stub{id: "loop", deps: []string{"loop"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := collect.NewRegistry()
			mustPanic(t, tc.want, func() { tc.setup(r) })
		})
	}
}

// TestUnregisteredDependencyImposesNoOrder: an unknown dependency is a wiring
// bug, not a cycle, and it must not make the plan unbuildable. The runner is
// what refuses to execute the collector.
func TestUnregisteredDependencyImposesNoOrder(t *testing.T) {
	r := collect.NewRegistry()
	r.Register(stub{id: "a", deps: []string{"never-registered"}})
	r.Register(stub{id: "b"})

	if got, want := r.Order(), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	missing := r.MissingDependencies()
	if !reflect.DeepEqual(missing, map[string][]string{"a": {"never-registered"}}) {
		t.Errorf("missing dependencies = %v", missing)
	}
}

// TestSSHDRegistersItself proves the port: importing the collector package is
// what puts it in the default registry.
func TestSSHDRegistersItself(t *testing.T) {
	c, ok := collect.Default().Get("sshd")
	if !ok {
		t.Fatalf("sshd is not in the default registry; it holds %v", collect.Default().IDs())
	}
	if c.Cost() != collect.Cheap {
		t.Errorf("sshd cost = %s, want cheap", c.Cost())
	}
	if c.Requires() != collect.CapNone {
		t.Errorf("sshd requires = %s, want none", c.Requires())
	}
	if len(c.DependsOn()) != 0 {
		t.Errorf("sshd depends on %v, want nothing", c.DependsOn())
	}
}

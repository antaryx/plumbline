// Command fixturegate enforces CONTRIBUTING.md rule 5 and docs/FIXTURES.md §4: every
// check in the catalog demonstrates at least one fixture yielding PASS and one
// yielding FAIL.
//
// It reads the catalog with go/ast rather than by matching text. Check IDs and
// test tables are Go syntax, and a regular expression over Go source starts
// lying the first time somebody reformats a literal or wraps a line. A gate
// that lies is worse than no gate, because it converts an unverified claim
// into a green tick.
//
// There is deliberately no configuration file, no flag and no exemption
// mechanism. A check that cannot have both fixtures does not belong in the
// catalog.
//
// Run from the repository root:
//
//	go run ./tools/fixturegate
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	checksRoot     = "internal/catalog/checks"
	catalogPkgPath = "github.com/antaryx/plumbline/internal/catalog"
	findingPkgPath = "github.com/antaryx/plumbline/internal/finding"
	checkTypeName  = "Check"
)

// resultIdents maps the finding.Result identifiers a test table may name onto
// the wire values they carry, so the report speaks the same language as the
// findings and the suppression files do.
var resultIdents = map[string]string{
	"Pass":          "PASS",
	"Fail":          "FAIL",
	"NotApplicable": "NOT_APPLICABLE",
	"Skipped":       "SKIPPED",
	"Unknown":       "UNKNOWN",
}

// resultOrder fixes the order states are reported in. Determinism is the
// property this project exists to provide; the gate observes it too.
var resultOrder = []string{"Pass", "Fail", "NotApplicable", "Skipped", "Unknown"}

// required are the two states every check must demonstrate.
var required = []string{"Pass", "Fail"}

// check is one catalog entry and the test-table coverage found for it.
type check struct {
	id      string   // "SSHD-0002"
	varName string   // "Check0002"; empty if the literal is not bound to a var
	file    string   // the file declaring it
	tests   []string // test files attributed to it
	states  map[string]bool
}

func main() {
	checks, err := scan(checksRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fixturegate: %v\n", err)
		os.Exit(1)
	}

	gaps := incomplete(checks)
	if len(gaps) > 0 {
		for _, g := range gaps {
			fmt.Fprint(os.Stderr, g.report())
		}
		fmt.Fprintf(os.Stderr, "ERROR: %d of %d check(s) lack a PASS or a FAIL fixture.\n", len(gaps), len(checks))
		fmt.Fprint(os.Stderr, "Every check needs at least one test-table case expecting finding.Pass and\n")
		fmt.Fprint(os.Stderr, "one expecting finding.Fail. See CONTRIBUTING.md rule 5 and docs/FIXTURES.md §4.\n")
		os.Exit(1)
	}

	fmt.Printf("ok: fixture coverage (%d check(s), each with PASS and FAIL cases)\n", len(checks))
}

// gap is a check together with the states it never demonstrates.
type gap struct {
	c       *check
	missing []string
}

// incomplete returns, in catalog order, every check missing a required state.
func incomplete(checks []*check) []gap {
	var out []gap
	for _, c := range checks {
		var missing []string
		for _, r := range required {
			if !c.states[r] {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			out = append(out, gap{c: c, missing: missing})
		}
	}
	return out
}

func (g gap) report() string {
	var b strings.Builder
	for _, m := range g.missing {
		fmt.Fprintf(&b, "%s: no test case expects %s\n", g.c.id, resultIdents[m])
	}
	fmt.Fprintf(&b, "    declared in: %s\n", g.c.file)
	if len(g.c.tests) == 0 {
		fmt.Fprintf(&b, "    tested by:   nothing - no _test.go in %s %s\n",
			filepath.Dir(g.c.file), g.c.attribution())
		return b.String()
	}
	fmt.Fprintf(&b, "    tested by:   %s\n", strings.Join(g.c.tests, ", "))
	fmt.Fprintf(&b, "    cases found: %s\n", g.c.found())
	return b.String()
}

// attribution explains, in the failure message, what the gate looked for. A
// check with no coverage is usually a test file the gate could not attribute,
// and saying so beats making the author guess.
func (c *check) attribution() string {
	want := strings.TrimSuffix(filepath.Base(c.file), ".go") + "_test.go"
	if c.varName == "" {
		return fmt.Sprintf("is named %s", want)
	}
	return fmt.Sprintf("names %s or is named %s", c.varName, want)
}

// found lists the states the check's tables do demonstrate.
func (c *check) found() string {
	var out []string
	for _, r := range resultOrder {
		if c.states[r] {
			out = append(out, resultIdents[r])
		}
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, ", ")
}

// scan walks root and returns every check found, ordered by ID.
func scan(root string) ([]*check, error) {
	byDir := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		dir := filepath.Dir(p)
		byDir[dir] = append(byDir[dir], p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}

	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	fset := token.NewFileSet()
	var all []*check
	for _, dir := range dirs {
		sort.Strings(byDir[dir])
		found, err := scanPackage(fset, byDir[dir])
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	return all, nil
}

type parsedFile struct {
	path string
	file *ast.File
}

// scanPackage extracts the checks declared in one module package and
// attributes the test tables in that package to them.
func scanPackage(fset *token.FileSet, paths []string) ([]*check, error) {
	var sources, tests []parsedFile
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		pf := parsedFile{path: p, file: f}
		if strings.HasSuffix(p, "_test.go") {
			tests = append(tests, pf)
			continue
		}
		sources = append(sources, pf)
	}

	var checks []*check
	for _, s := range sources {
		found, err := checksIn(fset, s.path, s.file)
		if err != nil {
			return nil, err
		}
		checks = append(checks, found...)
	}
	if len(checks) == 0 {
		return nil, nil
	}

	for _, t := range tests {
		covered := coveredBy(t, checks)
		if len(covered) == 0 {
			continue
		}
		states := tableStates(t.file)
		for _, c := range covered {
			c.tests = append(c.tests, t.path)
			for s := range states {
				c.states[s] = true
			}
		}
	}
	return checks, nil
}

// checksIn returns the catalog.Check literals declared in one source file.
func checksIn(fset *token.FileSet, p string, f *ast.File) ([]*check, error) {
	catalogName, ok := importName(f, catalogPkgPath)
	if !ok {
		// The file cannot name catalog.Check, so it declares no checks.
		return nil, nil
	}

	var out []*check
	for _, ref := range checkLits(f, catalogName) {
		id, err := checkID(ref.lit)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fset.Position(ref.lit.Pos()), err)
		}
		out = append(out, &check{
			id:      id,
			varName: ref.varName,
			file:    p,
			states:  map[string]bool{},
		})
	}
	return out, nil
}

// litRef is a catalog.Check literal and the variable holding it, if any.
type litRef struct {
	lit     *ast.CompositeLit
	varName string
}

// checkLits finds every catalog.Check literal in f, whether it is bound to its
// own variable or is an element of a slice or map of checks. Missing a
// declaration form would let a check enter the catalog unguarded, which is the
// one outcome this tool exists to prevent.
func checkLits(f *ast.File, catalogName string) []litRef {
	names := map[*ast.CompositeLit]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, val := range vs.Values {
				if i >= len(vs.Names) {
					continue
				}
				if lit, ok := checkLit(val, catalogName); ok {
					names[lit] = vs.Names[i].Name
				}
			}
		}
	}

	seen := map[*ast.CompositeLit]bool{}
	var out []litRef
	record := func(cl *ast.CompositeLit) {
		if seen[cl] {
			return
		}
		seen[cl] = true
		out = append(out, litRef{lit: cl, varName: names[cl]})
	}

	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch {
		case isCheckType(cl.Type, catalogName):
			record(cl)
		case isCheckContainer(cl.Type, catalogName):
			// Elements of []catalog.Check{{...}} carry no type of their own.
			for _, e := range cl.Elts {
				el := e
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					el = kv.Value
				}
				if inner, ok := el.(*ast.CompositeLit); ok {
					record(inner)
				}
			}
		}
		return true
	})
	return out
}

// checkLit unwraps catalog.Check{...} and &catalog.Check{...}.
func checkLit(e ast.Expr, catalogName string) (*ast.CompositeLit, bool) {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok || !isCheckType(cl.Type, catalogName) {
		return nil, false
	}
	return cl, true
}

func isCheckType(t ast.Expr, catalogName string) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == catalogName && sel.Sel.Name == checkTypeName
}

func isCheckContainer(t ast.Expr, catalogName string) bool {
	switch tt := t.(type) {
	case *ast.ArrayType:
		return isCheckType(tt.Elt, catalogName)
	case *ast.MapType:
		return isCheckType(tt.Value, catalogName)
	}
	return false
}

// checkID reads the ID field. An ID the gate cannot read is an error, not a
// check to skip: skipping it would silently drop it out of coverage.
func checkID(lit *ast.CompositeLit) (string, error) {
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "ID" {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", fmt.Errorf("catalog.Check ID is not a string literal; the fixture gate cannot identify this check")
		}
		id, err := strconv.Unquote(bl.Value)
		if err != nil {
			return "", fmt.Errorf("unquoting catalog.Check ID: %w", err)
		}
		return id, nil
	}
	return "", fmt.Errorf("catalog.Check literal has no ID field")
}

// coveredBy decides which checks a test file exercises. Two signals, in order:
// the file names the check's variable (directly or through a package
// qualifier), or, failing that, the file name corresponds to the declaring
// file. A test file that names several checks credits all of them; attributing
// individual table rows to individual checks is not possible from syntax
// alone, and the gate's question is whether the fixtures exist.
func coveredBy(t parsedFile, checks []*check) []*check {
	idents := identSet(t.file)
	var out []*check
	for _, c := range checks {
		if c.varName != "" && idents[c.varName] {
			out = append(out, c)
		}
	}
	if len(out) > 0 {
		return out
	}

	want := strings.TrimSuffix(filepath.Base(t.path), "_test.go") + ".go"
	for _, c := range checks {
		if filepath.Base(c.file) == want {
			out = append(out, c)
		}
	}
	return out
}

func identSet(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// tableStates returns the finding.Result constants named as elements of
// composite literals in f - that is, the expectations written in test tables.
//
// Only literal elements count. A result named in a comparison, as in
// `if got.Result == finding.Fail`, is an assertion about whatever case is
// running, not a case of its own; the reference test writes exactly that in
// its shared invariant block, and counting it would credit every check with
// FAIL coverage it does not have.
func tableStates(f *ast.File) map[string]bool {
	findingName, ok := importName(f, findingPkgPath)
	if !ok {
		return nil
	}

	states := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range cl.Elts {
			v := e
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				v = kv.Value
			}
			if name, ok := resultIdent(v, findingName); ok {
				states[name] = true
			}
		}
		return true
	})
	return states
}

func resultIdent(e ast.Expr, findingName string) (string, bool) {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		x, ok := v.X.(*ast.Ident)
		if ok && x.Name == findingName {
			_, isResult := resultIdents[v.Sel.Name]
			return v.Sel.Name, isResult
		}
	case *ast.Ident:
		// The finding package dot-imported: the constant stands alone.
		if findingName == "." {
			_, isResult := resultIdents[v.Name]
			return v.Name, isResult
		}
	}
	return "", false
}

// importName returns the identifier f uses for the package at pkgPath. The
// fallback is the last path element, which holds for every package in this
// module. If it ever stopped holding, the gate would find no states and fail
// loudly rather than pass quietly, which is the correct direction to break in.
func importName(f *ast.File, pkgPath string) (string, bool) {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != pkgPath {
			continue
		}
		if imp.Name == nil {
			return path.Base(p), true
		}
		if imp.Name.Name == "_" {
			continue
		}
		return imp.Name.Name, true
	}
	return "", false
}

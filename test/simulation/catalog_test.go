package simulation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A newly exported application operation must get a simulation driver in the
// same PR. This gate complements behavioral assertions; it is not code coverage.
func TestEveryAppOperationHasSimulationDriver(t *testing.T) {
	exports := map[string]bool{}
	calls := map[string]bool{}
	files, e := filepath.Glob("../../app/*.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if ok && id.Name == "App" {
				exports[fn.Name.Name] = true
			}
		}
	}
	files, e = filepath.Glob("*.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok {
				calls[sel.Sel.Name] = true
			}
			return true
		})
	}
	for name := range exports {
		if !calls[name] {
			t.Errorf("App.%s has no simulation driver; add behavior and coverage documentation", name)
		}
	}
	data, e := os.ReadFile("README.md")
	if e != nil {
		t.Fatal(e)
	}
	for name := range exports {
		if !strings.Contains(string(data), "`"+name+"`") {
			t.Errorf("App.%s missing from operation coverage table", name)
		}
	}
}

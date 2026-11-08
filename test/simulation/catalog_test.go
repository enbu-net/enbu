package simulation

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
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
	// Type-check the drivers so that only calls on an *app.App count: a
	// store's Delete must not stand in for a missing App.Delete driver.
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(fset, path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		parsed = append(parsed, f)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
	// Module packages need their export data located by the go command.
	out, e := exec.CommandContext(t.Context(), "go", "list", "-export", "-deps", "-f", "{{.ImportPath}}={{.Export}}", ".").Output()
	if e != nil {
		t.Fatalf("go list -export: %v", e)
	}
	exportData := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if path, file, ok := strings.Cut(line, "="); ok && file != "" {
			exportData[path] = file
		}
	}
	lookup := func(path string) (io.ReadCloser, error) {
		file, ok := exportData[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	}
	config := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup)}
	if _, e := config.Check("github.com/enbu-net/enbu/test/simulation", fset, parsed, info); e != nil {
		t.Fatal(e)
	}
	for sel, selection := range info.Selections {
		if selection.Kind() != types.MethodVal {
			continue
		}
		recv := selection.Recv()
		if pointer, ok := recv.(*types.Pointer); ok {
			recv = pointer.Elem()
		}
		if named, ok := recv.(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "github.com/enbu-net/enbu/app" && named.Obj().Name() == "App" {
			calls[sel.Sel.Name] = true
		}
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

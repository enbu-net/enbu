package clock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// New production timers must share the same injectable boundary as existing
// operations; otherwise a passing simulation can silently depend on real time.
func TestProductionTimeUsesClock(t *testing.T) {
	for _, dir := range []string{"app", "cli", "desktop", "pkg"} {
		err := filepath.WalkDir(filepath.Join("../..", dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, path, nil, 0)
			if err != nil {
				return err
			}
			imports := map[string]string{}
			for _, imp := range file.Imports {
				pkg, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				if pkg == "time" || pkg == "context" {
					name := pkg
					if imp.Name != nil {
						name = imp.Name.Name
					}
					if name == "." {
						t.Errorf("%s: dot import hides the time boundary", path)
					}
					imports[name] = pkg
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				forbidden := false
				switch imports[id.Name] {
				case "time":
					switch sel.Sel.Name {
					case "Now", "Since", "Until", "Sleep", "After", "AfterFunc", "NewTimer", "NewTicker", "Tick":
						forbidden = true
					}
				case "context":
					forbidden = sel.Sel.Name == "WithTimeout" || sel.Sel.Name == "WithDeadline"
				}
				if forbidden {
					t.Errorf("%s: use the injected Clock instead of %s.%s", set.Position(sel.Pos()), id.Name, sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

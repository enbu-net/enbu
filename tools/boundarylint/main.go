// boundarylint enforces storage boundaries that keep destructive operations
// behind application-layer authorization and validation.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const module = "github.com/enbu-net/enbu/"

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	violations, err := run(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, violation := range violations {
		fmt.Fprintln(os.Stderr, violation)
	}
	if len(violations) > 0 {
		os.Exit(1)
	}
}

func run(root string) ([]string, error) {
	var violations []string
	for _, layer := range []string{"app", "cli", "desktop"} {
		err := filepath.WalkDir(filepath.Join(root, layer), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files := token.NewFileSet()
			file, err := parser.ParseFile(files, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			violations = append(violations, inspect(files, file, layer, filepath.ToSlash(relative))...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return violations, nil
}

// Adding a new physical deletion path needs explicit review of its trust and
// concurrency conditions. Restrict each approved path to its own object kind.
var deletionKinds = map[string]string{
	"app/compact.go:CompactHistory":     "KindState",
	"app/environments.go:purgeResource": "KindState",
	"app/init.go:initializeRepository":  "KindRequest",
}

func inspect(files *token.FileSet, file *ast.File, layer, path string) []string {
	var violations []string
	emit := func(position token.Pos, message string) {
		violations = append(violations, fmt.Sprintf("%s:%d: %s", path, files.Position(position).Line, message))
	}
	storageAlias := ""
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		if layer != "app" && isStorageImplementation(importPath) {
			emit(spec.Pos(), "route workspace storage and signed history through app")
		}
		if importPath == module+"pkg/storage" {
			storageAlias = "storage"
			if spec.Name != nil {
				storageAlias = spec.Name.Name
			}
		}
	}
	if layer != "app" {
		return violations
	}
	allowed := map[*ast.SelectorExpr]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		kind := deletionKinds[path+":"+fn.Name.Name]
		if kind == "" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && len(call.Args) == 4 {
				if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Delete" &&
					isImportedSelector(call.Args[1], storageAlias, kind) {
					allowed[method] = true
				}
			}
			return true
		})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		// Conflict choices carry a boolean Delete field in the wire format.
		if field, ok := node.(*ast.KeyValueExpr); ok && path == "app/conflicts.go" {
			if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Delete" && isImportedSelector(field.Value, "c", "Delete") {
				allowed[field.Value.(*ast.SelectorExpr)] = true
			}
		}
		if method, ok := node.(*ast.SelectorExpr); ok && method.Sel.Name == "Delete" && !allowed[method] {
			emit(method.Pos(), "physical storage deletion must stay in a reviewed path with a fixed object kind")
		}
		return true
	})
	return violations
}

func isImportedSelector(expr ast.Expr, alias, member string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != member {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == alias
}

func isStorageImplementation(path string) bool {
	for _, root := range []string{module + "pkg/storage", module + "pkg/wsp", "oras.land/oras-go/v2", "github.com/minio/minio-go/v7"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

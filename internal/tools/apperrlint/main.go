package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var placeholderPattern = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

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
	codes, violations, err := loadCodes(filepath.Join(root, "apperr", "error.go"))
	if err != nil {
		return nil, err
	}

	usages := make(map[string]int)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == ".worktrees" || name == "node_modules" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			strings.Contains(path, string(filepath.Separator)+"apperr"+string(filepath.Separator)) ||
			strings.Contains(path, string(filepath.Separator)+"internal"+string(filepath.Separator)+"tools"+string(filepath.Separator)+"apperrlint") {
			return nil
		}
		fileViolations, fileUsages, parseErr := inspectGoFile(root, path)
		if parseErr != nil {
			return parseErr
		}
		violations = append(violations, fileViolations...)
		for name, count := range fileUsages {
			usages[name] += count
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for name := range codes {
		if usages[name] == 0 {
			violations = append(violations, fmt.Sprintf("apperr/error.go: error code %s is unused in production code", name))
		}
	}

	translationViolations, err := inspectTranslations(root, codes)
	if err != nil {
		return nil, err
	}
	violations = append(violations, translationViolations...)
	sort.Strings(violations)
	return violations, nil
}

func loadCodes(path string) (map[string]string, []string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil, err
	}
	codes := make(map[string]string)
	values := make(map[string]string)
	var violations []string
	for _, declaration := range file.Decls {
		gen, ok := declaration.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec := spec.(*ast.ValueSpec)
			for index, name := range valueSpec.Names {
				if !strings.HasPrefix(name.Name, "Code") || len(valueSpec.Values) <= index {
					continue
				}
				literal, ok := valueSpec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil {
					return nil, nil, unquoteErr
				}
				if previous, exists := values[value]; exists {
					violations = append(violations, fmt.Sprintf("apperr/error.go: duplicate error code %q in %s and %s", value, previous, name.Name))
				}
				values[value] = name.Name
				codes[name.Name] = value
			}
		}
	}
	return codes, violations, nil
}

func inspectGoFile(root, path string) ([]string, map[string]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil, err
	}
	relative, _ := filepath.Rel(root, path)
	var violations []string
	usages := make(map[string]int)

	ast.Inspect(file, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.SelectorExpr:
			if strings.HasPrefix(current.Sel.Name, "Code") {
				usages[current.Sel.Name]++
			}
		case *ast.CallExpr:
			if isAppErrorConstructor(current) && len(current.Args) > 0 {
				index := 0
				if selectorName(current.Fun) == "Is" {
					index = 1
				}
				if len(current.Args) > index {
					if literal, ok := current.Args[index].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						position := fset.Position(literal.Pos())
						violations = append(violations, fmt.Sprintf("%s:%d: error codes must use a declared constant", relative, position.Line))
					}
				}
			}
		case *ast.IfStmt:
			if containsErrorStringInspection(current.Cond) {
				position := fset.Position(current.Cond.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d: do not inspect err.Error() to control behavior", relative, position.Line))
			}
		case *ast.FuncDecl:
			if requiresAppNormalization(current) && !hasNormalizeDefer(current.Body) {
				position := fset.Position(current.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d: exported app operation %s must defer apperr.NormalizeInto", relative, position.Line, current.Name.Name))
			}
			if isDesktopBindingMethod(current) {
				position := fset.Position(current.Pos())
				if !returnsBindingResponse(current) {
					violations = append(violations, fmt.Sprintf("%s:%d: exported DesktopService method %s must return BindingResponse", relative, position.Line, current.Name.Name))
				} else if !callsBindingHelper(current.Body) {
					violations = append(violations, fmt.Sprintf("%s:%d: exported DesktopService method %s must call bindingResult or bindingError", relative, position.Line, current.Name.Name))
				}
			}
		}
		return true
	})
	return violations, usages, nil
}

func isDesktopBindingMethod(function *ast.FuncDecl) bool {
	return function.Recv != nil && function.Name.IsExported() &&
		receiverTypeName(function.Recv) == "DesktopService"
}

func receiverTypeName(receiver *ast.FieldList) string {
	for _, field := range receiver.List {
		switch value := field.Type.(type) {
		case *ast.StarExpr:
			if ident, ok := value.X.(*ast.Ident); ok {
				return ident.Name
			}
		case *ast.Ident:
			return value.Name
		}
	}
	return ""
}

func returnsBindingResponse(function *ast.FuncDecl) bool {
	if function.Type.Results == nil || len(function.Type.Results.List) != 1 {
		return false
	}
	ident, ok := function.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "BindingResponse"
}

func callsBindingHelper(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return !found
		}
		name := selectorName(call.Fun)
		if name == "" {
			if ident, identOK := call.Fun.(*ast.Ident); identOK {
				name = ident.Name
			}
		}
		found = name == "bindingResult" || name == "bindingError"
		return !found
	})
	return found
}

func isAppErrorConstructor(call *ast.CallExpr) bool {
	switch selectorName(call.Fun) {
	case "New", "Wrap", "Is":
		selector, ok := call.Fun.(*ast.SelectorExpr)
		ident, identOK := selector.X.(*ast.Ident)
		return ok && identOK && ident.Name == "apperr"
	default:
		return false
	}
}

func selectorName(expr ast.Expr) string {
	if selector, ok := expr.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}
	return ""
}

func containsErrorStringInspection(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && selectorName(call.Fun) == "Error" {
			found = true
		}
		return !found
	})
	return found
}

func requiresAppNormalization(function *ast.FuncDecl) bool {
	if function.Recv == nil || !function.Name.IsExported() || function.Type.Results == nil {
		return false
	}
	isApp := false
	for _, field := range function.Recv.List {
		switch receiver := field.Type.(type) {
		case *ast.StarExpr:
			ident, ok := receiver.X.(*ast.Ident)
			isApp = ok && ident.Name == "App"
		case *ast.Ident:
			isApp = receiver.Name == "App"
		}
	}
	if !isApp {
		return false
	}
	for _, result := range function.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok && ident.Name == "error" {
			return true
		}
	}
	return false
}

func hasNormalizeDefer(body *ast.BlockStmt) bool {
	for _, statement := range body.List {
		deferStatement, ok := statement.(*ast.DeferStmt)
		if !ok {
			continue
		}
		selector, ok := deferStatement.Call.Fun.(*ast.SelectorExpr)
		ident, identOK := selector.X.(*ast.Ident)
		if ok && identOK && ident.Name == "apperr" && selector.Sel.Name == "NormalizeInto" {
			return true
		}
	}
	return false
}

func inspectTranslations(root string, codes map[string]string) ([]string, error) {
	load := func(locale string) (map[string]string, error) {
		path := filepath.Join(root, "web", "src", "locales", "errors", locale+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var messages map[string]string
		if err := json.Unmarshal(data, &messages); err != nil {
			return nil, err
		}
		return messages, nil
	}
	en, err := load("en")
	if err != nil {
		return nil, err
	}
	ja, err := load("ja")
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, code := range codes {
		enMessage, enOK := en[code]
		jaMessage, jaOK := ja[code]
		if !enOK || !jaOK {
			violations = append(violations, fmt.Sprintf("web/src/locales/errors: code %q must have en and ja messages", code))
			continue
		}
		if strings.Join(placeholders(enMessage), ",") != strings.Join(placeholders(jaMessage), ",") {
			violations = append(violations, fmt.Sprintf("web/src/locales/errors: code %q has mismatched placeholders", code))
		}
	}
	for code := range en {
		if !containsCode(codes, code) {
			violations = append(violations, fmt.Sprintf("web/src/locales/errors/en.json: unknown code %q", code))
		}
	}
	for code := range ja {
		if !containsCode(codes, code) {
			violations = append(violations, fmt.Sprintf("web/src/locales/errors/ja.json: unknown code %q", code))
		}
	}
	return violations, nil
}

func placeholders(message string) []string {
	var values []string
	for _, match := range placeholderPattern.FindAllStringSubmatch(message, -1) {
		values = append(values, match[1])
	}
	sort.Strings(values)
	return values
}

func containsCode(codes map[string]string, value string) bool {
	for _, code := range codes {
		if code == value {
			return true
		}
	}
	return false
}

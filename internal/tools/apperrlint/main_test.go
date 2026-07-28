package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportsUnusedCodeAndStringInspection(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "apperr/error.go", `package apperr
type Code string
const (
	CodeInternal Code = "internal"
	CodeUnused Code = "unused"
)`)
	writeFixture(t, root, "app/app.go", `package app
type App struct{}
func (a *App) Run() (err error) {
	defer apperr.NormalizeInto(&err)
	if err != nil && err.Error() == "missing" { return err }
	return nil
}`)
	writeFixture(t, root, "other/use.go", `package other
func run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "web/src/locales/errors/en.json", `{"internal":"Internal","unused":"Unused"}`)
	writeFixture(t, root, "web/src/locales/errors/ja.json", `{"internal":"内部","unused":"未使用"}`)

	violations, err := run(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "CodeUnused is unused") {
		t.Fatalf("missing unused-code violation:\n%s", joined)
	}
	if !strings.Contains(joined, "do not inspect err.Error()") {
		t.Fatalf("missing string-inspection violation:\n%s", joined)
	}
}

func TestRunReportsMissingAppNormalizationAndTranslation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "apperr/error.go", `package apperr
type Code string
const CodeInternal Code = "internal"`)
	writeFixture(t, root, "app/app.go", `package app
type App struct{}
func (a *App) Run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "web/src/locales/errors/en.json", `{"internal":"Internal {name}"}`)
	writeFixture(t, root, "web/src/locales/errors/ja.json", `{"internal":"内部"}`)

	violations, err := run(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "must defer apperr.NormalizeInto") {
		t.Fatalf("missing normalization violation:\n%s", joined)
	}
	if !strings.Contains(joined, "mismatched placeholders") {
		t.Fatalf("missing translation violation:\n%s", joined)
	}
}

func TestRunReportsUnsafeDesktopBindingMethods(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "apperr/error.go", `package apperr
type Code string
const CodeInternal Code = "internal"`)
	writeFixture(t, root, "other/use.go", `package other
func run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "desktop/wails/binding.go", `package main
type BindingResponse struct{}
type DesktopService struct{}
func (s *DesktopService) Raw() error { return nil }
func (s *DesktopService) Bypass() BindingResponse { return BindingResponse{} }`)
	writeFixture(t, root, "web/src/locales/errors/en.json", `{"internal":"Internal"}`)
	writeFixture(t, root, "web/src/locales/errors/ja.json", `{"internal":"内部"}`)

	violations, err := run(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "Raw must return BindingResponse") {
		t.Fatalf("missing response violation:\n%s", joined)
	}
	if !strings.Contains(joined, "Bypass must call bindingResult or bindingError") {
		t.Fatalf("missing helper violation:\n%s", joined)
	}
}

func TestRunExcludesToolPackagesAndAcceptsDirectDefers(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "apperr/error.go", `package apperr
type Code string
const (
	CodeInternal Code = "internal"
	CodeOnlySelf Code = "only_self"
)`)
	writeFixture(t, root, "app/app.go", `package app
type App struct{}
func cleanup() {}
func (a *App) Run() (err error) {
	defer cleanup()
	defer apperr.NormalizeInto(&err)
	return nil
}`)
	writeFixture(t, root, "internal/tools/apperrlint/self.go", `package main
func self() { _ = apperr.CodeOnlySelf }`)
	writeFixture(t, root, "other/use.go", `package other
func run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "web/src/locales/errors/en.json", `{"internal":"Internal","only_self":"Self"}`)
	writeFixture(t, root, "web/src/locales/errors/ja.json", `{"internal":"内部","only_self":"自身"}`)

	violations, err := run(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "CodeOnlySelf is unused") {
		t.Fatalf("self package was not excluded:\n%s", joined)
	}
	if strings.Contains(joined, "must defer apperr.NormalizeInto") {
		t.Fatalf("direct defer hid NormalizeInto:\n%s", joined)
	}
}

func writeFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

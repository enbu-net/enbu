package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunReportsUnusedCodeAndStringInspection(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "pkg/apperr/error.go", `package apperr
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
	writeFixture(t, root, "web/messages/en.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"Internal","error_unused":"Unused"}`)
	writeFixture(t, root, "web/messages/ja.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"内部","error_unused":"未使用"}`)

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
	writeFixture(t, root, "pkg/apperr/error.go", `package apperr
type Code string
const CodeInternal Code = "internal"`)
	writeFixture(t, root, "app/app.go", `package app
type App struct{}
func (a *App) Run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "web/messages/en.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"Internal {name}"}`)
	writeFixture(t, root, "web/messages/ja.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"内部"}`)

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
	writeFixture(t, root, "pkg/apperr/error.go", `package apperr
type Code string
const CodeInternal Code = "internal"`)
	writeFixture(t, root, "other/use.go", `package other
func run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "desktop/service.go", `package desktop
type Service struct{ core interface{ List() ([]string, error); Save() error } }
func withRepoResult[T any](s *Service, fn func() (T, error)) (T, error) { return fn() }
func publicError(err error) error { return err }
func publicInto(err *error) {}
func (s *Service) Raw() error { return s.core.Save() }
func (s *Service) RawResult() ([]string, error) { return s.core.List() }
func (s *Service) Saved() error { return publicError(s.core.Save()) }
func (s *Service) Listed() ([]string, error) { return withRepoResult(s, s.core.List) }
func (s *Service) Deferred() (err error) { defer publicInto(&err); return s.core.Save() }
func (s *Service) Version() string { return "v1" }`)
	writeFixture(t, root, "desktop/rpc/server.go", `package rpc
type Service struct{}
func (s *Service) Elsewhere() error { return nil }`)
	writeFixture(t, root, "web/messages/en.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"Internal"}`)
	writeFixture(t, root, "web/messages/ja.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"内部"}`)

	violations, err := run(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(violations, "\n")
	for _, method := range []string{"Raw", "RawResult"} {
		if !strings.Contains(joined, "method "+method+" must return its error through") {
			t.Fatalf("missing violation for %s:\n%s", method, joined)
		}
	}
	for _, method := range []string{"Saved", "Listed", "Deferred", "Version", "Elsewhere"} {
		if strings.Contains(joined, "method "+method+" ") {
			t.Fatalf("unexpected violation for %s:\n%s", method, joined)
		}
	}
}

func TestRunExcludesToolPackagesAndAcceptsDirectDefers(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "pkg/apperr/error.go", `package apperr
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
	writeFixture(t, root, "tools/apperrlint/self.go", `package main
func self() { _ = apperr.CodeOnlySelf }`)
	writeFixture(t, root, "other/use.go", `package other
func run() error { return apperr.New(apperr.CodeInternal, "failed", nil) }`)
	writeFixture(t, root, "web/messages/en.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"Internal","error_only_self":"Self"}`)
	writeFixture(t, root, "web/messages/ja.json", `{"$schema":"https://inlang.com/schema/inlang-message-format","app_name":"enbu","error_internal":"内部","error_only_self":"自身"}`)

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

package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestBoundaryRules(t *testing.T) {
	for _, tc := range []struct {
		name, layer, path, source, diagnostic string
	}{
		{
			name:  "a desktop service cannot bypass the app layer",
			layer: "desktop", path: "desktop/service.go",
			source:     `package desktop; import wire "github.com/enbu-net/enbu/pkg/wsp"`,
			diagnostic: "route workspace storage and signed history through app",
		},
		{
			name:  "a CLI command can use app",
			layer: "cli", path: "cli/pull.go",
			source: `package cli; import "github.com/enbu-net/enbu/app"`,
		},
		{
			name:  "an unrelated package name is permitted",
			layer: "desktop", path: "desktop/copy.go",
			source: `package desktop; import "example.com/wsp"`,
		},
		{
			name:  "a helper cannot delete unverified state",
			layer: "app", path: "app/compact.go",
			source: `package app
import disk "github.com/enbu-net/enbu/pkg/storage"
func cleanup() { _ = s.store.Delete(ctx, disk.KindState, scope, rev) }`,
			diagnostic: "physical storage deletion must stay in a reviewed path",
		},
		{
			name:  "compaction can delete state",
			layer: "app", path: "app/compact.go",
			source: `package app
import disk "github.com/enbu-net/enbu/pkg/storage"
func (a *App) CompactHistory() { _ = s.store.Delete(ctx, disk.KindState, scope, rev) }`,
		},
		{
			name:  "a join request cleanup cannot delete state",
			layer: "app", path: "app/init.go",
			source: `package app
import "github.com/enbu-net/enbu/pkg/storage"
func (a *App) initializeRepository() { _ = s.store.Delete(ctx, storage.KindState, scope, rev) }`,
			diagnostic: "physical storage deletion must stay in a reviewed path",
		},
		{
			name:  "physical deletion has a fixed kind",
			layer: "app", path: "app/environments.go",
			source: `package app
func (s *session) purgeResource() { _ = s.store.Delete(ctx, kind, scope, rev) }`,
			diagnostic: "physical storage deletion must stay in a reviewed path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := token.NewFileSet()
			file, err := parser.ParseFile(files, tc.path, tc.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			got := inspect(files, file, tc.layer, tc.path)
			if tc.diagnostic == "" && len(got) != 0 || tc.diagnostic != "" && (len(got) != 1 || !strings.Contains(got[0], tc.diagnostic)) {
				t.Fatalf("got %v, want %q", got, tc.diagnostic)
			}
		})
	}
}

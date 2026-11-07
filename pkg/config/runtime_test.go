package config

import "testing"

func TestExplicitDeviceStateDirectoriesAreIndependent(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	const ws = "00000000-0000-4000-8000-000000000001"
	if err := SaveLocalStateTo(a, ws, &LocalConfig{Current: "production", Previous: "staging"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocalStateTo(b, ws, &LocalConfig{Current: "development"}); err != nil {
		t.Fatal(err)
	}
	first, err := LoadLocalStateFrom(a, ws)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadLocalStateFrom(b, ws)
	if err != nil {
		t.Fatal(err)
	}
	if first.Current != "production" || first.Previous != "staging" || second.Current != "development" || second.Previous != "" {
		t.Fatalf("state leaked: %+v %+v", first, second)
	}
}
func TestProjectAndEnvironmentUseSuppliedIdentifiers(t *testing.T) {
	ids := []string{"incarnation", "workspace", "second-incarnation"}
	index := 0
	next := func() string { v := ids[index]; index++; return v }
	cfg := NewProjectWithIDs("default", next)
	if cfg.WorkspaceID != "workspace" || cfg.Environments["default"].Incarnation != "incarnation" {
		t.Fatalf("unexpected identifiers: %+v", cfg)
	}
	if err := cfg.AddEnvironmentWithID("staging", next); err != nil {
		t.Fatal(err)
	}
	if cfg.Environments["staging"].Incarnation != "second-incarnation" || index != 3 {
		t.Fatal("identifier source bypassed")
	}
}

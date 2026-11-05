package simulation

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Mutation experiments edit only disposable copies. A compile error is not a
// killed mutant: the intended behavioral test must report an actual failure.
func TestOracleMutationExperiments(t *testing.T) {
	if os.Getenv("ENBU_SIM_MUTATION") != "1" {
		t.Skip("set ENBU_SIM_MUTATION=1 for isolated source mutation experiments")
	}
	cases := []struct{ name, file, old, new, scenario string }{
		{"lost-update", "app/secrets.go", "secrets[key] = value", "delete(secrets,key)", "TestScenarios/concurrent-keys"},
		{"missed-conflict", "app/secrets.go", "func conflictError(cs []merge.Conflict) error {", "func conflictError(cs []merge.Conflict) error { return nil;", "TestScenarios/conflicting-edits"},
		{"privilege-escalation", "app/members.go", "if p, _ := s.head.Principal(s.self()); !p.Admin {", "if p, _ := s.head.Principal(s.self()); !p.Admin && false {", "TestScenarios/membership"},
		{"missed-rollback", "app/workspace.go", "return nil, wspError(fmt.Errorf(\"%w: all previously accepted revisions are missing\", wsp.ErrRollback))", "return nil,storageError(storage.ErrNotFound)", "TestScenarios/adversarial-storage"},
		{"delete-late-valid-state", "app/compact.go", "return err != nil && !errors.Is(err, wsp.ErrRollback), nil", "return true, nil", "TestCompactionLatePublicationAndCrashRecovery"},
		{"delete-temporarily-unreachable-state", "app/compact.go", "case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):\n\t\treturn false, nil", "case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):\n\t\treturn true, nil", "TestCompactionLatePublicationAndCrashRecovery"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"app", "pkg", "test/simulation"} {
				if e := os.CopyFS(filepath.Join(root, dir), os.DirFS(filepath.Join("../..", dir))); e != nil {
					t.Fatal(e)
				}
			}
			for _, name := range []string{"go.mod", "go.sum"} {
				b, e := os.ReadFile(filepath.Join("../..", name))
				if e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			control := exec.Command("go", "test", "-json", "-count=1", "-tags=fixture", "./test/simulation", "-run", "^"+tc.scenario+"$")
			control.Dir = root
			control.Env = append(os.Environ(), "GITHUB_SHA="+revision(t), "ENBU_SIM_MUTATION=0", "ENBU_SIM_EXPLORE=1", "ENBU_SIM_SHARDS=1", "ENBU_SIM_SHARD=0", "ENBU_SIM_ARTIFACTS="+filepath.Join(root, "failures"))
			if output, err := control.CombinedOutput(); err != nil {
				t.Fatalf("unmodified control failed; mutant cannot be scored: %v\n%s", err, output)
			}
			path := filepath.Join(root, tc.file)
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Contains(b, []byte(tc.old)) {
				t.Fatalf("mutation target disappeared: %s", tc.file)
			}
			b = bytes.Replace(b, []byte(tc.old), []byte(tc.new), 1)
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("go", "test", "-json", "-count=1", "-tags=fixture", "./test/simulation", "-run", "^"+tc.scenario+"$")
			cmd.Dir = root
			cmd.Env = control.Env
			out, e := cmd.CombinedOutput()
			if e == nil {
				t.Fatal("mutant survived")
			}
			killed := false
			for _, line := range bytes.Split(out, []byte("\n")) {
				var event struct{ Action, Test string }
				if json.Unmarshal(line, &event) == nil && event.Action == "fail" && event.Test == tc.scenario {
					killed = true
				}
			}
			if !killed {
				t.Fatalf("mutant did not fail the intended behavioral assertion:\n%s", out)
			}
		})
	}
}

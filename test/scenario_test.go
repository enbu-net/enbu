//go:build scenario

package test

import (
	"fmt"
	"github.com/enbu-net/enbu/pkg/config"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScenario_SingleUserAddPull(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Add("alice", "DB_HOST", "localhost"),
		Add("alice", "DB_PORT", "5432"),
		PullContainsAll("alice", "DB_HOST=", "localhost", "DB_PORT=", "5432"),
	)
}

func TestScenario_JoinFlowRequiresApproval(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Add("alice", "SECRET", "only-for-alice"),
		Join("bob"),
		PullFails("bob"),
		AddFails("bob", "BOB_ONLY", "not-yet"),
		Approve("alice", "bob"),
		// Approval re-encrypts, so no separate sync is needed.
		PullContains("bob", "only-for-alice"),
	)
}

func TestScenario_ThreeUsersSequentialJoin(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob", "charlie"),
		Register("alice"),
		Add("alice", "SHARED_KEY", "initial-value"),
		Join("bob"),
		PullFails("bob"),
		Approve("alice", "bob"),
		PullContains("bob", "initial-value"),
		Add("alice", "NEW_KEY", "after-bob-joined"),
		PullContains("bob", "after-bob-joined"),
		Join("charlie"),
		PullFails("charlie"),
		Approve("alice", "charlie"),
		PullContainsAll("charlie", "initial-value", "after-bob-joined"),
	)
}

func TestScenario_AddRejectsExistingSecretAndEditUpdates(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Add("alice", "API_KEY", "old-key"),
		AddFails("alice", "API_KEY", "new-key"),
		PullContains("alice", "old-key"),
		Edit("alice", "API_KEY", "new-key"),
		PullDoesNotContain("alice", "old-key"),
		PullContains("alice", "new-key"),
	)
}

func TestScenario_DeleteSecret(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Add("alice", "API_KEY", "sk-secret"),
		Add("alice", "DATABASE_URL", "postgres://prod/app"),
		Delete("alice", "API_KEY"),
		PullDoesNotContain("alice", "API_KEY=", "sk-secret"),
		PullContainsAll("alice", "DATABASE_URL=", "postgres://prod/app"),
	)
}

func TestScenario_DeleteMissingSecretIsNoop(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Add("alice", "DATABASE_URL", "postgres://prod/app"),
		Delete("alice", "MISSING_KEY"),
		PullContainsAll("alice", "DATABASE_URL=", "postgres://prod/app"),
	)
}

func TestScenario_DeleteBeforeFirstSecretIsNoop(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Delete("alice", "MISSING_KEY"),
		PullFails("alice"),
	)
}

func TestScenario_SpecialCharacterValues(t *testing.T) {
	testCases := []struct{ key, value string }{
		{"JAPANESE", "日本語のシークレット"},
		{"EMOJI", "🔑🔒✨"},
		{"NEWLINES", "line1\\nline2\\nline3"},
		{"QUOTES", `he said "hello"`},
		{"EQUALS", "key=value=extra"},
		{"SPACES", "  leading and trailing  "},
		{"EMPTY", ""},
		{"URL", "postgres://user:p@ss@host:5432/db?sslmode=require"},
	}

	steps := []Step{
		Users("alice"),
		Register("alice"),
	}
	for _, tc := range testCases {
		steps = append(steps, Add("alice", tc.key, tc.value))
	}
	for _, tc := range testCases {
		steps = append(steps, PullContains("alice", tc.key+"="))
	}
	steps = append(steps,
		PullContains("alice", "日本語のシークレット"),
		PullContains("alice", "🔑🔒✨"),
	)

	RunScenario(t, steps...)
}

func TestScenario_ManySecrets(t *testing.T) {
	steps := []Step{
		Users("alice"),
		Register("alice"),
	}

	const count = 50
	for i := range count {
		steps = append(steps, Add("alice", fmt.Sprintf("SECRET_%03d", i), fmt.Sprintf("value-%d", i)))
	}

	steps = append(steps, StepFunc("alice sees all added secret keys", func(t *testing.T, s *ScenarioState) {
		output := pullStdout(t, s.ctx, s.user(t, "alice"))
		for i := range count {
			key := fmt.Sprintf("SECRET_%03d", i)
			if !strings.Contains(output, key+"=") {
				t.Fatalf("missing %s after adding %d secrets", key, count)
			}
		}
	}))

	RunScenario(t, steps...)
}

func TestScenario_PullNoSecrets(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		PullFails("alice"),
	)
}

func TestScenario_SyncIdempotent(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		Add("alice", "KEY", "value"),
		Sync("alice"),
		Sync("alice"),
		Sync("bob"),
		PullContains("alice", "value"),
		PullContains("bob", "value"),
	)
}

// Storage has no compare-and-swap, so concurrent writers publish side by side.
// Every add that reports success must still be there afterwards, for everyone.
func TestScenario_ConcurrentAdds(t *testing.T) {
	names := []string{"alice", "bob", "carol", "dave"}
	steps := []Step{Users(names...)}
	for _, n := range names {
		steps = append(steps, Register(n))
	}
	steps = append(steps, Add("alice", "SEED", "initial"))
	steps = append(steps,
		StepFunc("everyone adds distinct keys at the same time, three rounds", func(t *testing.T, s *ScenarioState) {
			for round := 0; round < 3; round++ {
				var wg sync.WaitGroup
				errs := make([]error, len(names))
				for i, n := range names {
					wg.Add(1)
					go func() {
						defer wg.Done()
						key := fmt.Sprintf("FROM_%s_%d", strings.ToUpper(n), round)
						errs[i] = executeCommand(s.ctx, s.user(t, n).svc, "add", key, key+"-data")
					}()
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Fatalf("%s's add failed in round %d: %v", names[i], round, err)
					}
				}
			}
		}),
		StepFunc("nothing a successful add wrote is lost, for anyone", func(t *testing.T, s *ScenarioState) {
			for _, reader := range names {
				output := pullStdout(t, s.ctx, s.user(t, reader))
				if !strings.Contains(output, "SEED") {
					t.Fatalf("%s lost SEED: %s", reader, output)
				}
				for _, n := range names {
					for round := 0; round < 3; round++ {
						if key := fmt.Sprintf("FROM_%s_%d", strings.ToUpper(n), round); !strings.Contains(output, key) {
							t.Fatalf("%s does not see %s: %s", reader, key, output)
						}
					}
				}
			}
		}),
	)
	RunScenario(t, steps...)
}

// Two people changing one key at the same time is the one case that needs a
// person: both values are kept until someone chooses.
func TestScenario_ConcurrentEditsOfOneKeyNeedAChoice(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		Add("alice", "KEY", "original"),
		StepFunc("both edit KEY at the same time", func(t *testing.T, s *ScenarioState) {
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i, n := range []string{"alice", "bob"} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs[i] = executeCommand(s.ctx, s.user(t, n).svc, "edit", "KEY", n+"-value")
				}()
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("edit %d failed: %v", i, err)
				}
			}
		}),
		StepFunc("the key waits for a decision and neither value is lost", func(t *testing.T, s *ScenarioState) {
			alice := s.user(t, "alice")
			// The editors raced, so the registry may have serialized them; settle
			// whichever way it went.
			err := executeCommand(s.ctx, alice.svc, "pull")
			if err == nil {
				if out := pullStdout(t, s.ctx, alice); !strings.Contains(out, "-value") {
					t.Fatalf("an edit was lost: %s", out)
				}
				return
			}
			if !strings.Contains(err.Error(), "differently") {
				t.Fatalf("unexpected error: %v", err)
			}
			set, lerr := alice.svc.ListConflicts(s.ctx, "")
			if lerr != nil || len(set.Conflicts) != 1 {
				t.Fatalf("listing conflicts: %+v %v", set, lerr)
			}
			// Deciding without the listing's id is refused; with it the choice goes through.
			if err := executeCommand(s.ctx, alice.svc, "resolve", "--pick", "KEY=1"); err == nil {
				t.Fatal("resolve without --seen was accepted")
			}
			if err := executeCommand(s.ctx, alice.svc, "resolve", "--seen", set.ID, "--pick", "KEY=1"); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			for _, n := range []string{"alice", "bob"} {
				if out := pullStdout(t, s.ctx, s.user(t, n)); !strings.Contains(out, "-value") {
					t.Fatalf("%s sees %s after resolving", n, out)
				}
			}
		}),
	)
}

func TestScenario_AddAfterSyncPreservesRecipients(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Add("alice", "FIRST", "first-value"),
		Register("bob"),
		Sync("alice"),
		Add("bob", "SECOND", "second-value"),
		PullContainsAll("alice", "first-value", "second-value"),
		PullContainsAll("bob", "first-value", "second-value"),
	)
}

func TestScenario_PendingDeviceCannotAddUntilApproved(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Add("alice", "DATABASE_URL", "postgres://prod/app"),
		Join("bob"),
		AddFails("bob", "BOB_ONLY", "not-yet"),
		Approve("alice", "bob"),
		Add("bob", "BOB_ONLY", "after-approval"),
		PullContainsAll("alice", "DATABASE_URL", "BOB_ONLY", "after-approval"),
		PullContainsAll("bob", "DATABASE_URL", "BOB_ONLY", "after-approval"),
	)
}

func TestScenario_RemovedMemberLosesAccess(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		Add("alice", "KEY", "before-removal"),
		PullContains("bob", "before-removal"),
		Remove("alice", "bob"),
		PullFails("bob"),
		AddFails("bob", "LATE", "after-removal"),
		Add("alice", "AFTER", "after-removal"),
		PullContainsAll("alice", "before-removal", "after-removal"),
	)
}

func TestScenario_SyncBeforeFirstSecretThenTeamCanPull(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		Sync("alice"),
		Add("alice", "FIRST_SECRET", "created-after-empty-sync"),
		PullContains("bob", "created-after-empty-sync"),
	)
}

func TestScenario_EnvironmentSecretsAreIsolated(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "API_KEY", "dev-secret"),
		AddEnv("alice", "prod", "API_KEY", "prod-secret"),
		PullEnvContainsAll("alice", "dev", "API_KEY", "dev-secret"),
		PullEnvDoesNotContain("alice", "dev", "prod-secret"),
		PullEnvContainsAll("alice", "prod", "API_KEY", "prod-secret"),
		PullEnvDoesNotContain("alice", "prod", "dev-secret"),
		PullEnvContainsAll("bob", "dev", "dev-secret"),
		PullEnvContainsAll("bob", "prod", "prod-secret"),
	)
}

func TestScenario_RotateSharedSecretForWholeTeam(t *testing.T) {
	RunScenario(t,
		Users("alice", "bob", "charlie"),
		Register("alice"),
		Register("bob"),
		Add("alice", "API_TOKEN", "old-token"),
		Add("alice", "UNCHANGED", "still-here"),
		Sync("alice"),
		Register("charlie"),
		Sync("bob"),
		Edit("charlie", "API_TOKEN", "new-token"),
		PullDoesNotContain("alice", "old-token"),
		PullContainsAll("alice", "API_TOKEN", "new-token", "UNCHANGED", "still-here"),
		PullDoesNotContain("bob", "old-token"),
		PullContainsAll("bob", "API_TOKEN", "new-token", "UNCHANGED", "still-here"),
		PullDoesNotContain("charlie", "old-token"),
		PullContainsAll("charlie", "API_TOKEN", "new-token", "UNCHANGED", "still-here"),
	)
}

func TestScenario_FullLifecycleMultiStage(t *testing.T) {
	RunScenario(t,
		Users("founder", "early-hire", "intern", "contractor"),
		Register("founder"),
		Add("founder", "DB_URL", "postgres://prod:5432/app"),
		Add("founder", "STRIPE_KEY", "sk_live_xxx"),
		Join("early-hire"),
		PullFails("early-hire"),
		Approve("founder", "early-hire"),
		PullContains("early-hire", "sk_live_xxx"),
		Add("early-hire", "REDIS_URL", "redis://cache:6379"),
		Add("early-hire", "SENTRY_DSN", "https://sentry.io/xxx"),
		PullContainsAll("founder", "REDIS_URL", "SENTRY_DSN"),
		Register("intern"),
		Sync("early-hire"),
		PullContains("intern", "postgres://prod:5432/app"),
		Add("intern", "INTERN_TEST", "test-value"),
		Register("contractor"),
		Sync("founder"),
		PullContainsAll("founder", "DB_URL", "STRIPE_KEY", "REDIS_URL", "SENTRY_DSN", "INTERN_TEST"),
		PullContainsAll("early-hire", "DB_URL", "STRIPE_KEY", "REDIS_URL", "SENTRY_DSN", "INTERN_TEST"),
		PullContainsAll("intern", "DB_URL", "STRIPE_KEY", "REDIS_URL", "SENTRY_DSN", "INTERN_TEST"),
		PullContainsAll("contractor", "DB_URL", "STRIPE_KEY", "REDIS_URL", "SENTRY_DSN", "INTERN_TEST"),
	)
}

func TestScenario_MultiEnvironmentSameRecipient(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "DB_URL", "postgres://dev/app"),
		AddEnv("alice", "staging", "DB_URL", "postgres://staging/app"),
		AddEnv("alice", "prod", "DB_URL", "postgres://prod/app"),
		PullEnvContainsAll("bob", "dev", "postgres://dev/app"),
		PullEnvContainsAll("bob", "staging", "postgres://staging/app"),
		PullEnvContainsAll("bob", "prod", "postgres://prod/app"),
		PullEnvDoesNotContain("bob", "dev", "postgres://prod/app"),
		PullEnvDoesNotContain("bob", "prod", "postgres://dev/app"),
	)
}

func TestScenario_EnvironmentIndependentEditsAndDeletes(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice"),
		Register("alice"),
		AddEnv("alice", "dev", "API_KEY", "dev-key"),
		AddEnv("alice", "prod", "API_KEY", "prod-key"),
		AddEnv("alice", "dev", "EXTRA", "dev-extra"),
		StepFunc("edit dev does not affect prod", func(t *testing.T, s *ScenarioState) {
			if err := executeCommand(s.ctx, s.user(t, "alice").svc, "edit", "--env", "dev", "API_KEY", "dev-key-v2"); err != nil {
				t.Fatalf("edit dev: %v", err)
			}
			devOut := pullStdoutEnv(t, s.ctx, s.user(t, "alice"), "dev")
			if !strings.Contains(devOut, "dev-key-v2") {
				t.Fatalf("dev should have updated key: %s", devOut)
			}
			prodOut := pullStdoutEnv(t, s.ctx, s.user(t, "alice"), "prod")
			if !strings.Contains(prodOut, "prod-key") {
				t.Fatalf("prod should still have original key: %s", prodOut)
			}
			if strings.Contains(prodOut, "dev-key-v2") {
				t.Fatal("prod should not contain dev value")
			}
		}),
		StepFunc("delete from dev does not affect prod", func(t *testing.T, s *ScenarioState) {
			if err := executeCommand(s.ctx, s.user(t, "alice").svc, "delete", "--env", "dev", "EXTRA"); err != nil {
				t.Fatalf("delete dev EXTRA: %v", err)
			}
			devOut := pullStdoutEnv(t, s.ctx, s.user(t, "alice"), "dev")
			if strings.Contains(devOut, "EXTRA") {
				t.Fatal("dev should not have EXTRA after delete")
			}
			prodOut := pullStdoutEnv(t, s.ctx, s.user(t, "alice"), "prod")
			if !strings.Contains(prodOut, "prod-key") {
				t.Fatal("prod should be unaffected")
			}
		}),
	)
}

func TestScenario_ApprovalReEncryptsEveryEnvironment(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob", "charlie"),
		Register("alice"),
		AddEnv("alice", "dev", "SECRET", "dev-value"),
		AddEnv("alice", "prod", "SECRET", "prod-value"),
		Join("bob"),
		Join("charlie"),
		PullFailsEnv("bob", "dev"),
		PullFailsEnv("charlie", "prod"),
		Approve("alice", "bob"),
		Approve("alice", "charlie"),
		PullEnvContainsAll("bob", "dev", "dev-value"),
		PullEnvContainsAll("bob", "prod", "prod-value"),
		PullEnvContainsAll("charlie", "dev", "dev-value"),
		PullEnvContainsAll("charlie", "prod", "prod-value"),
	)
}

func TestScenario_LateJoinerGetsAllEnvironments(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob", "charlie"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "KEY", "dev-val"),
		AddEnv("alice", "staging", "KEY", "staging-val"),
		Sync("alice"),
		PullEnvContainsAll("bob", "dev", "dev-val"),
		PullEnvContainsAll("bob", "staging", "staging-val"),
		Join("charlie"),
		PullFailsEnv("charlie", "dev"),
		Approve("alice", "charlie"),
		PullEnvContainsAll("charlie", "dev", "dev-val"),
		PullEnvContainsAll("charlie", "staging", "staging-val"),
	)
}

func TestScenario_ConcurrentSyncsOnDifferentEnvironments(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob", "charlie"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "DEV_KEY", "dev-123"),
		AddEnv("alice", "prod", "PROD_KEY", "prod-456"),
		Register("charlie"),
		StepFunc("alice syncs dev and prod concurrently", func(t *testing.T, s *ScenarioState) {
			alice := s.user(t, "alice")
			var wg sync.WaitGroup
			var err1, err2 error
			wg.Add(2)
			go func() {
				defer wg.Done()
				err1 = executeCommand(s.ctx, alice.svc, "sync", "--env", "dev")
			}()
			go func() {
				defer wg.Done()
				err2 = executeCommand(s.ctx, alice.svc, "sync", "--env", "prod")
			}()
			wg.Wait()
			if err1 != nil {
				t.Fatalf("sync dev failed: %v", err1)
			}
			if err2 != nil {
				t.Fatalf("sync prod failed: %v", err2)
			}
		}),
		PullEnvContainsAll("charlie", "dev", "DEV_KEY", "dev-123"),
		PullEnvContainsAll("charlie", "prod", "PROD_KEY", "prod-456"),
	)
}

func TestScenario_DefaultEnvironmentUsedWhenNoEnvFlag(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config with dev as default", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice"),
		Register("alice"),
		Add("alice", "DEFAULT_KEY", "goes-to-dev"),
		PullEnvContainsAll("alice", "dev", "DEFAULT_KEY", "goes-to-dev"),
		PullFailsEnv("alice", "prod"),
	)
}

func TestScenario_EnvFlagOverridesDefault(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config with dev as default", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice"),
		Register("alice"),
		Add("alice", "DEV_ONLY", "dev-val"),
		AddEnv("alice", "prod", "PROD_ONLY", "prod-val"),
		PullEnvContainsAll("alice", "dev", "DEV_ONLY"),
		PullEnvDoesNotContain("alice", "dev", "PROD_ONLY"),
		PullEnvContainsAll("alice", "prod", "PROD_ONLY"),
		PullEnvDoesNotContain("alice", "prod", "DEV_ONLY"),
	)
}

func TestScenario_EditInOneEnvDoesNotAffectOther(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "SHARED_KEY", "original"),
		AddEnv("alice", "prod", "SHARED_KEY", "original"),
		StepFunc("bob edits dev only", func(t *testing.T, s *ScenarioState) {
			if err := executeCommand(s.ctx, s.user(t, "bob").svc, "edit", "--env", "dev", "SHARED_KEY", "updated-by-bob"); err != nil {
				t.Fatalf("bob edit dev: %v", err)
			}
		}),
		PullEnvContainsAll("alice", "dev", "updated-by-bob"),
		PullEnvDoesNotContain("alice", "prod", "updated-by-bob"),
		PullEnvContainsAll("alice", "prod", "original"),
	)
}

func TestScenario_SyncOnEmptyEnvironmentIsNoop(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.empty]
output = ".env.empty"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob"),
		Register("alice"),
		Register("bob"),
		AddEnv("alice", "dev", "KEY", "value"),
		SyncEnv("alice", "empty"),
		PullEnvContainsAll("alice", "dev", "KEY", "value"),
		PullFailsEnv("alice", "empty"),
	)
}

func TestScenario_ManyUsersAllEnvironments(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice", "bob", "charlie", "dave", "eve"),
		Register("alice"),
		Register("bob"),
		Register("charlie"),
		Register("dave"),
		Register("eve"),
		AddEnv("alice", "dev", "TOKEN", "dev-token"),
		AddEnv("alice", "staging", "TOKEN", "staging-token"),
		AddEnv("alice", "prod", "TOKEN", "prod-token"),
		PullEnvContainsAll("bob", "dev", "dev-token"),
		PullEnvContainsAll("charlie", "staging", "staging-token"),
		PullEnvContainsAll("dave", "prod", "prod-token"),
		PullEnvContainsAll("eve", "dev", "dev-token"),
		PullEnvContainsAll("eve", "staging", "staging-token"),
		PullEnvContainsAll("eve", "prod", "prod-token"),
	)
}

func TestScenario_DeleteAllSecretsInEnvironment(t *testing.T) {
	RunScenario(t,
		StepFunc("environment config exists", func(t *testing.T, s *ScenarioState) {
			content := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
			cfg, loadErr := config.LoadProject()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			content = "workspace_id = \"" + cfg.WorkspaceID + "\"\n" + content
			if err := os.WriteFile("enbu.toml", []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}),
		Users("alice"),
		Register("alice"),
		AddEnv("alice", "dev", "KEY1", "val1"),
		AddEnv("alice", "dev", "KEY2", "val2"),
		AddEnv("alice", "prod", "PROD_KEY", "prod-val"),
		StepFunc("delete all dev secrets", func(t *testing.T, s *ScenarioState) {
			alice := s.user(t, "alice")
			if err := executeCommand(s.ctx, alice.svc, "delete", "--env", "dev", "KEY1"); err != nil {
				t.Fatal(err)
			}
			if err := executeCommand(s.ctx, alice.svc, "delete", "--env", "dev", "KEY2"); err != nil {
				t.Fatal(err)
			}
		}),
		PullEnvContainsAll("alice", "prod", "PROD_KEY", "prod-val"),
	)
}

func TestScenario_HistoryAddRestore(t *testing.T) {
	RunScenario(t,
		Users("alice"),
		Register("alice"),
		Add("alice", "DB_HOST", "original-value"),
		StepFunc("sleep 1s for distinct snapshot timestamp", func(t *testing.T, s *ScenarioState) {
			// Snapshots are tagged with unix timestamp (1s resolution).
			// Without this sleep, add and edit land on the same second
			// and the second snapshot tag silently overwrites the first.
			time.Sleep(1100 * time.Millisecond)
		}),
		Edit("alice", "DB_HOST", "updated-value"),
		PullContains("alice", "updated-value"),
		StepFunc("history has 2 entries", func(t *testing.T, s *ScenarioState) {
			entries, err := s.user(t, "alice").svc.ListHistory(s.ctx, "")
			if err != nil {
				t.Fatalf("ListHistory: %v", err)
			}
			if len(entries) != 2 {
				t.Fatalf("expected 2 history entries, got %d", len(entries))
			}
		}),
		StepFunc("restore to version 1", func(t *testing.T, s *ScenarioState) {
			if err := executeCommand(s.ctx, s.user(t, "alice").svc, "history", "restore", "1"); err != nil {
				t.Fatalf("history restore: %v", err)
			}
		}),
		PullContains("alice", "original-value"),
		PullDoesNotContain("alice", "updated-value"),
	)
}

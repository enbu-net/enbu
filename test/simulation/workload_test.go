package simulation

import "testing"

func TestRejoinAfterMembership(t *testing.T) {
	t.Parallel()
	exercise(t, 811, Plan{Devices: 3, Scenario: "membership", Actions: []Action{
		{Kind: "rejoin", Device: 0},
		{Kind: "rejoin", Device: 1},
		{Kind: "add", Device: 1, Key: "AFTER_REJOIN", Value: "preserved"},
		{Kind: "restart", Device: 1},
		{Kind: "read", Device: 1},
	}})
}

func TestMixedEnvironmentLifecycle(t *testing.T) {
	t.Parallel()
	exercise(t, 812, Plan{Devices: 3, Actions: []Action{
		{Kind: "create-env", Device: 0, Environment: "env_0"},
		{Kind: "add", Device: 1, Environment: "env_0", Key: "A", Value: "kept"},
		{Kind: "rename-env", Device: 2, Environment: "env_0"},
		{Kind: "read", Device: 1, Environment: "env_0_renamed"},
		{Kind: "switch-env", Device: 2, Environment: "default"},
		{Kind: "delete-env", Device: 2, Environment: "env_0_renamed"},
		{Kind: "create-env", Device: 1, Environment: "env_0_renamed"},
		{Kind: "read", Device: 0, Environment: "env_0_renamed"},
		{Kind: "rejoin", Device: 0},
	}})
}

// Each device's environment choice is modelled independently of the app: the
// renaming device follows its rename, another device's stale choice falls back
// to the default, and deleting the modelled current environment is refused.
func TestWorkloadModelsEachDevicesEnvironment(t *testing.T) {
	t.Parallel()
	exercise(t, 813, Plan{Devices: 2, Actions: []Action{
		{Kind: "create-env", Device: 0, Environment: "env_0"},
		{Kind: "delete-env", Device: 0, Environment: "env_0"},
		{Kind: "rename-env", Device: 1, Environment: "env_0"},
		{Kind: "delete-env", Device: 0, Environment: "env_0_renamed"},
		{Kind: "create-env", Device: 1, Environment: "env_1"},
		{Kind: "rename-env", Device: 1, Environment: "env_1"},
		{Kind: "delete-env", Device: 1, Environment: "env_1_renamed"},
		{Kind: "switch-env", Device: 1, Environment: "default"},
		{Kind: "delete-env", Device: 1, Environment: "env_1_renamed"},
	}})
}

// Once the model has written an environment, emptying it keeps its history:
// editing a missing key is secret_missing, never artifact_not_found.
func TestWorkloadRemembersWrittenEnvironments(t *testing.T) {
	t.Parallel()
	exercise(t, 814, Plan{Devices: 2, Actions: []Action{
		{Kind: "create-env", Device: 0, Environment: "env_0"},
		{Kind: "edit", Device: 1, Environment: "env_0", Key: "A", Value: "never"},
		{Kind: "add", Device: 1, Environment: "env_0", Key: "A", Value: "kept"},
		{Kind: "delete", Device: 0, Environment: "env_0", Key: "A"},
		{Kind: "edit", Device: 1, Environment: "env_0", Key: "A", Value: "missing"},
		{Kind: "pull", Device: 0, Environment: "env_0"},
		{Kind: "rename-env", Device: 0, Environment: "env_0"},
		{Kind: "edit", Device: 1, Environment: "env_0_renamed", Key: "A", Value: "missing"},
	}})
}

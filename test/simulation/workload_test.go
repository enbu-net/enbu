package simulation

import "testing"

func TestRejoinAfterMembership(t *testing.T) {
	exercise(t, 811, Plan{Devices: 3, Scenario: "membership", Actions: []Action{
		{Kind: "rejoin", Device: 0},
		{Kind: "rejoin", Device: 1},
		{Kind: "add", Device: 1, Key: "AFTER_REJOIN", Value: "preserved"},
		{Kind: "restart", Device: 1},
		{Kind: "read", Device: 1},
	}})
}

func TestMixedEnvironmentLifecycle(t *testing.T) {
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

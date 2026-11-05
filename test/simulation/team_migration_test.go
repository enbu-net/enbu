package simulation

import "testing"

func TestTeamMigrationClocks(t *testing.T) {
	for _, profile := range []string{"", "frozen", "backward", "skewed"} {
		t.Run(profile, func(t *testing.T) { exercise(t, 31, Plan{Devices: 3, Clock: profile, Scenario: "team-migration"}) })
	}
}

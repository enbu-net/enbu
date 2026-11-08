package simulation

import (
	"fmt"
	"testing"
)

func TestFirstMemberOnboardingClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			t.Run(fmt.Sprintf("devices-%d/%s", devices, profile), func(t *testing.T) {
				shardCase(t)
				exercise(t, 43, Plan{Devices: devices, Clock: profile, Scenario: "first-member", Actions: Generate(43, 16, devices)})
			})
		}
	}
}

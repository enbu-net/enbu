package simulation

import (
	"fmt"
	"testing"
)

func TestPartialKeyRecoveryClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, kind := range partialKeyCases {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", kind, devices, profile), func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					exercise(t, 59, Plan{Devices: devices, Clock: profile, Scenario: "partial-key-" + kind})
				})
			}
		}
	}
}

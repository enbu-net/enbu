package simulation

import (
	"fmt"
	"testing"
)

func TestMultipleWorkspaceClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, scenario := range []string{"multiple-workspaces", "shared-storage-workspaces"} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", scenario, devices, profile), func(t *testing.T) {
					exercise(t, 47, Plan{Devices: devices, Clock: profile, Scenario: scenario})
				})
			}
		}
	}
}

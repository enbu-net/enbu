package simulation

import (
	"fmt"
	"testing"
)

func TestOutputBoundaryClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, kind := range []string{"public", "hardlink", "canceled-hardlink", "removed-hardlink"} {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", kind, devices, profile), func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					exercise(t, 101, Plan{Devices: devices, Clock: profile, Scenario: "output-boundary-" + kind})
				})
			}
		}
	}
}

func TestOutputBoundaryMembershipSmoke(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"removed-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			exercise(t, 101, Plan{Devices: 3, Scenario: "output-boundary-" + kind})
		})
	}
}

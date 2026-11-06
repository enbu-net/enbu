package simulation

import (
	"fmt"
	"testing"
)

func TestOutputBoundaryClocks(t *testing.T) {
	exploration(t)
	for _, kind := range []string{"public", "hardlink", "canceled-hardlink"} {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", kind, devices, profile), func(t *testing.T) {
					shardCase(t)
					exercise(t, 101, Plan{Devices: devices, Clock: profile, Scenario: "output-boundary-" + kind})
				})
			}
		}
	}
}

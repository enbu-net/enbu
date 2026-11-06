package simulation

import (
	"fmt"
	"testing"
)

func TestRequestFloodClocks(t *testing.T) {
	exploration(t)
	for _, scenario := range []string{"request-flood", "hidden-request-conflict"} {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", scenario, devices, profile), func(t *testing.T) { exercise(t, 67, Plan{Devices: devices, Clock: profile, Scenario: scenario}) })
			}
		}
	}
}

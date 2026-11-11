package simulation

import (
	"fmt"
	"testing"
)

func TestSignedWireAttackClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, mode := range []string{"warm", "cold"} {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", mode, devices, profile), func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					exercise(t, 83, Plan{Devices: devices, Clock: profile, Scenario: "wire-format-" + mode})
				})
			}
		}
	}
}

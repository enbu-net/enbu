package simulation

import (
	"fmt"
	"testing"
)

func TestDisasterRecoverySmoke(t *testing.T) {
	for _, mode := range []string{"witness", "all-stale", "retired-key"} {
		t.Run(mode, func(t *testing.T) {
			exercise(t, 113, Plan{Devices: 3, Scenario: "disaster-" + mode + "-cold"})
		})
	}
}

func TestDisasterRecoveryClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for _, mode := range []string{"witness", "all-stale", "retired-key"} {
				for _, cache := range []string{"warm", "cold"} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/%s", devices, profile, mode, cache), func(t *testing.T) {
						shardCase(t)
						exercise(t, 113, Plan{Devices: devices, Clock: profile, Scenario: "disaster-" + mode + "-" + cache})
					})
				}
			}
		}
	}
}

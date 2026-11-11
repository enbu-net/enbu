package simulation

import (
	"fmt"
	"testing"
)

func TestHistorySnapshotSmoke(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"forward", "backward"} {
		for _, operation := range []string{"list", "diff"} {
			for _, change := range []string{"edit", "remove", "compact"} {
				t.Run(profile+"/"+operation+"/"+change, func(t *testing.T) {
					t.Parallel()
					shardCase(t)
					clock := ""
					if profile == "backward" {
						clock = profile
					}
					exercise(t, 127, Plan{Devices: 3, Clock: clock, Scenario: "history-snapshot-" + operation + "-" + change + "-cold"})
				})
			}
		}
	}
}

func TestHistorySnapshotClocks(t *testing.T) {
	t.Parallel()
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			for _, operation := range []string{"list", "diff"} {
				for _, change := range []string{"edit", "remove", "compact"} {
					for _, cache := range []string{"warm", "cold"} {
						t.Run(fmt.Sprintf("devices-%d/%s/%s/%s/%s", devices, profile, operation, change, cache), func(t *testing.T) {
							t.Parallel()
							shardCase(t)
							exercise(t, 127, Plan{Devices: devices, Clock: profile, Scenario: "history-snapshot-" + operation + "-" + change + "-" + cache})
						})
					}
				}
			}
		}
	}
}

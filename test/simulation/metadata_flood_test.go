package simulation

import (
	"fmt"
	"testing"
)

func TestMetadataFloodClocks(t *testing.T) {
	exploration(t)
	for _, mode := range metadataFloodCases {
		for _, devices := range []int{2, 3, 8} {
			for _, profile := range []string{"", "frozen", "backward", "skewed"} {
				t.Run(fmt.Sprintf("%s/devices-%d/%s", mode, devices, profile), func(t *testing.T) {
					shardCase(t)
					exercise(t, 71, Plan{Devices: devices, Clock: profile, Scenario: "metadata-" + mode})
				})
			}
		}
	}
}

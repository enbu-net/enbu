package simulation

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestGeneratedGroupsUseDistinctDevicesAndPreservePriorState(t *testing.T) {
	for devices := 2; devices <= 8; devices++ {
		actions := Generate(19, 64, devices)
		groups := 0
		for _, action := range actions {
			if action.Kind != "parallel" {
				continue
			}
			groups++
			c := action.Parallel
			if c == nil || len(c.Devices) != 2 || c.Devices[0] == c.Devices[1] {
				t.Fatalf("invalid generated group: %+v", c)
			}
			for _, device := range c.Devices {
				if device < 0 || device >= devices {
					t.Fatalf("invalid device %d", device)
				}
			}
		}
		if groups != 4 {
			t.Fatalf("expected four concurrent groups, got %d", groups)
		}
		if !reflect.DeepEqual(actions, Generate(19, 64, devices)) {
			t.Fatal("generation not deterministic")
		}
	}
	exercise(t, 901, Plan{Devices: 4, Actions: []Action{
		{Kind: "add", Device: 2, Key: "BEFORE", Value: "must survive"},
		{Kind: "parallel", Parallel: &ConcurrentCase{Left: "edit", Right: "delete", SameKey: true, Devices: []int{2, 3}, Compact: true}},
		{Kind: "restart", Device: 2},
		{Kind: "parallel", Parallel: &ConcurrentCase{Left: "import", Right: "sync", Devices: []int{1, 2}}},
		{Kind: "compact", Device: 0},
		{Kind: "rejoin", Device: 2},
		{Kind: "read", Device: 3},
	}})
}
func TestGeneratedConcurrentWorkloads(t *testing.T) {
	exploration(t)
	for devices := 3; devices <= 8; devices++ {
		for seed := uint64(0); seed < 4; seed++ {
			if os.Getenv("ENBU_SIM_SHARDS") != "" {
				shards := integer(t, "ENBU_SIM_SHARDS", 1)
				shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
				if err != nil || shard < 0 || shard >= shards {
					t.Fatal("invalid shard")
				}
				if ((devices-3)*4+int(seed))%shards != shard {
					continue
				}
			}
			t.Run(fmt.Sprintf("devices-%d/seed-%d", devices, seed), func(t *testing.T) {
				exercise(t, seed+3000, Plan{Devices: devices, Actions: Generate(seed, 32, devices)})
			})
		}
	}
}

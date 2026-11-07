package simulation

import (
	"fmt"
	"strings"
	"testing"
)

func TestLargerTeamSmoke(t *testing.T) {
	shardCase(t)
	exercise(t, 269, Plan{Devices: 9, Clock: "frozen", Swarm: "disjoint-mixed"})
}

func TestLargerTeamRejectsInvalidCountsBeforeBootstrap(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 33, 4096} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			tape, err := Prepare(269, "invalid-team-size", Plan{Devices: count})
			if err != nil {
				t.Fatal(err)
			}
			if err := Execute(t.Context(), tape, t.TempDir()); err == nil {
				t.Fatal("invalid team size accepted")
			}
			if len(tape.Recording.Entries) != 1 || tape.Recording.Entries[0].Kind != "plan" {
				t.Fatal("invalid team size reached bootstrap")
			}
		})
	}
}

func TestLargerTeamClocks(t *testing.T) {
	exploration(t)
	scenes := []string{"swarm-disjoint-add", "swarm-disjoint-mixed", "swarm-identical-edit", "swarm-identical-delete", "swarm-distinct-edit", "swarm-edit-delete", "swarm-conflicting-import", "swarm-offline-observer", "team-incident"}
	for _, mode := range []string{"witness", "all-stale", "retired-key", "compacted", "compacted-no-record", "compacted-old-data"} {
		for _, cache := range []string{"warm", "cold"} {
			scenes = append(scenes, "disaster-"+mode+"-"+cache)
		}
	}
	index := 0
	for _, devices := range []int{9, 16, 32} {
		for _, profile := range []string{"", "frozen", "backward", "skewed"} {
			name := profile
			if name == "" {
				name = "forward"
			}
			for _, scene := range scenes {
				t.Run(fmt.Sprintf("devices-%d/%s/%s", devices, name, scene), func(t *testing.T) {
					indexedCase(t, index)
					plan := Plan{Devices: devices, Clock: profile, Scenario: scene}
					if strings.HasPrefix(scene, "swarm-") {
						plan.Scenario = ""
						plan.Swarm = strings.TrimPrefix(scene, "swarm-")
					}
					exercise(t, 269, plan)
				})
				index++
			}
		}
	}
}

package simulation

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
)

func TestMultiUserClockProfiles(t *testing.T) {
	exploration(t)
	index := 0
	for _, clock := range []string{"frozen", "backward", "skewed"} {
		for _, scenario := range []string{"history", "key-update", "membership", "concurrent-keys", "conflicting-edits", "control-fork"} {
			index++
			if os.Getenv("ENBU_SIM_SHARDS") != "" {
				shards := integer(t, "ENBU_SIM_SHARDS", 1)
				shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
				if err != nil || shard < 0 || shard >= shards {
					t.Fatal("invalid shard")
				}
				if (index-1)%shards != shard {
					continue
				}
			}
			for seed := uint64(0); seed < 4; seed++ {
				t.Run(fmt.Sprintf("%s/%s/seed-%d", clock, scenario, seed), func(t *testing.T) {
					exercise(t, seed, Plan{Devices: 3, Clock: clock, Scenario: scenario})
				})
			}
		}
	}
}

func TestClockReadsDoNotAdvanceTimers(t *testing.T) {
	for _, profile := range []string{"", "frozen", "backward", "skewed"} {
		t.Run(profile, func(t *testing.T) {
			tape := NewTape(0, "clock-contract")
			w, err := NewWorld(t.TempDir(), tape, 3)
			if err != nil {
				t.Fatal(err)
			}
			w.Clock = profile
			for _, d := range w.Devices {
				c := d.App.Runtime.Clock
				before := c.Now()
				ctx, cancel := clock.WithTimeout(t.Context(), c, time.Second)
				for i := 0; i < 1000; i++ {
					if !c.Now().Equal(before) || ctx.Err() != nil {
						t.Fatal("reading time advanced the clock")
					}
				}
				w.timeline.Advance(time.Second - time.Nanosecond)
				if ctx.Err() != nil {
					t.Fatal("timer expired early")
				}
				w.timeline.Advance(time.Nanosecond)
				<-ctx.Done()
				cancel()
				if ctx.Err() != context.DeadlineExceeded {
					t.Fatalf("wrong deadline: %v", ctx.Err())
				}
			}
		})
	}
}

func TestClockProfilesWithCompoundRaces(t *testing.T) {
	exploration(t)
	index := 0
	for _, profile := range []string{"frozen", "backward", "skewed"} {
		for _, control := range []string{"remove-writer", "demote-admin"} {
			for _, fault := range []string{"crash-before", "crash-after", "after"} {
				for _, resolution := range []string{"same", "different", "delete"} {
					index++
					if os.Getenv("ENBU_SIM_SHARDS") != "" {
						shards := integer(t, "ENBU_SIM_SHARDS", 1)
						shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
						if err != nil || shard < 0 || shard >= shards {
							t.Fatal("invalid shard")
						}
						if (index-1)%shards != shard {
							continue
						}
					}
					for seed := uint64(0); seed < 4; seed++ {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/seed-%d", profile, control, fault, resolution, seed), func(t *testing.T) {
							exercise(t, seed, Plan{Devices: 4, Clock: profile, Compound: &CompoundCase{Control: control, Fault: fault, Resolution: resolution}})
						})
					}
				}
			}
		}
	}
}

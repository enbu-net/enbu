package simulation

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

func TestConcurrentCompactionSmoke(t *testing.T) {
	run := func(tape *Tape) {
		t.Helper()
		world, err := NewWorld(t.TempDir(), tape, 3)
		if err != nil {
			t.Fatal(err)
		}
		ctx := wsp.WithSerialHeadReads(t.Context())
		if err := world.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		c := ConcurrentCase{Left: "delete", Right: "delete", SameKey: true, Devices: []int{1, 2}}
		if err := world.ConcurrentCase(ctx, c); err != nil {
			t.Fatal(err)
		}
		_, refusal := world.Devices[0].App.CompactHistory(ctx, "default", 1)
		if err := requireCode(refusal, apperr.CodeConflict); err != nil {
			t.Fatal(err)
		}
		c.Compact = true
		if err := validateConcurrentResults(c, false, []error{nil, nil, refusal}); err != nil {
			t.Fatal(err)
		}
		if err := validateConcurrentResults(c, false, []error{refusal, nil, nil}); err == nil {
			t.Fatal("writer conflict was accepted as a compactor result")
		}
		if err := validateConcurrentResults(c, false, []error{nil, refusal}); err == nil {
			t.Fatal("missing compactor result was accepted")
		}
		if err := tape.Observe("delayed-compactor", nil, ErrorCode(refusal)); err != nil {
			t.Fatal(err)
		}
		if err := world.Check(ctx, "default"); err != nil {
			t.Fatal(err)
		}
		if err := tape.Finish(); err != nil {
			t.Fatal(err)
		}
	}
	tape := NewTape(0, "delayed-compactor")
	run(tape)
	run(&Tape{Recording: tape.Recording, Replay: true})
}

func TestConcurrentOperationMatrix(t *testing.T) {
	exploration(t)
	index := 0
	for _, left := range ConcurrentOperations {
		for _, right := range ConcurrentOperations {
			for _, same := range []bool{false, true} {
				index++
				if raw := os.Getenv("ENBU_SIM_SHARDS"); raw != "" {
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
					t.Run(fmt.Sprintf("%s/%s/same-%t/seed-%d", left, right, same, seed), func(t *testing.T) {
						exercise(t, seed, Plan{Devices: 3, Concurrent: &ConcurrentCase{Left: left, Right: right, SameKey: same}})
					})
				}
			}
		}
	}
}

func TestConcurrentAdditions(t *testing.T) {
	exploration(t)
	for _, same := range []bool{false, true} {
		for seed := uint64(0); seed < 4; seed++ {
			t.Run(fmt.Sprintf("same-%t/seed-%d", same, seed), func(t *testing.T) {
				exercise(t, seed, Plan{Devices: 3, Concurrent: &ConcurrentCase{Left: "add", Right: "add", SameKey: same}})
			})
		}
	}
}

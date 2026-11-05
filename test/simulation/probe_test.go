package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/pkg/wsp"
	"os"
	"sort"
	"strconv"
	"testing"
)

func TestOperationFaultMatrix(t *testing.T) {
	for index, op := range ProbeOperations {
		if os.Getenv("ENBU_SIM_SHARDS") != "" {
			shards := integer(t, "ENBU_SIM_SHARDS", 1)
			shard, err := strconv.Atoi(os.Getenv("ENBU_SIM_SHARD"))
			if err != nil || shard < 0 || shard >= shards {
				t.Fatal("invalid shard")
			}
			if index%shards != shard {
				continue
			}
		}
		t.Run(op, func(t *testing.T) {
			w, e := NewWorld(t.TempDir(), NewTape(999, ""), 3)
			if e != nil {
				t.Fatal(e)
			}
			ctx := wsp.WithSerialHeadReads(context.Background())
			if e := w.Bootstrap(ctx); e != nil {
				t.Fatal(e)
			}
			counts, e := w.Probe(ctx, Probe{Operation: op})
			if e != nil {
				t.Fatal(e)
			}
			methods := make([]string, 0, len(counts))
			for method := range counts {
				methods = append(methods, method)
			}
			sort.Strings(methods)
			for _, method := range methods {
				occurrences := []int{1}
				if counts[method] > 1 {
					occurrences = append(occurrences, counts[method])
				}
				if os.Getenv("ENBU_SIM_EXHAUSTIVE") == "1" {
					occurrences = nil
					for i := 1; i <= counts[method]; i++ {
						occurrences = append(occurrences, i)
					}
				}
				modes := []string{"before", "cancel", "crash-before"}
				if method == "publish" || method == "delete" {
					modes = append(modes, "after", "crash-after")
				}
				for _, at := range occurrences {
					for _, mode := range modes {
						t.Run(fmt.Sprintf("%s-%d-%s", method, at, mode), func(t *testing.T) { exercise(t, 999, Plan{Devices: 3, Probe: &Probe{op, Fault{method, at, mode}}}) })
					}
				}
			}
		})
	}
}

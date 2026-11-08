package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/pkg/config"
	"sort"
	"testing"
)

func TestFoundingRetriesExactControlAfterLostReply(t *testing.T) {
	for _, mode := range []string{"before", "after", "crash-before", "crash-after"} {
		t.Run(mode, func(t *testing.T) {
			tape := NewTape(123, "")
			w, e := NewWorld(t.TempDir(), tape, 2)
			if e != nil {
				t.Fatal(e)
			}
			d := w.Devices[0]
			d.Store.Arm(Fault{"publish", 1, mode})
			if e := catchCrash(func() error { _, err := d.App.InitializeRepository(context.Background()); return err }); e == nil {
				t.Fatal("fault not returned")
			}
			cfg, e := config.LoadProjectFrom(d.App.RepositoryDir)
			if e != nil {
				t.Fatal(e)
			}
			genesis := cfg.ControlGenesis
			if genesis == "" {
				t.Fatal("lost trusted genesis")
			}
			w.Restart(0)
			d = w.Devices[0]
			d.Store.Arm(Fault{})
			r, e := d.App.InitializeRepository(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if r.ControlGenesis != genesis {
				t.Fatal("retry changed root")
			}
			if e := d.App.AddSecret(context.Background(), "default", "AFTER", "ok"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestFoundingEveryStorageBoundaryRecovers(t *testing.T) {
	exploration(t)
	measured := baseline(t, 456, Plan{Devices: 2, FoundingFault: &Fault{}})
	counts := countsBetween(t, measured, "founding-start", "founding-result")
	methods := make([]string, 0, len(counts))
	for method := range counts {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, method := range methods {
		for at := 1; at <= counts[method]; at++ {
			modes := []string{"before", "cancel", "crash-before"}
			if method == "publish" {
				modes = append(modes, "after", "crash-after")
			}
			for _, mode := range modes {
				t.Run(fmt.Sprintf("%s-%d-%s", method, at, mode), func(t *testing.T) {
					shardCase(t)
					exercise(t, 456, Plan{Devices: 2, FoundingFault: &Fault{method, at, mode}})
				})
			}
		}
	}
}

package simulation

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

// enbu.toml names a genesis only once its publish was confirmed. A retry after
// a lost reply finds the genesis this device signed and adopts it.
func TestFoundingRetriesExactControlAfterLostReply(t *testing.T) {
	for _, mode := range []string{"before", "after", "crash-before", "crash-after"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			tape := NewTape(123, "")
			w, e := NewWorld(t.TempDir(), tape, 2)
			if e != nil {
				t.Fatal(e)
			}
			d := w.Devices[0]
			d.Store.Arm(Fault{"publish", 1, mode})
			if e := catchCrash(func() error { _, err := d.App.InitializeRepository(ctx); return err }); e == nil {
				t.Fatal("fault not returned")
			}
			d.Store.Arm(Fault{})
			published, e := d.Store.Discover(ctx, storage.KindControl, "")
			if e != nil {
				t.Fatal(e)
			}
			committed := mode == "after" || mode == "crash-after"
			if committed != (len(published) == 1) || len(published) > 1 {
				t.Fatalf("published controls %v", published)
			}
			cfg, e := config.LoadProjectFrom(d.App.RepositoryDir)
			if e != nil {
				t.Fatal(e)
			}
			if cfg.ControlGenesis != "" {
				t.Fatal("enbu.toml names a genesis whose publish was not confirmed")
			}
			w.Restart(0)
			d = w.Devices[0]
			r, e := d.App.InitializeRepository(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !r.Founded || committed && r.ControlGenesis != string(published[0]) {
				t.Fatalf("retry did not adopt the published genesis: %+v", r)
			}
			if after, e := d.Store.Discover(ctx, storage.KindControl, ""); e != nil || len(after) != 1 {
				t.Fatalf("retry published another genesis: %v %v", after, e)
			}
			if e := d.App.AddSecret(ctx, "default", "AFTER", "ok"); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestFoundingEveryStorageBoundaryRecovers(t *testing.T) {
	exploration(t)
	baseline := exercise(t, 456, Plan{Devices: 2, FoundingFault: &Fault{}})
	counts := countsBetween(t, baseline, "founding-start", "founding-result")
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
				t.Run(fmt.Sprintf("%s-%d-%s", method, at, mode), func(t *testing.T) { exercise(t, 456, Plan{Devices: 2, FoundingFault: &Fault{method, at, mode}}) })
			}
		}
	}
}

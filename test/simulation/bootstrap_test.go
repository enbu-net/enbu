package simulation

import (
	"context"
	"github.com/enbu-net/enbu/pkg/config"
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

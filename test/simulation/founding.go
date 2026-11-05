package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// FoundingProbe includes the reads after publication and trust acceptance, not
// only the first Publish. This is where a lost response can strand a founder.
func (w *World) FoundingProbe(ctx context.Context, fault Fault) (map[string]int, error) {
	ctx = wsp.WithSerialHeadReads(ctx)
	d := w.Devices[0]
	d.Store.Arm(fault)
	initial := catchCrash(func() error { _, err := d.App.InitializeRepository(ctx); return err })
	counts := map[string]int{}
	for method, n := range d.Store.calls {
		counts[method] = n
	}
	if err := w.Tape.Observe("founding-result", fault, ErrorCode(initial)); err != nil {
		return nil, err
	}
	if fault.Method == "" && initial != nil {
		return nil, fmt.Errorf("baseline founding: %w", initial)
	}
	if fault.Method != "" && counts[fault.Method] < fault.At {
		return nil, fmt.Errorf("unreached founding fault: %+v", fault)
	}
	before, err := config.LoadProjectFrom(d.App.RepositoryDir)
	if err != nil {
		return nil, err
	}
	d.Store.Arm(Fault{})
	w.Restart(0)
	d = w.Devices[0]
	result, err := d.App.InitializeRepository(ctx)
	if err != nil {
		return nil, fmt.Errorf("founding recovery: %w", err)
	}
	if result.WorkspaceID != before.WorkspaceID || result.ControlGenesis == "" {
		return nil, fmt.Errorf("founding recovery replaced the workspace")
	}
	if before.ControlGenesis != "" && result.ControlGenesis != before.ControlGenesis {
		return nil, fmt.Errorf("founding recovery replaced the genesis")
	}
	if err := w.Tape.Observe("founding-recovery", nil, result); err != nil {
		return nil, err
	}
	if err := d.App.AddSecret(ctx, "default", "AFTER", "kept"); err != nil {
		return nil, err
	}
	got, err := d.App.ListSecrets(ctx, "default")
	if err != nil {
		return nil, err
	}
	if len(got) != 1 || got["AFTER"] != "kept" {
		return nil, fmt.Errorf("recovered workspace cannot preserve a write")
	}
	if err := w.Tape.Observe("founding-secrets", nil, got); err != nil {
		return nil, err
	}
	return counts, nil
}

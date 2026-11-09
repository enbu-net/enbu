package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

type AcceptanceCase struct {
	AfterReadmission bool
	Restart          bool
	Admin            bool
}

// changeFixtureControl deliberately isolates the trust rule from the
// application's re-encryption on removal. Otherwise its takeover masks whether
// a removed author's unmerged head is still read.
func (w *World) changeFixtureControl(ctx context.Context, mutate func(*wsp.Control) error) (*wsp.Verified, error) {
	d := w.Devices[0]
	cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
	if err != nil {
		return nil, err
	}
	view, err := wsp.LoadControl(ctx, d.Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return nil, err
	}
	if mutate == nil {
		return view.Head()
	}
	signer, err := d.Keys.Signer(cfg.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = signer.Close() }()
	head, err := wsp.UpdateControl(ctx, d.Store, view, signer, mutate)
	if err != nil {
		return nil, err
	}
	if err := w.Tape.Observe("fixture-control-epoch", nil, head.Digest); err != nil {
		return nil, err
	}
	return head, nil
}

func (w *World) AcceptanceCase(ctx context.Context, c AcceptanceCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	root, err := w.publishMergeNode(ctx, 0, map[string]string{"BASE": "kept"})
	if err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"BASE": "kept"}
	if err := w.Devices[0].App.CreateEnvironment("prod"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := w.Devices[0].App.AddSecret(ctx, "prod", "SENTINEL", "unchanged"); err != nil {
		return err
	}
	w.Model["prod"] = map[string]string{"SENTINEL": "unchanged"}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "prod"); err != nil {
		return err
	}
	old, err := w.changeFixtureControl(ctx, nil)
	if err != nil {
		return err
	}
	observer, ok := old.Principal(signing.DeviceID(w.Devices[1].ID))
	if !ok {
		return fmt.Errorf("observer missing from bootstrap")
	}
	observer.Admin = c.Admin
	if c.Admin {
		old, err = w.changeFixtureControl(ctx, func(next *wsp.Control) error {
			for i := range next.Principals {
				if next.Principals[i].ID == observer.ID {
					next.Principals[i].Admin = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	values := map[string]string{"BASE": "kept", "AUTHOR": "accepted value"}
	if _, err := w.publishNodeAtControl(ctx, 2, old.Digest, values, root.Rev); err != nil {
		return err
	}
	checkObserver := func(want map[string]string) error {
		got, err := w.Devices[1].App.ListSecrets(ctx, "default")
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			return &Violation{Kind: "acceptance", Detail: fmt.Errorf("case %+v got %v want %v", c, got, want)}
		}
		return w.Tape.Observe("observer-accepted", c, got)
	}
	if !c.AfterReadmission {
		if err := checkObserver(values); err != nil {
			return err
		}
	}
	remove := func(id string) func(*wsp.Control) error {
		return func(next *wsp.Control) error {
			kept := next.Principals[:0:0]
			for _, p := range next.Principals {
				if string(p.ID) != id {
					kept = append(kept, p)
				}
			}
			next.Principals = kept
			return nil
		}
	}
	if _, err := w.changeFixtureControl(ctx, remove(w.Devices[1].ID)); err != nil {
		return err
	}
	if _, err := w.Devices[1].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("removed observer read: %v", err)
	}
	if err := requireCode(w.Devices[1].App.AddSecret(ctx, "prod", "DENIED", "x"), apperr.CodeNotMember); err != nil {
		return err
	}
	if _, err := w.changeFixtureControl(ctx, func(next *wsp.Control) error { next.Principals = append(next.Principals, observer); return nil }); err != nil {
		return err
	}
	if c.AfterReadmission {
		if err := checkObserver(values); err != nil {
			return err
		}
	}
	if c.Restart {
		w.Restart(1)
	}
	if _, err := w.changeFixtureControl(ctx, remove(w.Devices[2].ID)); err != nil {
		return err
	}
	if _, err := w.Devices[2].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("removed author read: %v", err)
	}
	// This fixture deliberately bypasses removal's re-encryption. The author's
	// unmerged head is now untrusted, but the observer already accepted its
	// generation. Returning the older root would violate F2b's fail-closed
	// freshness rule; neither a read nor sync may lower that checkpoint.
	checkRollback := func() error {
		got, err := w.Devices[1].App.ListSecrets(ctx, "default")
		if err := requireCode(err, apperr.CodeRollback); err != nil {
			return fmt.Errorf("removed author's accepted generation did not stop the observer: %w", err)
		}
		if got != nil {
			return fmt.Errorf("rollback returned partial secrets: %v", got)
		}
		return nil
	}
	if err := checkRollback(); err != nil {
		return err
	}
	if err := requireCode(w.Devices[1].App.SyncSecrets(ctx, "default"), apperr.CodeRollback); err != nil {
		return fmt.Errorf("sync bypassed the accepted generation: %w", err)
	}
	if c.Restart {
		w.Restart(1)
		if err := checkRollback(); err != nil {
			return fmt.Errorf("restart lost the accepted generation: %w", err)
		}
	}
	// An explicit new publication by a current member can establish freshness
	// again. This is a fixture-authorized value, not automatic recovery of the
	// removed author's branch or a checkpoint reset. Keep checking below that
	// readmission alone never revives the old content.
	want := map[string]string{"BASE": "kept"}
	if _, err := w.publishMergeNode(ctx, 0, want, root.Rev); err != nil {
		return err
	}
	if err := checkObserver(want); err != nil {
		return err
	}
	if err := w.Devices[1].App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	w.Model["default"] = clone(want)
	// Re-admitting the author must not revive its old branch. Fresh author
	// writes must still work.
	if _, err := w.Devices[2].App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
		return err
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[2].ID); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "prod"); err != nil {
		return err
	}
	if err := w.Devices[2].App.AddSecret(ctx, "default", "FRESH", "new epoch"); err != nil {
		return err
	}
	w.Model["default"]["FRESH"] = "new epoch"
	if _, err := w.Devices[0].App.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Check(ctx, "prod"); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}

package simulation

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

type CompactionRaceCase struct {
	Publication string
	Fault       string
}

// CompactionRace publishes between the compactor's verified read and its own
// listing. A transient fetch failure is not evidence that an object is junk.
func (w *World) CompactionRace(ctx context.Context, c CompactionRaceCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	switch c.Publication {
	case "valid", "junk", "missing", "corrupt", "offline", "cancelled":
	default:
		return fmt.Errorf("invalid compaction publication %q", c.Publication)
	}
	switch c.Fault {
	case "", "before", "after", "cancel", "crash-before", "crash-after":
	default:
		return fmt.Errorf("invalid compaction fault %q", c.Fault)
	}
	first, err := w.publishMergeNode(ctx, 0, map[string]string{"K": "old"})
	if err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"K": "old"}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	// Device 2 goes offline with a checkpoint below the eventual floor.
	middle, err := w.publishMergeNode(ctx, 1, map[string]string{"K": "middle"}, first.Rev)
	if err != nil {
		return err
	}
	latest, err := w.publishMergeNode(ctx, 1, map[string]string{"K": "current"}, middle.Rev)
	if err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"K": "current"}
	lateValues := map[string]string{"K": "current", "LATE": "retained"}
	late, err := w.publishMergeNode(ctx, 1, lateValues, latest.Rev)
	if err != nil {
		return err
	}
	// Prepare signed bytes without exposing them to the compactor's read.
	if err := w.Devices[1].Store.Delete(ctx, late.Kind, late.Scope, late.Rev); err != nil {
		return err
	}
	if c.Publication == "junk" {
		late = storagetest.Object(storage.KindState, latest.Scope, "invalid-signature", "junk")
	}
	d := w.Devices[0]
	real := d.Store.Store
	defer func() { d.Store.Store = real; d.Store.Arm(Fault{}) }()
	listings, fetches := 0, 0
	d.Store.Store = storagetest.Wrap(real, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState && scope == late.Scope {
				listings++
				if listings == 2 {
					if err := next.Publish(ctx, late); err != nil {
						return nil, err
					}
					if err := w.Tape.Observe("late-compaction-publication", c.Publication, late); err != nil {
						return nil, err
					}
				}
			}
			return next.Discover(ctx, kind, scope)
		},
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if kind == storage.KindState && scope == late.Scope && rev == late.Rev {
				fetches++
				if c.Publication == "missing" {
					return nil, storage.ErrNotFound
				}
				if c.Publication == "corrupt" {
					return nil, storage.ErrCorrupt
				}
				if c.Publication == "offline" {
					return nil, ErrOffline
				}
				if c.Publication == "cancelled" {
					return nil, context.Canceled
				}
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
	})
	d.Store.Arm(Fault{})
	if c.Fault != "" {
		d.Store.Arm(Fault{Method: "delete", At: 1, Mode: c.Fault})
	}
	err = catchCrash(func() error {
		result, err := d.App.CompactHistory(ctx, "default", 1)
		return w.Observe("compact-late", c, result, err)
	})
	if listings != 2 || fetches != 1 {
		return fmt.Errorf("late publication not examined: listings=%d fetches=%d", listings, fetches)
	}
	terminal := c.Publication == "offline" || c.Publication == "cancelled"
	if terminal {
		want := ErrOffline
		if c.Publication == "cancelled" {
			want = context.Canceled
		}
		if !errors.Is(err, want) || d.Store.calls["delete"] != 0 {
			return fmt.Errorf("terminal fetch was ignored or deletion began: %v deletes=%d", err, d.Store.calls["delete"])
		}
	} else if c.Fault == "" && err != nil {
		return err
	}
	if c.Fault != "" && (err == nil || d.Store.faultHits != 1) {
		return fmt.Errorf("compaction fault not reached: %v hits=%d", err, d.Store.faultHits)
	}
	d.Store.Store = real
	d.Store.Arm(Fault{})
	left, err := d.Store.Discover(ctx, storage.KindState, late.Scope)
	if err != nil {
		return err
	}
	if c.Publication != "junk" && !slices.Contains(left, late.Rev) {
		return fmt.Errorf("compaction deleted late or temporarily unreadable revision")
	}
	if c.Fault == "" && c.Publication == "junk" && slices.Contains(left, late.Rev) {
		return fmt.Errorf("compaction retained invalid publication")
	}
	if c.Publication != "junk" {
		w.Model["default"] = lateValues
	}
	// Restart everyone, including the observer with the old checkpoint, before
	// retrying. Signed records must make partially completed deletion readable.
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if _, err := w.Devices[0].App.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	if err := w.Devices[2].App.AddSecret(ctx, "default", "RECOVERED", "yes"); err != nil {
		return err
	}
	w.Model["default"]["RECOVERED"] = "yes"
	return w.Check(ctx, "default")
}

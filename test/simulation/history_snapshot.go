package simulation

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func (w *World) HistorySnapshot(ctx context.Context, operation, change string, cold bool) error {
	if operation != "list" && operation != "diff" {
		return fmt.Errorf("invalid history snapshot operation %q", operation)
	}
	switch change {
	case "edit", "remove", "upgrade", "compact":
	default:
		return fmt.Errorf("invalid history snapshot change %q", change)
	}
	reader := w.Devices[1]
	admin := w.Devices[0].App
	advance := func(boundary string) error {
		w.timeline.Advance(time.Second)
		return w.Tape.Observe("history-time-step", boundary, 1)
	}
	cfg, err := config.LoadProjectFrom(admin.RepositoryDir)
	if err != nil {
		return err
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	initial, err := w.Devices[0].Store.Discover(ctx, storage.KindState, scope)
	if err != nil || len(initial) != 1 {
		return fmt.Errorf("history snapshot requires one initial revision: count=%d error=%v", len(initial), err)
	}
	if err := advance("first-fixture"); err != nil {
		return err
	}
	first, err := w.publishMergeNode(ctx, 0, map[string]string{"BASE": "old-a", "TOKEN": "old-b", "REMOVE_ME": "old"}, initial[0])
	if err != nil {
		return err
	}
	before := map[string]string{"BASE": "frozen-a", "TOKEN": "frozen-b", "ADDED": "before"}
	if err := advance("second-fixture"); err != nil {
		return err
	}
	second, err := w.publishMergeNode(ctx, 0, before, first.Rev)
	if err != nil {
		return err
	}
	w.Model["default"] = before
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if cold {
		if err := os.RemoveAll(reader.App.CacheDir); err != nil {
			return err
		}
	} else if _, err := reader.App.ListHistory(ctx, "default"); err != nil {
		return err
	}
	// These tags come from fixture publications, not ListHistory's output.
	oldTags := []string{initial[0].Encoded(), first.Rev.Encoded(), second.Rev.Encoded()}
	after := map[string]string{"BASE": "peer-a", "TOKEN": "peer-b", "ADDED": "before", "LATE": "peer"}
	base := reader.Store.Store
	fired := false
	var peerErr error
	var added digest.Digest
	reader.Store.Store = storagetest.Wrap(base, storagetest.Hooks{Discover: func(c context.Context, next storage.Store, kind storage.Kind, resource string) ([]digest.Digest, error) {
		refs, err := next.Discover(c, kind, resource)
		if err != nil || fired || kind != storage.KindState || resource != scope {
			return refs, err
		}
		fired = true
		if peerErr = advance("peer-update"); peerErr != nil {
			return refs, nil
		}
		_, peerErr = admin.ImportSecrets(ctx, "default", after, true)
		if peerErr != nil {
			return refs, nil
		}
		latest, err := w.Devices[0].Store.Discover(ctx, kind, resource)
		if err != nil {
			peerErr = err
			return refs, nil
		}
		for _, rev := range latest {
			if !slices.Contains(refs, rev) {
				if added != "" {
					peerErr = fmt.Errorf("peer update published multiple secret revisions")
					return refs, nil
				}
				added = rev
			}
		}
		if peerErr = advance("team-change"); peerErr != nil {
			return refs, nil
		}
		switch change {
		case "remove":
			peerErr = admin.RemoveMember(ctx, reader.ID)
		case "upgrade":
			siblingStore := &Store{Store: base, Tape: w.Tape, Device: 1, advance: reader.Store.advance}
			sibling := w.newApp(1, len(w.Devices), reader.Keys, siblingStore)
			_, peerErr = sibling.UpgradeIdentity(ctx)
			if peerErr == nil {
				peerErr = admin.ApproveMember(ctx, reader.ID)
			}
		case "compact":
			_, peerErr = admin.CompactHistory(ctx, "default", 1)
		}
		return refs, nil
	}})
	var history []app.HistoryEntry
	var diff *app.Diff
	if operation == "list" {
		history, err = reader.App.ListHistory(ctx, "default")
	} else {
		diff, err = reader.App.DiffHistory(ctx, "default", 2, 3)
	}
	reader.Store.Store = base
	if !fired || peerErr != nil || added == "" {
		return fmt.Errorf("history boundary was not exercised: fired=%t peer=%v", fired, peerErr)
	}
	w.Model["default"] = after
	tags := func(entries []app.HistoryEntry) ([]string, error) {
		out := make([]string, 0, len(entries))
		for i, entry := range entries {
			if entry.Index != i+1 {
				return nil, fmt.Errorf("history indices do not match the returned snapshot")
			}
			out = append(out, entry.Tag)
		}
		return out, nil
	}
	if err != nil {
		// Compaction may reclaim an uncached input before it is read. It
		// must cause a safe failure, never a silently mixed diff/history.
		if change != "compact" || !apperr.Is(err, apperr.CodeRollback) && !apperr.Is(err, apperr.CodeInvalidArgument) {
			return fmt.Errorf("in-flight history operation failed unexpectedly: %w", err)
		}
		if history != nil || diff != nil {
			return fmt.Errorf("failed history operation returned partial output")
		}
	} else if operation == "list" {
		got, tagErr := tags(history)
		if tagErr != nil || !reflect.DeepEqual(got, oldTags) && (change != "compact" || !reflect.DeepEqual(got, []string{added.Encoded()})) {
			return fmt.Errorf("history mixed captured and later revisions: tags=%v error=%v", got, tagErr)
		}
	} else {
		want := &app.Diff{Added: []string{"ADDED"}, Removed: []string{"REMOVE_ME"}, Modified: []string{"BASE", "TOKEN"}}
		if !reflect.DeepEqual(diff, want) {
			return fmt.Errorf("diff mixed captured and later states: got=%+v want=%+v", diff, want)
		}
	}
	var readmission digest.Digest
	if change == "remove" {
		if got, err := reader.App.ListHistory(ctx, "default"); !apperr.Is(err, apperr.CodeNotMember) || got != nil {
			return fmt.Errorf("revoked member started a new history read: %v", err)
		}
		if got, err := reader.App.DiffHistory(ctx, "default", 1, 2); !apperr.Is(err, apperr.CodeNotMember) || got != nil {
			return fmt.Errorf("revoked member started a new diff: %v", err)
		}
		if _, err := reader.App.InitializeRepository(ctx); err != nil {
			return err
		}
		previous, err := w.Devices[0].Store.Discover(ctx, storage.KindState, scope)
		if err != nil {
			return err
		}
		if err := advance("readmission"); err != nil {
			return err
		}
		if err := admin.ApproveMember(ctx, reader.ID); err != nil {
			return err
		}
		current, err := w.Devices[0].Store.Discover(ctx, storage.KindState, scope)
		if err != nil {
			return err
		}
		for _, rev := range current {
			if !slices.Contains(previous, rev) {
				if readmission != "" {
					return fmt.Errorf("readmission published multiple secret revisions")
				}
				readmission = rev
			}
		}
		if readmission == "" {
			return fmt.Errorf("readmission did not re-encrypt for the returning device")
		}
	}
	w.Restart(1)
	fresh, err := w.Devices[1].App.ListHistory(ctx, "default")
	if err != nil {
		return err
	}
	wantTags := append(slices.Clone(oldTags), added.Encoded())
	if readmission != "" {
		// The intervening parent is unreadable to the returning device, so
		// it cannot prove this revision only re-encrypts unchanged content.
		wantTags = append(wantTags, readmission.Encoded())
	}
	if change == "compact" {
		wantTags = []string{added.Encoded()}
	}
	gotTags, err := tags(fresh)
	if err != nil || !reflect.DeepEqual(gotTags, wantTags) {
		return fmt.Errorf("fresh history did not recover the peer's complete update: got=%v want=%v error=%v", gotTags, wantTags, err)
	}
	return w.Check(ctx, "default")
}

package simulation

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

var metadataFloodCases = []string{"control-count", "state-count", "compaction-count", "control-duplicate", "state-duplicate"}

func (w *World) MetadataFlood(ctx context.Context, mode string) error {
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	a := w.Devices[0].App
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	kind := storage.KindControl
	count := 10001
	switch mode {
	case "control-count", "control-duplicate":
	case "state-count", "state-duplicate":
		kind = storage.KindState
		count = 20001
	case "compaction-count":
		kind = storage.KindCompaction
		count = 1001
	default:
		return fmt.Errorf("unknown metadata flood %q", mode)
	}
	duplicate := mode == "control-duplicate" || mode == "state-duplicate"
	var injected *storage.Object
	if duplicate {
		objectScope := ""
		if kind == storage.KindState {
			objectScope = scope
		}
		object := storagetest.Object(kind, objectScope, "malformed metadata", "")
		if kind == storage.KindState {
			object.Payload = []byte("must-not-decrypt")
		}
		if err := w.Devices[0].Store.Publish(ctx, object); err != nil {
			return err
		}
		injected = &object
	} else if mode == "compaction-count" {
		// A valid, unaccepted root without the accepted ancestor forces the reader
		// to inspect deletion excuses. None of the flood's records may be trusted.
		object, err := w.publishNodeAtControl(ctx, 0, "", clone(w.Model["default"]))
		if err != nil {
			return err
		}
		injected = &object
	}
	var refs []digest.Digest
	if !duplicate {
		for i := 0; i < count; i++ {
			refs = append(refs, digest.FromString(fmt.Sprintf("%s-garbage-%d", mode, i)))
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	}
	headReads := map[storage.Kind]int{}
	badReads, badBlobs, writes, deletes, blobs := 0, 0, 0, 0, 0
	base := w.Devices[0].Store.Store
	attack := storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, k storage.Kind, s string) ([]digest.Digest, error) {
			if mode == "compaction-count" && k == storage.KindState && s == scope {
				return []digest.Digest{injected.Rev}, nil
			}
			if k == kind && (k == storage.KindControl || s == scope) {
				if duplicate {
					found, err := next.Discover(ctx, k, s)
					if err != nil {
						return nil, err
					}
					for range 8 {
						found = append(found, injected.Rev)
					}
					return found, nil
				}
				return refs, nil
			}
			return next.Discover(ctx, k, s)
		},
		FetchHead: func(ctx context.Context, next storage.Store, k storage.Kind, s string, rev digest.Digest) ([]byte, error) {
			headReads[k]++
			if duplicate && rev == injected.Rev {
				badReads++
				if kind == storage.KindControl {
					// A digest-valid malformed header is cached by the App. A
					// corrupt response cannot be cached, so repeated external
					// reads expose a missing protocol-level deduplication guard.
					return nil, storage.ErrCorrupt
				}
			}
			return next.FetchHead(ctx, k, s, rev)
		},
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			writes++
			return next.Publish(ctx, o)
		},
		Delete: func(ctx context.Context, next storage.Store, k storage.Kind, s string, rev digest.Digest) error {
			deletes++
			return next.Delete(ctx, k, s, rev)
		},
		OpenPayload: func(ctx context.Context, next storage.Store, k storage.Kind, s string, rev digest.Digest) (io.ReadCloser, error) {
			blobs++
			if duplicate && rev == injected.Rev {
				badBlobs++
			}
			return next.OpenPayload(ctx, k, s, rev)
		},
	})
	for _, d := range w.Devices {
		d.Store.Store = attack
	}
	path := filepath.Join(a.RepositoryDir, ".env")
	local := []byte("LOCAL_ONLY=personal\nBASE=before-metadata-flood\n")
	if err := os.WriteFile(path, local, 0600); err != nil {
		return err
	}
	if duplicate {
		got, err := a.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(got, w.Model["default"]) {
			return fmt.Errorf("duplicate invalid refs changed accepted data: %v", err)
		}
		if badReads != 1 || badBlobs != 0 {
			return fmt.Errorf("duplicate metadata reads=%d, ciphertext opens=%d", badReads, badBlobs)
		}
	} else {
		for _, op := range []struct {
			name string
			run  func() error
		}{
			{"read", func() error { _, err := a.ListSecrets(ctx, "default"); return err }},
			{"edit", func() error { return a.EditSecret(ctx, "default", "BASE", "must-not-commit") }},
			{"pull", func() error { return a.PullSecretsToFile(ctx, "default") }},
			{"sync", func() error { return a.SyncSecrets(ctx, "default") }},
			{"compact", func() error { _, err := a.CompactHistory(ctx, "default", 1); return err }},
		} {
			err := op.run()
			if check := requireCode(err, apperr.CodeUntrusted); check != nil {
				return fmt.Errorf("%s flood %s: %w", mode, op.name, check)
			}
			if err := w.Tape.Observe("metadata-flood-denial", []string{mode, op.name}, ErrorCode(err)); err != nil {
				return err
			}
			if headReads[kind] != 0 || writes != 0 || deletes != 0 || blobs != 0 {
				return fmt.Errorf("oversized %s work: heads=%d writes=%d deletes=%d blobs=%d", mode, headReads[kind], writes, deletes, blobs)
			}
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(got) != string(local) {
		return fmt.Errorf("metadata flood modified local secrets")
	}
	for _, d := range w.Devices {
		d.Store.Store = base
	}
	if injected != nil {
		if err := w.Devices[0].Store.Delete(ctx, injected.Kind, injected.Scope, injected.Rev); err != nil {
			return err
		}
	}
	after, err := a.ListMembers(ctx)
	if err != nil || !reflect.DeepEqual(members, after) {
		return fmt.Errorf("metadata flood changed membership: %v", err)
	}
	if err := w.Devices[1].App.EditSecret(ctx, "default", "BASE", "teammate-after-metadata-flood"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "teammate-after-metadata-flood"
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Devices[0].App.PullSecretsToFile(ctx, "default"); err != nil {
		return err
	}
	expected := clone(w.Model["default"])
	expected["LOCAL_ONLY"] = "personal"
	return w.checkOutput("metadata-flood-recovery", path, expected)
}

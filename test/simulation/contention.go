package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

var contentionOperations = []string{"add", "edit", "delete", "import", "sync"}

// Contention forces real teammate commits between each read and its final head
// recheck. Scheduling is by call position, never goroutine timing or wall time.
func (w *World) Contention(ctx context.Context, mode string) error {
	op, outcome, ok := strings.Cut(mode, "-")
	if !ok || outcome != "exhausted" && outcome != "yield" {
		return fmt.Errorf("unknown contention case %q", mode)
	}
	a := w.Devices[0].App
	apply := func() error {
		switch op {
		case "add":
			return a.AddSecret(ctx, "default", "OWN", "accepted")
		case "edit":
			return a.EditSecret(ctx, "default", "BASE", "accepted")
		case "delete":
			return a.DeleteSecret(ctx, "default", "BASE")
		case "import":
			_, err := a.ImportSecrets(ctx, "default", map[string]string{"BASE": "accepted", "OWN": "accepted"}, true)
			return err
		case "sync":
			return a.SyncSecrets(ctx, "default")
		default:
			return fmt.Errorf("unknown contention operation %q", op)
		}
	}
	accept := func() {
		switch op {
		case "add":
			w.Model["default"]["OWN"] = "accepted"
		case "edit":
			w.Model["default"]["BASE"] = "accepted"
		case "delete":
			delete(w.Model["default"], "BASE")
		case "import":
			w.Model["default"]["BASE"] = "accepted"
			w.Model["default"]["OWN"] = "accepted"
		}
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	scope := storage.StateScope(cfg.WorkspaceID, cfg.Resource("default"))
	path := filepath.Join(a.RepositoryDir, ".env")
	local := "LOCAL_ONLY=personal\nBASE=before-contention\n"
	if err := os.WriteFile(path, []byte(local), 0600); err != nil {
		return err
	}
	limit := 3
	if op == "sync" {
		limit = 5
	}
	interferences := limit
	if outcome == "yield" {
		interferences = limit - 1
	}
	reads, commits, ownWrites := 0, 0, 0
	base := w.Devices[0].Store.Store
	w.Devices[0].Store.Store = storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, s string) ([]digest.Digest, error) {
			if kind == storage.KindState && s == scope {
				reads++
				// Bound the harness too: a broken infinite retry loop must fail
				// deterministically without waiting for the test timeout.
				if reads > 2*limit+2 {
					return nil, fmt.Errorf("contention read budget exceeded")
				}
				if reads%2 == 0 && commits < interferences {
					peer := 1 + commits%(len(w.Devices)-1)
					key := fmt.Sprintf("PEER_%d", commits)
					value := fmt.Sprintf("device-%d-acknowledged", peer)
					if err := w.Devices[peer].App.AddSecret(ctx, "default", key, value); err != nil {
						return nil, err
					}
					w.Model["default"][key] = value
					commits++
				}
			}
			return next.Discover(ctx, kind, s)
		},
		Publish: func(ctx context.Context, next storage.Store, object storage.Object) error {
			ownWrites++
			return next.Publish(ctx, object)
		},
	})
	err = apply()
	w.Devices[0].Store.Store = base
	if record := w.Tape.Observe("contention-attempt", mode, []any{reads, commits, ownWrites, ErrorCode(err)}); record != nil {
		return record
	}
	if commits != interferences {
		return fmt.Errorf("contention exercised %d teammate commits, want %d", commits, interferences)
	}
	if outcome == "exhausted" {
		if err := requireCode(err, apperr.CodeConflict); err != nil {
			return err
		}
		if reads != 2*limit || ownWrites != 0 {
			return fmt.Errorf("exhaustion must stop before publishing: reads=%d writes=%d", reads, ownWrites)
		}
		if err := w.Check(ctx, "default"); err != nil {
			return fmt.Errorf("failed operation changed accepted state: %w", err)
		}
		if err := apply(); err != nil {
			return fmt.Errorf("writer could not recover after contention stopped: %w", err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("writer did not progress when peers yielded: %w", err)
		}
		if ownWrites != 1 {
			return fmt.Errorf("successful retry published %d revisions, want one", ownWrites)
		}
	}
	accept()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != local {
		return fmt.Errorf("contention modified local dotenv: %v", err)
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Devices[1].App.AddSecret(ctx, "default", "AFTER_CONTENTION", "team-progress"); err != nil {
		return err
	}
	w.Model["default"]["AFTER_CONTENTION"] = "team-progress"
	return w.Check(ctx, "default")
}

package simulation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func (w *World) OutputBoundary(ctx context.Context, kind string) error {
	for _, replace := range []bool{false, true} {
		// Identity upgrade is a one-time transition. Use separate worlds for
		// the two local-variable policies rather than upgrading it twice.
		if strings.HasPrefix(kind, "upgraded-") && replace != (kind == "upgraded-replace-hardlink") {
			continue
		}
		a := w.Devices[1].App
		before := map[string]string{"BASE": "old-private-a", "TOKEN": "old-private-b"}
		after := map[string]string{"BASE": "new-private-a", "TOKEN": "new-private-b"}
		if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", before, true); err != nil {
			return err
		}
		w.Model["default"] = before
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		path := filepath.Join(a.RepositoryDir, ".env")
		target := filepath.Join(w.Root, fmt.Sprintf("unrelated-%t.env", replace))
		original := []byte("LOCAL_ONLY=personal\n")
		if err := os.WriteFile(target, original, 0o644); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if kind == "public" {
			if err := os.WriteFile(path, original, 0o644); err != nil {
				return err
			}
		} else if err := os.Link(target, path); err != nil {
			return err
		}
		if err := os.RemoveAll(a.CacheDir); err != nil {
			return err
		}
		callCtx, cancel := context.WithCancel(ctx)
		store := w.Devices[1].Store
		base := store.Store
		fired := false
		var peerErr error
		store.Store = storagetest.Wrap(base, storagetest.Hooks{OpenBlob: func(c context.Context, next storage.Store, k storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
			r, err := next.OpenBlob(c, k, scope, rev, index)
			if err != nil || fired || k != storage.KindState {
				return r, err
			}
			fired = true
			_, peerErr = w.Devices[0].App.ImportSecrets(ctx, "default", after, true)
			if peerErr == nil {
				switch kind {
				case "removed-hardlink":
					peerErr = w.Devices[0].App.RemoveMember(ctx, w.Devices[1].ID)
				case "upgraded-preserve-hardlink", "upgraded-replace-hardlink":
					// A second client of this identity has its own storage-call
					// lock; the export is paused inside its client's OpenBlob.
					siblingStore := &Store{Store: base, Tape: w.Tape, Device: 1, advance: store.advance}
					sibling := w.newApp(1, len(w.Devices), w.Devices[1].Keys, siblingStore)
					_, peerErr = sibling.UpgradeIdentity(ctx)
					if peerErr == nil {
						peerErr = w.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID)
					}
				}
			}
			if kind == "canceled-hardlink" {
				cancel()
			}
			return r, nil
		}})
		written, pullErr := a.PullSecretsToFileWith(callCtx, "default", replace)
		store.Store = base
		cancel()
		if !fired || peerErr != nil {
			return fmt.Errorf("team output boundary not reached: fired=%t peer=%v", fired, peerErr)
		}
		w.Model["default"] = after
		got, err := os.ReadFile(target)
		if err != nil || string(got) != string(original) {
			return fmt.Errorf("pull modified an unrelated linked file: %v", err)
		}
		if kind == "canceled-hardlink" {
			if !errors.Is(pullErr, context.Canceled) || written != nil {
				return fmt.Errorf("canceled pull acknowledged output: %v", pullErr)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != string(original) {
				return fmt.Errorf("canceled output lost local data: %v", err)
			}
			if _, err := a.PullSecretsToFileWith(ctx, "default", replace); err != nil {
				return err
			}
			before = after // A fresh request must see the peer's complete update.
		} else if pullErr != nil {
			return pullErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return fmt.Errorf("output contains a non-assignment")
			}
			if _, duplicate := values[key]; duplicate {
				return fmt.Errorf("output repeats a key")
			}
			values[key] = strings.Trim(value, "\"")
		}
		want := map[string]string{"BASE": before["BASE"], "TOKEN": before["TOKEN"]}
		if !replace {
			want["LOCAL_ONLY"] = "personal"
		}
		if !reflect.DeepEqual(values, want) {
			return fmt.Errorf("export mixed snapshots or local variables: got=%v want=%v", values, want)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("pull left an unsafe output entry: %v %v", info, err)
		}
		got, err = os.ReadFile(target)
		if err != nil || string(got) != string(original) {
			return fmt.Errorf("recovery modified an unrelated file: %v", err)
		}
		entries, err := os.ReadDir(a.RepositoryDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".enbu-output-") {
				return fmt.Errorf("completed pull retained a plaintext temporary file")
			}
		}
		if kind == "removed-hardlink" {
			for _, run := range []func() error{
				func() error { _, err := a.ListSecrets(ctx, "default"); return err },
				func() error { return a.PullSecretsToFile(ctx, "default") },
				func() error { return a.SyncSecrets(ctx, "default") },
			} {
				if err := requireCode(run(), apperr.CodeNotMember); err != nil {
					return fmt.Errorf("revoked reader began another export: %w", err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !reflect.DeepEqual(got, data) {
					return fmt.Errorf("denied export changed the local snapshot: %v", err)
				}
			}
			if _, err := a.InitializeRepository(ctx, app.InitOptions{}); err != nil {
				return err
			}
			if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID); err != nil {
				return err
			}
		}
		w.Restart(1)
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		if _, exists := w.Model["default"]["LOCAL_ONLY"]; exists {
			return fmt.Errorf("local plaintext was published to team storage")
		}
	}
	return nil
}

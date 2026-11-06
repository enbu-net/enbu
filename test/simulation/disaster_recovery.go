package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

type recoveryFile struct {
	data []byte
	mode fs.FileMode
}

type recoveryDevice struct {
	files map[string]recoveryFile
	keys  map[string]*keyMaterial
}

func copyRecoveryKeys(src map[string]*keyMaterial) map[string]*keyMaterial {
	out := make(map[string]*keyMaterial, len(src))
	for name, material := range src {
		copy := *material
		copy.signing = bytes.Clone(material.signing)
		out[name] = &copy
	}
	return out
}

func backupRecoveryDevice(d *Device) (recoveryDevice, error) {
	out := recoveryDevice{files: map[string]recoveryFile{}, keys: copyRecoveryKeys(d.Keys.workspaces)}
	err := filepath.WalkDir(d.App.RepositoryDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected nonregular recovery fixture")
		}
		rel, err := filepath.Rel(d.App.RepositoryDir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		out.files[rel] = recoveryFile{data: data, mode: info.Mode().Perm()}
		return nil
	})
	return out, err
}

func (w *World) restoreRecoveryDevice(i int, backup recoveryDevice, cold bool) error {
	d := w.Devices[i]
	dir := d.App.RepositoryDir
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, rel := range slices.Sorted(maps.Keys(backup.files)) {
		file := backup.files[rel]
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, file.data, file.mode); err != nil {
			return err
		}
	}
	if cold {
		if err := os.RemoveAll(d.App.CacheDir); err != nil {
			return err
		}
	}
	d.Keys.workspaces = copyRecoveryKeys(backup.keys)
	w.Restart(i)
	return w.Tape.Observe("restore-device-backup", []any{i, cold}, len(backup.files))
}

func (w *World) backupRecoveryStore(ctx context.Context) ([]storage.Object, error) {
	cfg, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return nil, err
	}
	s := w.Devices[0].Store
	var out []storage.Object
	for _, kind := range []storage.Kind{storage.KindControl, storage.KindRequest, storage.KindState, storage.KindCompaction} {
		scopes := []string{""}
		if kind == storage.KindState || kind == storage.KindCompaction {
			scopes = nil
			for _, env := range cfg.EnvironmentNames() {
				scopes = append(scopes, storage.StateScope(cfg.WorkspaceID, cfg.Resource(env)))
			}
		}
		for _, scope := range scopes {
			revs, err := s.Discover(ctx, kind, scope)
			if err != nil {
				return nil, err
			}
			for _, rev := range revs {
				head, err := s.FetchHead(ctx, kind, scope, rev)
				if err != nil {
					return nil, err
				}
				object := storage.Object{Kind: kind, Scope: scope, Rev: rev, Head: head}
				if kind == storage.KindState {
					blob, err := storage.ReadBlob(ctx, s, kind, scope, rev, 0, storage.MaxPayloadBytes)
					if err != nil {
						return nil, err
					}
					object.Blobs = [][]byte{blob}
				}
				out = append(out, object)
			}
		}
	}
	return out, nil
}

func (w *World) restoreRecoveryStore(ctx context.Context, backup []storage.Object) error {
	current, err := w.backupRecoveryStore(ctx)
	if err != nil {
		return err
	}
	s := w.Devices[0].Store
	for _, object := range current {
		if err := s.Delete(ctx, object.Kind, object.Scope, object.Rev); err != nil {
			return err
		}
	}
	for _, object := range backup {
		if err := s.Publish(ctx, object); err != nil {
			return err
		}
	}
	return nil
}

// A retained checkpoint is a rollback witness. Rolling back every trusted
// checkpoint as well as storage removes that witness; signatures cannot prove
// freshness without it. Keep this boundary distinct from a failed recovery.
func (w *World) DisasterRecovery(ctx context.Context, mode string, cold bool) error {
	switch mode {
	case "witness", "all-stale", "retired-key":
	default:
		return fmt.Errorf("unknown disaster recovery mode %q", mode)
	}
	a := w.Devices[0].App
	if err := a.CreateEnvironment("staging"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	w.Model["staging"] = map[string]string{}
	oldModels := make(map[string]map[string]string)
	for _, env := range []string{"default", "staging"} {
		old := maps.Clone(w.Model[env])
		old["A"], old["B"] = env+"-old-a", env+"-old-b"
		if _, err := a.ImportSecrets(ctx, env, old, true); err != nil {
			return err
		}
		w.Model[env] = old
		oldModels[env] = maps.Clone(old)
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	oldDevices := make([]recoveryDevice, len(w.Devices))
	for i, d := range w.Devices {
		selection := "default"
		if i%2 == 1 {
			selection = "staging"
		}
		if err := d.App.SwitchEnvironment(selection); err != nil {
			return err
		}
		backup, err := backupRecoveryDevice(d)
		if err != nil {
			return err
		}
		oldDevices[i] = backup
	}
	oldStore, err := w.backupRecoveryStore(ctx)
	if err != nil {
		return err
	}
	for _, env := range []string{"default", "staging"} {
		latest := maps.Clone(w.Model[env])
		latest["A"], latest["B"] = env+"-latest-a", env+"-latest-b"
		if _, err := w.Devices[1].App.ImportSecrets(ctx, env, latest, true); err != nil {
			return err
		}
		w.Model[env] = latest
	}
	if mode == "retired-key" {
		if _, err := w.Devices[1].App.UpgradeIdentity(ctx); err != nil {
			return err
		}
		if err := a.ApproveMember(ctx, w.Devices[1].ID); err != nil {
			return err
		}
	} else if err := a.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
		return err
	}
	for _, env := range []string{"default", "staging"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	currentDevices := make([]recoveryDevice, len(w.Devices))
	for i, d := range w.Devices {
		if err := d.App.SwitchEnvironment("default"); err != nil {
			return err
		}
		backup, err := backupRecoveryDevice(d)
		if err != nil {
			return err
		}
		currentDevices[i] = backup
	}
	currentStore, err := w.backupRecoveryStore(ctx)
	if err != nil {
		return err
	}
	for i := range w.Devices {
		backup := oldDevices[i]
		if mode == "witness" && i == 0 {
			backup = currentDevices[i]
		}
		if err := w.restoreRecoveryDevice(i, backup, cold); err != nil {
			return err
		}
	}
	if mode != "retired-key" {
		if err := w.restoreRecoveryStore(ctx, oldStore); err != nil {
			return err
		}
	}
	for i, d := range w.Devices {
		selection := "default"
		if i%2 == 1 {
			selection = "staging"
		}
		if current, err := d.App.CurrentEnvironment(); err != nil || current != selection {
			return fmt.Errorf("backup restore mixed personal selection for device %d: got %q want %q: %v", i, current, selection, err)
		}
		for _, env := range []string{"default", "staging"} {
			start := len(w.Tape.Recording.Entries)
			got, err := d.App.ListSecrets(ctx, env)
			if mode == "witness" && i == 0 {
				if err := requireCode(err, apperr.CodeRollback); err != nil {
					return fmt.Errorf("retained witness accepted a rolled-back store: %w", err)
				}
				if err := requireCode(d.App.AddSecret(ctx, env, "MUST_NOT_WRITE", "recovery-canary"), apperr.CodeRollback); err != nil {
					return err
				}
			} else if mode == "retired-key" && i == 1 {
				var noMatch *agecrypto.NoIdentityMatchError
				if !errors.As(err, &noMatch) || got != nil {
					return fmt.Errorf("retired key recovered a newer encrypted state: %w", err)
				}
			} else {
				want := w.Model[env]
				if mode != "retired-key" {
					want = oldModels[env]
				}
				if err != nil || !reflect.DeepEqual(got, want) {
					return fmt.Errorf("restored reader %d/%s returned an unexpected snapshot: %v", i, env, err)
				}
			}
			for _, entry := range w.Tape.Recording.Entries[start:] {
				if entry.Kind != "storage-request" {
					continue
				}
				var request struct{ Method string }
				if err := json.Unmarshal(entry.Input, &request); err != nil {
					return err
				}
				if request.Method == "publish" || request.Method == "delete" {
					return fmt.Errorf("recovery probe changed remote storage")
				}
			}
		}
	}
	if err := w.restoreRecoveryStore(ctx, currentStore); err != nil {
		return err
	}
	if mode == "retired-key" {
		if err := w.restoreRecoveryDevice(1, currentDevices[1], cold); err != nil {
			return err
		}
	}
	for _, env := range []string{"default", "staging"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
		if err := w.Devices[len(w.Devices)-1].App.AddSecret(ctx, env, "RECOVERED", "acknowledged-after-recovery"); err != nil {
			return err
		}
		w.Model[env]["RECOVERED"] = "acknowledged-after-recovery"
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

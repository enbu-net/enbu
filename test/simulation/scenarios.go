package simulation

import (
	"context"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

var Scenarios = []string{"environments", "history", "membership", "key-update", "concurrent-keys", "conflicting-edits", "control-fork", "trust-root", "write-faults", "read-faults", "file-output", "public-surface", "local-corruption", "adversarial-storage", "delete-faults", "partition-recovery", "stale-writer", "concurrent-environments"}

func requireCode(e error, c apperr.Code) error {
	if ErrorCode(e) != string(c) {
		return fmt.Errorf("got %s want %s: %v", ErrorCode(e), c, e)
	}
	return nil
}
func (w *World) Scenario(ctx context.Context, name string) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	a, b := w.Devices[0].App, w.Devices[1].App
	// Every scenario starts with a real acknowledged revision.
	if e := a.AddSecret(ctx, "default", "BASE", "original"); e != nil {
		return e
	}
	w.Model["default"]["BASE"] = "original"
	switch name {
	case "environments":
		if e := a.CreateEnvironment("staging"); e != nil {
			return e
		}
		w.Model["staging"] = map[string]string{}
		if e := w.Share(0); e != nil {
			return e
		}
		if current, e := b.CurrentEnvironment(); e != nil || current != "default" {
			return fmt.Errorf("personal environment leaked: %s %v", current, e)
		}
		if e := a.AddSecret(ctx, "staging", "ONLY", "staging"); e != nil {
			return e
		}
		w.Model["staging"]["ONLY"] = "staging"
		if e := w.Check(ctx, "staging"); e != nil {
			return e
		}
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		if e := a.RenameEnvironment("staging", "renamed"); e != nil {
			return e
		}
		w.Model["renamed"] = w.Model["staging"]
		delete(w.Model, "staging")
		if e := w.Share(0); e != nil {
			return e
		}
		if e := w.Check(ctx, "renamed"); e != nil {
			return e
		}
		if e := a.SwitchEnvironment("default"); e != nil {
			return e
		}
		if previous, e := a.SwitchPrevious(); e != nil || previous != "renamed" {
			return fmt.Errorf("previous: %s %v", previous, e)
		}
		if e := a.SwitchEnvironment("default"); e != nil {
			return e
		}
		c, e := config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		inc := c.Environments["renamed"].Incarnation
		if e := a.DeleteEnvironment("renamed"); e != nil {
			return e
		}
		delete(w.Model, "renamed")
		if e := a.CreateEnvironment("renamed"); e != nil {
			return e
		}
		w.Model["renamed"] = map[string]string{}
		c, e = config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		if c.Environments["renamed"].Incarnation == inc {
			return fmt.Errorf("recreated environment reused incarnation")
		}
		if e := w.Share(0); e != nil {
			return e
		}
		if e := w.Check(ctx, "renamed"); e != nil {
			return e
		}
		if _, e := a.PurgeIncarnation(ctx, inc); e != nil {
			return e
		}
		if e := a.SwitchEnvironment("default"); e != nil {
			return e
		}
		if _, e := a.DeleteEnvironmentPurging(ctx, "renamed"); e != nil {
			return e
		}
		delete(w.Model, "renamed")
		return w.Share(0)
	case "history":
		before := clone(w.Model["default"])
		if e := a.EditSecret(ctx, "default", "BASE", "changed"); e != nil {
			return e
		}
		w.Model["default"]["BASE"] = "changed"
		history, e := a.ListHistory(ctx, "default")
		if e != nil {
			return e
		}
		if len(history) != 2 {
			return fmt.Errorf("history length %d want 2", len(history))
		}
		diff, e := a.DiffHistory(ctx, "default", 1, 2)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(diff.Modified, []string{"BASE"}) {
			return fmt.Errorf("wrong diff: %+v", diff)
		}
		if e := a.RestoreHistory(ctx, "default", 1); e != nil {
			return e
		}
		w.Model["default"] = before
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		result, e := a.CompactHistory(ctx, "default", 1)
		if e != nil {
			return e
		}
		if result.Removed == 0 {
			return fmt.Errorf("compaction removed nothing")
		}
		for i := range w.Devices {
			w.Restart(i)
		}
		return w.Check(ctx, "default")
	case "membership":
		if e := requireCode(b.SetAdmin(ctx, w.Devices[0].ID, false), apperr.CodeAccessDenied); e != nil {
			return e
		}
		if e := requireCode(b.RemoveMember(ctx, w.Devices[0].ID), apperr.CodeAccessDenied); e != nil {
			return e
		}
		if e := a.SetAdmin(ctx, w.Devices[1].ID, true); e != nil {
			return e
		}
		if e := b.SetAdmin(ctx, w.Devices[1].ID, false); e != nil {
			return e
		}
		if e := a.RemoveMember(ctx, w.Devices[1].ID); e != nil {
			return e
		}
		// Authorization rejection alone is insufficient: the removed key must
		// also fail to decrypt the current ciphertext directly from storage.
		cfg, err := config.LoadProjectFrom(a.RepositoryDir)
		if err != nil {
			return err
		}
		view, err := wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
		if err != nil {
			return err
		}
		states, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
		if err != nil {
			return err
		}
		id, err := w.Devices[1].Keys.Load(cfg.WorkspaceID)
		if err != nil {
			return err
		}
		defer func() { _ = id.Close() }()
		if len(states.Heads) == 0 {
			return fmt.Errorf("removal left no current encrypted state")
		}
		for _, head := range states.Heads {
			blob, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, head)
			if err != nil {
				return err
			}
			_, err = age.Decrypt(blob, id)
			var noMatch *agecrypto.NoIdentityMatchError
			if !errors.As(err, &noMatch) {
				return fmt.Errorf("removed key could decrypt current ciphertext: %v", err)
			}
		}

		if _, e := b.ListSecrets(ctx, "default"); requireCode(e, apperr.CodeNotMember) != nil {
			return fmt.Errorf("removed device read: %v", e)
		}
		if e := requireCode(b.AddSecret(ctx, "default", "UNAUTHORIZED", "value"), apperr.CodeNotMember); e != nil {
			return e
		}
		r, e := b.InitializeRepository(ctx)
		if e != nil {
			return e
		}
		if !r.Pending {
			return fmt.Errorf("removed device silently rejoined")
		}
		requests, e := a.ListJoinRequests(ctx)
		if e != nil {
			return e
		}
		if len(requests) != 1 {
			return fmt.Errorf("pending requests %d", len(requests))
		}
		if e := a.ApproveMember(ctx, w.Devices[1].ID); e != nil {
			return e
		}
		members, e := a.ListMembers(ctx)
		if e != nil {
			return e
		}
		if len(members) != len(w.Devices) {
			return fmt.Errorf("membership count changed")
		}
		return w.Check(ctx, "default")
	case "key-update":
		r, e := b.UpgradeIdentity(ctx)
		if e != nil {
			return e
		}
		if !r.Pending {
			return fmt.Errorf("member key updated without approval")
		}
		if e := a.ApproveMember(ctx, w.Devices[1].ID); e != nil {
			return e
		}
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		r, e = a.UpgradeIdentity(ctx)
		if e != nil {
			return e
		}
		if r.Pending {
			return fmt.Errorf("admin key still pending")
		}
		return w.Check(ctx, "default")
	case "concurrent-keys":
		var ops []func(int) error
		for range w.Devices {
			ops = append(ops, func(i int) error {
				return w.Devices[i].App.AddSecret(ctx, "default", fmt.Sprintf("FROM_%d", i), "kept")
			})
		}
		if e := w.Batch(ctx, "publish", ops); e != nil {
			return e
		}
		for i := range w.Devices {
			w.Model["default"][fmt.Sprintf("FROM_%d", i)] = "kept"
		}
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		if e := a.SyncSecrets(ctx, "default"); e != nil {
			return e
		}
		return w.Check(ctx, "default")
	case "conflicting-edits":
		if e := w.Batch(ctx, "publish", []func(int) error{func(int) error { return a.EditSecret(ctx, "default", "BASE", "alice") }, func(int) error { return b.EditSecret(ctx, "default", "BASE", "bob") }}); e != nil {
			return e
		}
		set, e := a.ListConflicts(ctx, "default")
		if e != nil {
			return e
		}
		if len(set.Conflicts) != 1 || set.Conflicts[0].Key != "BASE" {
			return fmt.Errorf("concurrent edits not reported: %+v", set)
		}
		if _, e := a.ListSecrets(ctx, "default"); requireCode(e, apperr.CodeSecretConflict) != nil {
			return fmt.Errorf("conflicted read accepted: %v", e)
		}
		if e := requireCode(a.ResolveSecrets(ctx, "default", []string{"obsolete"}, map[string]app.SecretChoice{"BASE": {Value: "lost"}}), apperr.CodeConflict); e != nil {
			return e
		}
		if e := a.ResolveSecrets(ctx, "default", set.Heads, map[string]app.SecretChoice{"BASE": {Value: "resolved"}}); e != nil {
			return e
		}
		w.Model["default"]["BASE"] = "resolved"
		return w.Check(ctx, "default")
	case "control-fork":
		if len(w.Devices) < 3 {
			return fmt.Errorf("control fork needs three devices")
		}
		if e := a.SetAdmin(ctx, w.Devices[1].ID, true); e != nil {
			return e
		}
		if e := w.Batch(ctx, "publish", []func(int) error{func(int) error { return allowFork(a.SetAdmin(ctx, w.Devices[2].ID, true)) }, func(int) error { return allowFork(b.SetAdmin(ctx, w.Devices[2].ID, false)) }}); e != nil {
			return e
		}
		if _, e := a.ListSecrets(ctx, "default"); requireCode(e, apperr.CodeControlForked) != nil {
			return fmt.Errorf("forked read accepted: %v", e)
		}
		if e := a.ResolveControlFork(ctx); e != nil {
			return e
		}
		return w.Check(ctx, "default")
	case "trust-root":
		c, e := config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		trusted := c.ControlGenesis
		c.ControlGenesis = "sha256:" + strings.Repeat("0", 64)
		if e := config.SaveProjectTo(a.RepositoryDir, c); e != nil {
			return e
		}
		for _, op := range []func() error{func() error { _, e := a.ListSecrets(ctx, "default"); return e }, func() error { return a.AddSecret(ctx, "default", "EVIL", "x") }, func() error { _, e := a.ListMembers(ctx); return e }} {
			if e := requireCode(op(), apperr.CodeTrustRootChanged); e != nil {
				return e
			}
		}
		c.ControlGenesis = trusted
		if e := config.SaveProjectTo(a.RepositoryDir, c); e != nil {
			return e
		}
		return w.Check(ctx, "default")
	case "write-faults":
		for _, mode := range []string{"before", "after", "cancel"} {
			key := "FAULT_" + mode
			w.Devices[0].Store.Arm(Fault{"publish", 1, mode})
			e := a.AddSecret(ctx, "default", key, "durable")
			if e == nil {
				return fmt.Errorf("%s publish failure not delivered", mode)
			}
			w.Devices[0].Store.Arm(Fault{})
			if mode == "after" {
				w.Model["default"][key] = "durable"
			}
			if e := w.Check(ctx, "default"); e != nil {
				return e
			}
			if mode != "after" {
				if e := a.AddSecret(ctx, "default", key, "durable"); e != nil {
					return e
				}
				w.Model["default"][key] = "durable"
			}
		}
		return w.Check(ctx, "default")
	case "read-faults":
		for _, f := range []Fault{{"head", 1, "before"}, {"head", 1, "corrupt"}, {"head", 1, "missing"}, {"blob", 1, "short"}, {"blob", 1, "corrupt"}, {"blob", 1, "missing"}, {"discover", 1, "before"}, {"discover", 1, "stale"}} {
			if e := os.RemoveAll(a.CacheDir); e != nil {
				return e
			}
			w.Devices[0].Store.Arm(f)
			got, e := a.ListSecrets(ctx, "default")
			if e == nil && !reflect.DeepEqual(got, w.Model["default"]) {
				return fmt.Errorf("read fault exposed incorrect state: %+v", f)
			}
			if w.Devices[0].Store.calls[f.Method] < f.At {
				return fmt.Errorf("fault not reached: %+v", f)
			}
			w.Devices[0].Store.Arm(Fault{})
			w.Restart(0)
			if e := w.Check(ctx, "default"); e != nil {
				return e
			}
		}
		return nil
	case "file-output":
		if e := a.PullSecretsToFile(ctx, "default"); e != nil {
			return e
		}
		path := filepath.Join(a.RepositoryDir, ".env")
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if !strings.Contains(string(data), "BASE=") {
			return fmt.Errorf("pull output missing BASE")
		}
		if e := os.WriteFile(path, []byte("invalid dotenv !!!"), 0600); e != nil {
			return e
		}
		if e := requireCode(a.PullSecretsToFile(ctx, "default"), apperr.CodeOutputUnreadable); e != nil {
			return e
		}
		if _, e := a.PullSecretsToFileWith(ctx, "default", true); e != nil {
			return e
		}
		data, _, count, pe := a.PullSecrets(ctx, "default")
		if pe != nil || count != len(w.Model["default"]) || !strings.Contains(string(data), "BASE=") {
			return fmt.Errorf("pull bytes: count %d error %v", count, pe)
		}
		_, e = a.ReadConfig()
		if e != nil {
			return e
		}
		return nil
	case "public-surface":
		a.SetRepositoryDir(a.RepositoryDir)
		if _, e := a.WorkspaceID(); e != nil {
			return e
		}
		if got, e := a.DefaultStorageURL(); e != nil || got != "oci://ghcr.io/team/workspace-enbu" {
			return fmt.Errorf("default storage: %s %v", got, e)
		}
		if _, _, e := a.CreateIdentity(); e != nil {
			return e
		}
		if _, e := a.IdentityInfo(); e != nil {
			return e
		}
		a.DiagnoseIdentity()
		ids, e := a.LoadWorkspaceIdentities()
		if e != nil {
			return e
		}
		app.CloseIdentities(ids)
		if _, e := a.ListEnvironments(); e != nil {
			return e
		}
		text, e := a.ReadConfig()
		if e != nil {
			return e
		}
		if e := a.WriteConfig(text); e != nil {
			return e
		}
		cfg, e := config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		protected := strings.Replace(text, cfg.WorkspaceID, "00000000-0000-4000-8000-000000000000", 1)
		if e := requireCode(a.WriteConfig(protected), apperr.CodeConfigProtected); e != nil {
			return e
		}
		if e := requireCode(a.SetAdmin(ctx, w.Devices[0].ID, false), apperr.CodeInvalidArgument); e != nil {
			return e
		}
		if e := requireCode(a.RemoveMember(ctx, w.Devices[0].ID), apperr.CodeInvalidArgument); e != nil {
			return e
		}
		if e := requireCode(a.CreateEnvironment("default"), apperr.CodeEnvironmentExists); e != nil {
			return e
		}
		if e := requireCode(a.DeleteEnvironment("default"), apperr.CodeInvalidArgument); e != nil {
			return e
		}
		if e := requireCode(a.ApproveMember(ctx, "bad-id"), apperr.CodeInvalidArgument); e != nil {
			return e
		}
		if _, e := a.ImportSecrets(ctx, "default", map[string]string{"BASE": "overwrite"}, false); requireCode(e, apperr.CodeSecretExists) != nil {
			return fmt.Errorf("import conflict: %v", e)
		}
		return w.Check(ctx, "default")
	case "local-corruption":
		// Personal state corruption must not silently select the team default.
		id, e := a.WorkspaceID()
		if e != nil {
			return e
		}
		if e := config.SaveLocalStateTo(a.Runtime.LocalStateDir, id, &config.LocalConfig{}); e != nil {
			return e
		}
		files, e := filepath.Glob(filepath.Join(a.Runtime.LocalStateDir, "state", "*"))
		if e != nil || len(files) != 1 {
			return fmt.Errorf("state file missing: %v", e)
		}
		data, e := os.ReadFile(files[0])
		if e != nil {
			return e
		}
		if e := os.WriteFile(files[0], []byte("[malformed"), 0600); e != nil {
			return e
		}
		if _, e := a.CurrentEnvironment(); e == nil {
			return fmt.Errorf("corrupt personal state silently accepted")
		}
		if e := os.WriteFile(files[0], data, 0600); e != nil {
			return e
		}
		// A corrupt optimization cache must be discarded and rebuilt.
		_ = filepath.WalkDir(a.CacheDir, func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				return os.WriteFile(path, []byte("damaged"), 0600)
			}
			return err
		})
		w.Restart(0)
		return w.Check(ctx, "default")
	case "adversarial-storage":
		c, e := config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		scope := storage.StateScope(c.WorkspaceID, c.Resource("default"))
		// Digest-valid objects with invalid signatures or encoding carry no authority.
		for _, kind := range []storage.Kind{storage.KindState, storage.KindControl, storage.KindRequest} {
			sc := ""
			if kind == storage.KindState {
				sc = scope
			}
			o := storagetest.Object(kind, sc, "forged signed object", "forged ciphertext")
			if e := w.Devices[0].Store.Publish(ctx, o); e != nil {
				return e
			}
		}
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		requests, e := a.ListJoinRequests(ctx)
		if e != nil {
			return e
		}
		if len(requests) != 0 {
			return fmt.Errorf("forged request gained authority")
		}
		// Removing an acknowledged current state must fail closed on every device.
		revs, e := w.Devices[0].Store.Discover(ctx, storage.KindState, scope)
		if e != nil {
			return e
		}
		var saved []storage.Object
		for _, rev := range revs {
			head, e := w.Devices[0].Store.FetchHead(ctx, storage.KindState, scope, rev)
			if e != nil {
				return e
			}
			blob, e := storage.ReadBlob(ctx, w.Devices[0].Store, storage.KindState, scope, rev, 0, storage.MaxPayloadBytes)
			if e != nil {
				return e
			}
			saved = append(saved, storage.Object{Kind: storage.KindState, Scope: scope, Rev: rev, Head: head, Blobs: [][]byte{blob}})
			if e := w.Devices[0].Store.Delete(ctx, storage.KindState, scope, rev); e != nil {
				return e
			}
		}
		for _, d := range w.Devices {
			if _, e := d.App.ListSecrets(ctx, "default"); requireCode(e, apperr.CodeRollback) != nil {
				return fmt.Errorf("rollback accepted: %v", e)
			}
		}
		for _, o := range saved {
			if e := w.Devices[0].Store.Publish(ctx, o); e != nil {
				return e
			}
		}
		return w.Check(ctx, "default")
	case "delete-faults":
		for _, mode := range []string{"before", "after"} {
			if e := a.EditSecret(ctx, "default", "BASE", mode); e != nil {
				return e
			}
			w.Model["default"]["BASE"] = mode
			w.Devices[0].Store.Arm(Fault{"delete", 1, mode})
			if _, e := a.CompactHistory(ctx, "default", 1); e == nil {
				return fmt.Errorf("delete failure not delivered")
			}
			w.Devices[0].Store.Arm(Fault{})
			if e := w.Check(ctx, "default"); e != nil {
				return e
			}
			if _, e := a.CompactHistory(ctx, "default", 1); e != nil {
				return e
			}
		}
		return w.Check(ctx, "default")

	case "partition-recovery":
		w.Devices[1].Store.Arm(Fault{"*", 0, "partition"})
		if e := b.AddSecret(ctx, "default", "OFFLINE", "lost"); e == nil {
			return fmt.Errorf("partitioned write acknowledged")
		}
		if e := a.AddSecret(ctx, "default", "ONLINE", "kept"); e != nil {
			return e
		}
		w.Model["default"]["ONLINE"] = "kept"
		w.Devices[1].Store.Arm(Fault{})
		w.Restart(1)
		if e := b.SyncSecrets(ctx, "default"); e != nil {
			return e
		}
		return w.Check(ctx, "default")
	case "stale-writer":
		if e := w.Check(ctx, "default"); e != nil {
			return e
		}
		if e := a.AddSecret(ctx, "default", "FROM_A", "kept"); e != nil {
			return e
		}
		w.Model["default"]["FROM_A"] = "kept"
		w.Devices[1].Store.Arm(Fault{"discover", 0, "stale"})
		if e := b.AddSecret(ctx, "default", "FROM_B", "kept"); e != nil {
			return e
		}
		w.Model["default"]["FROM_B"] = "kept"
		w.Devices[1].Store.Arm(Fault{})
		if e := a.SyncSecrets(ctx, "default"); e != nil {
			return e
		}
		return w.Check(ctx, "default")

	case "concurrent-environments":
		if e := a.CreateEnvironment("alpha"); e != nil {
			return e
		}
		if e := b.CreateEnvironment("beta"); e != nil {
			return e
		}
		if e := a.AddSecret(ctx, "alpha", "ALPHA", "a"); e != nil {
			return e
		}
		if e := b.AddSecret(ctx, "beta", "BETA", "b"); e != nil {
			return e
		}
		// A member update must include scopes absent from this admin's config.
		if e := a.RemoveMember(ctx, w.Devices[1].ID); e != nil {
			return e
		}
		left, e := config.LoadProjectFrom(a.RepositoryDir)
		if e != nil {
			return e
		}
		right, e := config.LoadProjectFrom(b.RepositoryDir)
		if e != nil {
			return e
		}
		left.Environments["beta"] = right.Environments["beta"]
		if e := config.SaveProjectTo(a.RepositoryDir, left); e != nil {
			return e
		}
		if e := w.Share(0); e != nil {
			return e
		}
		if _, e := b.InitializeRepository(ctx); e != nil {
			return e
		}
		if e := a.ApproveMember(ctx, w.Devices[1].ID); e != nil {
			return e
		}
		w.Model["alpha"] = map[string]string{"ALPHA": "a"}
		w.Model["beta"] = map[string]string{"BETA": "b"}
		if e := w.Check(ctx, "alpha"); e != nil {
			return e
		}
		if e := w.Check(ctx, "beta"); e != nil {
			return e
		}
		return w.Check(ctx, "default")

	default:
		return fmt.Errorf("unknown scenario %q", name)
	}
}

func allowFork(e error) error {
	if ErrorCode(e) == string(apperr.CodeControlForked) {
		return nil
	}
	return e
}

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

var Scenarios = []string{"disaster-witness-warm", "disaster-witness-cold", "disaster-all-stale-warm", "disaster-all-stale-cold", "disaster-retired-key-warm", "disaster-retired-key-cold", "disaster-compacted-warm", "disaster-compacted-cold", "disaster-compacted-no-record-warm", "disaster-compacted-no-record-cold", "disaster-compacted-old-data-warm", "disaster-compacted-old-data-cold", "portable-config", "output-boundary-public", "output-boundary-hardlink", "output-boundary-canceled-hardlink", "output-boundary-removed-hardlink", "output-boundary-upgraded-preserve-hardlink", "output-boundary-upgraded-replace-hardlink", "wire-format-warm", "wire-format-cold", "contention-add-exhausted", "contention-add-yield", "contention-edit-exhausted", "contention-edit-yield", "contention-delete-exhausted", "contention-delete-yield", "contention-import-exhausted", "contention-import-yield", "contention-sync-exhausted", "contention-sync-yield", "environments", "history", "membership", "key-update", "concurrent-keys", "conflicting-edits", "control-fork", "trust-root", "write-faults", "read-faults", "file-output", "public-surface", "local-corruption", "adversarial-storage", "delete-faults", "partition-recovery", "stale-writer", "concurrent-environments", "concurrent-faults", "forged-state-signature", "team-incident", "team-migration", "locked-device", "rejected-edits", "request-signature-attack", "refounding", "first-member", "secret-formats", "same-user-processes", "lost-device-replacement", "multiple-workspaces", "shared-storage-workspaces", "metadata-control-count", "metadata-state-count", "metadata-compaction-count", "metadata-control-duplicate", "metadata-state-duplicate", "request-flood", "hidden-request-conflict", "git-worktrees", "partial-key-signing", "partial-key-current", "partial-key-pending-before-approval", "partial-key-pending-after-approval", "partial-key-previous", "partial-key-promotion-before", "partial-key-promotion-after"}

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
	if strings.HasPrefix(name, "retained-observer-") {
		parts := strings.Split(strings.TrimPrefix(name, "retained-observer-"), "-")
		if len(parts) != 2 || parts[0] != "value" && parts[0] != "delete" || parts[1] != "warm" && parts[1] != "cold" {
			return fmt.Errorf("invalid retained observer scenario %q", name)
		}
		return w.RetainedObserver(ctx, parts[1] == "cold", parts[0] == "delete")
	}
	if name == "observer-control-cold" || name == "observer-control-warm" {
		return w.ObserverControlEquivocation(ctx, name == "observer-control-cold")
	}
	if strings.HasPrefix(name, "observer-state-") {
		parts := strings.Split(strings.TrimPrefix(name, "observer-state-"), "-")
		if len(parts) != 2 || parts[0] != "conflict" && parts[0] != "disjoint" || parts[1] != "warm" && parts[1] != "cold" {
			return fmt.Errorf("invalid observer state scenario %q", name)
		}
		return w.ObserverStateEquivocation(ctx, parts[0] == "conflict", parts[1] == "cold")
	}
	if strings.HasPrefix(name, "history-snapshot-") {
		parts := strings.Split(strings.TrimPrefix(name, "history-snapshot-"), "-")
		if len(parts) != 3 || parts[2] != "warm" && parts[2] != "cold" {
			return fmt.Errorf("invalid history snapshot scenario %q", name)
		}
		return w.HistorySnapshot(ctx, parts[0], parts[1], parts[2] == "cold")
	}
	if strings.HasPrefix(name, "disaster-") {
		mode := strings.TrimPrefix(name, "disaster-")
		cold := strings.HasSuffix(mode, "-cold")
		mode = strings.TrimSuffix(strings.TrimSuffix(mode, "-cold"), "-warm")
		return w.DisasterRecovery(ctx, mode, cold)
	}
	if strings.HasPrefix(name, "metadata-") {
		return w.MetadataFlood(ctx, strings.TrimPrefix(name, "metadata-"))
	}
	if strings.HasPrefix(name, "contention-") {
		return w.Contention(ctx, strings.TrimPrefix(name, "contention-"))
	}
	if strings.HasPrefix(name, "output-boundary-") {
		return w.OutputBoundary(ctx, strings.TrimPrefix(name, "output-boundary-"))
	}
	if strings.HasPrefix(name, "wire-format-") {
		return w.WireAttacks(ctx, name == "wire-format-cold")
	}
	if strings.HasPrefix(name, "partial-key-") {
		return w.PartialKeys(ctx, strings.TrimPrefix(name, "partial-key-"))
	}
	switch name {
	case "portable-config":
		return w.PortableConfig(ctx)
	case "hidden-request-conflict":
		return w.HiddenRequestConflict(ctx)
	case "request-flood":
		return w.RequestFlood(ctx)
	case "git-worktrees":
		return w.GitWorktrees(ctx)
	case "multiple-workspaces":
		return w.MultipleWorkspaces(ctx, false)
	case "shared-storage-workspaces":
		return w.MultipleWorkspaces(ctx, true)
	case "lost-device-replacement":
		return w.DeviceReplacement(ctx)
	case "same-user-processes":
		return w.LocalProcesses(ctx)
	case "secret-formats":
		return w.SecretFormats(ctx)
	case "refounding":
		return w.Refounding(ctx)
	case "request-signature-attack":
		return w.RequestSignatureAttack(ctx)
	case "rejected-edits":
		return w.RejectedEdits(ctx)
	case "locked-device":
		return w.LockedDevice(ctx)
	case "team-migration":
		return w.TeamMigration(ctx)
	case "team-incident":
		return w.TeamIncident(ctx)
	case "forged-state-signature":
		return w.StateSignatureAttack(ctx)
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

		// Complete the transition as well as exercising mixed recipients.
		for i := 2; i < len(w.Devices); i++ {
			if _, e := w.Devices[i].App.UpgradeIdentity(ctx); e != nil {
				return e
			}
			if e := a.ApproveMember(ctx, w.Devices[i].ID); e != nil {
				return e
			}
		}
		members, e := a.ListMembers(ctx)
		if e != nil {
			return e
		}
		for _, member := range members {
			if !member.PostQuantum {
				return fmt.Errorf("hybrid transition left a classical member")
			}
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
			a = w.Devices[0].App
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
		return w.fileLifecycle(ctx)
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
		a.DiagnoseIdentity(ctx)
		start := len(w.Tape.Recording.Entries)
		report := a.Diagnose(ctx)
		if !report.Healthy {
			return fmt.Errorf("healthy workspace failed diagnosis: %+v", report.Checks)
		}
		if err := requireReadOnlyStorage(w.Tape.Recording.Entries[start:]); err != nil {
			return fmt.Errorf("diagnosis mutated storage: %w", err)
		}
		if err := w.Observe("diagnose", nil, report, nil); err != nil {
			return err
		}
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
		if e := w.Devices[1].App.SyncSecrets(ctx, "default"); e != nil {
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

	case "concurrent-faults":
		for index, mode := range []string{"before", "after", "crash-before", "crash-after"} {
			left, right := fmt.Sprintf("LEFT_%d", index), fmt.Sprintf("RIGHT_%d", index)
			w.Devices[0].Store.Arm(Fault{"publish", 1, mode})
			results, e := w.runBatch(ctx, "publish", []func(int) error{func(int) error { return a.AddSecret(ctx, "default", left, "a") }, func(int) error { return b.AddSecret(ctx, "default", right, "b") }})
			if e != nil {
				return e
			}
			if results[0] == nil || results[1] != nil {
				return fmt.Errorf("concurrent fault %s: %v", mode, results)
			}
			w.Devices[0].Store.Arm(Fault{})
			if errors.Is(results[0], ErrCrash) {
				w.Restart(0)
				a = w.Devices[0].App
			}
			w.Model["default"][right] = "b"
			if mode == "after" || mode == "crash-after" {
				w.Model["default"][left] = "a"
			}
			if e := w.Check(ctx, "default"); e != nil {
				return e
			}
			if _, ok := w.Model["default"][left]; !ok {
				if e := a.AddSecret(ctx, "default", left, "a"); e != nil {
					return e
				}
				w.Model["default"][left] = "a"
			}
			if e := a.SyncSecrets(ctx, "default"); e != nil {
				return e
			}
			if e := w.Check(ctx, "default"); e != nil {
				return e
			}
		}
		return nil

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

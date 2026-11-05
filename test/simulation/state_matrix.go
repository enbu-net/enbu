package simulation

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// StateCase is an explicit cross product, not a randomly sampled coverage claim.
type StateCase struct{ Operation, State, Role string }

var StateOperations = []string{"add", "edit", "delete", "import", "read", "pull", "sync", "history", "diff", "restore", "compact", "conflicts", "members", "requests", "approve", "remove", "admin", "upgrade", "resolve-stale", "resolve-empty", "file-pull", "initialize"}
var DataStates = []string{"empty", "populated", "deleted", "missing-environment"}
var MemberStates = []string{"admin", "member", "pending", "removed"}

func (w *World) StateCase(ctx context.Context, c StateCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	founder := w.Devices[0].App
	// A second environment must survive every operation, including rejection.
	if err := founder.CreateEnvironment("sentinel"); err != nil {
		return err
	}
	if err := founder.AddSecret(ctx, "sentinel", "UNCHANGED", "sentinel"); err != nil {
		return err
	}
	w.Model["sentinel"] = map[string]string{"UNCHANGED": "sentinel"}
	if err := founder.SwitchEnvironment("default"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	if c.State == "populated" || c.State == "deleted" {
		if err := founder.AddSecret(ctx, "default", "BASE", "original"); err != nil {
			return err
		}
		w.Model["default"]["BASE"] = "original"
	}
	if c.State == "deleted" {
		if err := founder.DeleteSecret(ctx, "default", "BASE"); err != nil {
			return err
		}
		delete(w.Model["default"], "BASE")
	}
	actor := 1
	switch c.Role {
	case "admin":
		actor = 0
	case "member":
	case "pending", "removed":
		if err := founder.RemoveMember(ctx, w.Devices[actor].ID); err != nil {
			return err
		}
		if c.Role == "pending" {
			if _, err := w.Devices[actor].App.InitializeRepository(ctx); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown role %s", c.Role)
	}
	controlOperation := false
	switch c.Operation {
	case "members", "requests", "approve", "remove", "admin", "upgrade", "initialize":
		controlOperation = true
	}
	if c.Operation == "approve" {
		if err := founder.RemoveMember(ctx, w.Devices[2].ID); err != nil {
			return err
		}
		if _, err := w.Devices[2].App.InitializeRepository(ctx); err != nil {
			return err
		}
	}
	membership := map[string]bool{}
	for index, device := range w.Devices {
		if index == actor && (c.Role == "pending" || c.Role == "removed") {
			continue
		}
		if index == 2 && c.Operation == "approve" {
			continue
		}
		membership[device.ID] = index == 0
	}
	a := w.Devices[actor].App
	env := "default"
	if c.State == "missing-environment" {
		env = "absent"
	}
	want := clone(w.Model["default"])
	expected := ""
	switch {
	case c.Operation == "resolve-empty":
		expected = string(apperr.CodeInvalidArgument)
	case c.State == "missing-environment" && !controlOperation:
		expected = string(apperr.CodeEnvironmentMissing)
	case c.Operation == "members" || c.Operation == "requests" || c.Operation == "initialize":
		// Control metadata is public, including for pending and removed devices.
	case c.Role == "pending" || c.Role == "removed":
		expected = string(apperr.CodeNotMember)
	case (c.Operation == "compact" || c.Operation == "approve" || c.Operation == "remove" || c.Operation == "admin") && c.Role == "member":
		expected = string(apperr.CodeAccessDenied)
	case c.Operation == "resolve-stale":
		expected = string(apperr.CodeConflict)
		if c.State == "empty" {
			expected = string(apperr.CodeArtifactNotFound)
		}
	case c.Operation == "file-pull" && c.State == "empty":
		expected = string(apperr.CodeArtifactNotFound)
	case c.Operation == "add" && c.State == "populated":
		expected = string(apperr.CodeSecretExists)
	case c.Operation == "edit" && c.State == "empty":
		expected = string(apperr.CodeArtifactNotFound)
	case c.Operation == "edit" && c.State == "deleted":
		expected = string(apperr.CodeSecretMissing)
	case c.Operation == "pull" && c.State == "empty":
		expected = string(apperr.CodeArtifactNotFound)
	case (c.Operation == "diff" || c.Operation == "restore") && c.State == "empty":
		expected = string(apperr.CodeInvalidArgument)
	}
	var out any
	var err error
	switch c.Operation {
	case "initialize":
		out, err = a.InitializeRepository(ctx)
	case "resolve-stale":
		err = a.ResolveSecrets(ctx, env, []string{"stale"}, map[string]app.SecretChoice{"BASE": {Value: "must-not-commit"}})
	case "resolve-empty":
		err = a.ResolveSecrets(ctx, env, nil, map[string]app.SecretChoice{"BASE": {Value: "must-not-commit"}})
	case "file-pull":
		err = a.PullSecretsToFile(ctx, env)
	case "add":
		err = a.AddSecret(ctx, env, "BASE", "changed")
	case "edit":
		err = a.EditSecret(ctx, env, "BASE", "changed")
	case "delete":
		err = a.DeleteSecret(ctx, env, "BASE")
	case "import":
		out, err = a.ImportSecrets(ctx, env, map[string]string{"BASE": "changed"}, true)
	case "read":
		out, err = a.ListSecrets(ctx, env)
	case "pull":
		out, err = a.PullSecretsData(ctx, env)
	case "sync":
		err = a.SyncSecrets(ctx, env)
	case "history":
		out, err = a.ListHistory(ctx, env)
	case "diff":
		out, err = a.DiffHistory(ctx, env, 1, 1)
	case "restore":
		err = a.RestoreHistory(ctx, env, 1)
	case "compact":
		out, err = a.CompactHistory(ctx, env, 1)
	case "conflicts":
		out, err = a.ListConflicts(ctx, env)
	case "members":
		out, err = a.ListMembers(ctx)
	case "requests":
		out, err = a.ListJoinRequests(ctx)
	case "approve":
		err = a.ApproveMember(ctx, w.Devices[2].ID)
	case "remove":
		err = a.RemoveMember(ctx, w.Devices[2].ID)
	case "admin":
		err = a.SetAdmin(ctx, w.Devices[2].ID, true)
	case "upgrade":
		out, err = a.UpgradeIdentity(ctx)
	default:
		return fmt.Errorf("unknown state operation %s", c.Operation)
	}
	if te := w.Tape.Observe("state-case", []any{c, expected}, []any{out, ErrorCode(err)}); te != nil {
		return te
	}
	if ErrorCode(err) != expected {
		return fmt.Errorf("%+v: got %s want %s: %v", c, ErrorCode(err), expected, err)
	}
	if expected == "" {
		switch c.Operation {
		case "add", "edit", "import":
			want["BASE"] = "changed"
		case "delete":
			delete(want, "BASE")
		case "restore":
			want["BASE"] = "original"
		case "initialize":
			result := out.(*app.InitResult)
			if result.Pending != (c.Role == "pending" || c.Role == "removed") || result.Founded || result.KeyCreated || result.DeviceID != w.Devices[actor].ID {
				return fmt.Errorf("reinitialization changed identity or implicit membership: %+v", result)
			}
		case "file-pull":
			if err := w.checkOutput("state-file-pull", filepath.Join(a.RepositoryDir, ".env"), want); err != nil {
				return err
			}
		case "pull":
			if !reflect.DeepEqual(out.(*app.PulledSecrets).Secrets, want) {
				return fmt.Errorf("pull differs from model")
			}
		case "history":
			count := 0
			switch c.State {
			case "populated":
				count = 1
			case "deleted":
				count = 2
			}
			if len(out.([]app.HistoryEntry)) != count {
				return fmt.Errorf("history count differs from model")
			}
		case "members":
			listed := map[string]bool{}
			for _, m := range out.([]app.MemberInfo) {
				listed[m.DeviceID] = m.Admin
			}
			if !reflect.DeepEqual(listed, membership) {
				return fmt.Errorf("listed membership differs from model")
			}
		case "read":
			if !reflect.DeepEqual(out, want) {
				return fmt.Errorf("read differs from model")
			}
		}
	}
	if expected == "" {
		switch c.Operation {
		case "approve":
			membership[w.Devices[2].ID] = false
		case "remove":
			delete(membership, w.Devices[2].ID)
		case "admin":
			membership[w.Devices[2].ID] = true
		case "upgrade":
			update := out.(*app.KeyUpdateResult)
			if update.Pending != (c.Role == "member") {
				return fmt.Errorf("key approval bypass: %+v", update)
			}
		}
	}
	members, err := founder.ListMembers(ctx)
	if err != nil {
		return err
	}
	gotMembership := map[string]bool{}
	for _, m := range members {
		gotMembership[m.DeviceID] = m.Admin
	}
	if !reflect.DeepEqual(gotMembership, membership) {
		return fmt.Errorf("membership differs: got %v want %v", gotMembership, membership)
	}
	if expected == "" && c.Operation == "upgrade" && c.Role == "member" {
		if err := founder.ApproveMember(ctx, w.Devices[actor].ID); err != nil {
			return err
		}
	}
	if _, present := membership[w.Devices[2].ID]; !present {
		if _, err := w.Devices[2].App.InitializeRepository(ctx); err != nil {
			return err
		}
		if err := founder.ApproveMember(ctx, w.Devices[2].ID); err != nil {
			return err
		}
	}
	w.Model["default"] = want
	// Restore membership only after asserting denial; then every device must agree.
	if c.Role == "pending" || c.Role == "removed" {
		if _, err := a.InitializeRepository(ctx); err != nil {
			return err
		}
		if err := founder.ApproveMember(ctx, w.Devices[actor].ID); err != nil {
			return err
		}
	}
	for _, name := range []string{"default", "sentinel"} {
		if err := w.Check(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// StateCase is an explicit cross product, not a randomly sampled coverage claim.
type StateCase struct{ Operation, State, Role string }

var StateOperations = []string{"add", "edit", "delete", "import", "read", "pull", "sync", "history", "diff", "restore", "compact", "conflicts"}
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
	a := w.Devices[actor].App
	env := "default"
	if c.State == "missing-environment" {
		env = "absent"
	}
	want := clone(w.Model["default"])
	expected := ""
	switch {
	case c.State == "missing-environment":
		expected = string(apperr.CodeEnvironmentMissing)
	case c.Role == "pending" || c.Role == "removed":
		expected = string(apperr.CodeNotMember)
	case c.Operation == "compact" && c.Role == "member":
		expected = string(apperr.CodeAccessDenied)
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
	default:
		return fmt.Errorf("unknown state operation %s", c.Operation)
	}
	if te := w.Tape.Observe("state-case", []any{c, expected}, []any{out, ErrorCode(err)}); te != nil {
		return te
	}
	if ErrorCode(err) != expected {
		return fmt.Errorf("%+v: got %s want %s: %w", c, ErrorCode(err), expected, err)
	}
	if expected == "" {
		switch c.Operation {
		case "add", "edit", "import":
			want["BASE"] = "changed"
		case "delete":
			delete(want, "BASE")
		case "restore":
			want["BASE"] = "original"
		case "read":
			if !reflect.DeepEqual(out, want) {
				return fmt.Errorf("read differs from model")
			}
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

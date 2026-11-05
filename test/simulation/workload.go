package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"math/rand/v2"
	"reflect"
	"sort"
)

type Action struct {
	Kind        string
	Device      int
	Key, Value  string
	Environment string
}

func Generate(seed uint64, steps, devices int) []Action {
	r := rand.New(rand.NewPCG(seed, 0x4f504552))
	out := make([]Action, 0, steps)
	kinds := []string{"add", "edit", "delete", "import", "read", "sync", "restart", "pull", "history", "invalid", "create-env", "switch-env", "rename-env", "delete-env", "compact", "members", "rejoin", "role"}
	for i := 0; i < steps; i++ {
		out = append(out, Action{Kind: kinds[r.IntN(len(kinds))], Device: r.IntN(devices), Key: fmt.Sprintf("K_%d", r.IntN(12)), Value: fmt.Sprintf("v_%d_%d", i, r.Uint64()), Environment: fmt.Sprintf("env_%d", r.IntN(3))})
	}
	return out
}

// Workload maintains a separate sequential specification. Errors never become
// acceptable just because the application returned them.
func (w *World) Workload(ctx context.Context, actions []Action) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	for step, op := range actions {
		d := w.Devices[op.Device]
		a := d.App
		env := op.Environment
		if env == "" {
			env = "default"
		}
		m, present := w.Model[env]
		// Lifecycle actions address absent names; data operations keep exercising
		// live environments even before a generated create has occurred.
		if !present && !lifecycleAction(op.Kind) {
			env = "default"
			m = w.Model[env]
		}

		hasRevision := len(m) > 0
		if !hasRevision && (op.Kind == "edit" || op.Kind == "pull") {
			history, err := a.ListHistory(ctx, env)
			if err != nil {
				return err
			}
			hasRevision = len(history) > 0
		}
		_, exists := m[op.Key]
		expected := ""
		var out any
		var e error
		switch op.Kind {
		case "add":
			e = a.AddSecret(ctx, env, op.Key, op.Value)
			if exists {
				expected = string(apperr.CodeSecretExists)
			} else {
				m[op.Key] = op.Value
			}
		case "edit":
			e = a.EditSecret(ctx, env, op.Key, op.Value)
			if !exists {
				expected = string(apperr.CodeSecretMissing)
				if !hasRevision {
					expected = string(apperr.CodeArtifactNotFound)
				}
			} else {
				m[op.Key] = op.Value
			}
		case "delete":
			e = a.DeleteSecret(ctx, env, op.Key)
			delete(m, op.Key)
		case "import":
			out, e = a.ImportSecrets(ctx, env, map[string]string{op.Key: op.Value}, true)
			m[op.Key] = op.Value
		case "read":
			out, e = a.ListSecrets(ctx, env)
		case "sync":
			e = a.SyncSecrets(ctx, env)
		case "restart":
			w.Restart(op.Device)
		case "pull":
			var data *app.PulledSecrets
			data, e = a.PullSecretsData(ctx, env)
			out = data
			if e == nil {
				if !reflect.DeepEqual(data.Secrets, m) {
					return fmt.Errorf("pull reference mismatch")
				}
			}
			if !hasRevision {
				expected = string(apperr.CodeArtifactNotFound)
			}
		case "history":
			out, e = a.ListHistory(ctx, env)
		case "create-env":
			if present {
				expected = string(apperr.CodeEnvironmentExists)
			}
			e = a.CreateEnvironment(env)
			if !present && e == nil {
				w.Model[env] = map[string]string{}
			}
			if e == nil {
				e = w.Share(op.Device)
			}
		case "switch-env":
			e = a.SwitchEnvironment(env)
			if !present {
				expected = string(apperr.CodeEnvironmentMissing)
			}
		case "rename-env":
			target := env + "_renamed"
			_, targetExists := w.Model[target]
			e = a.RenameEnvironment(env, target)
			if !present {
				expected = string(apperr.CodeEnvironmentMissing)
			} else if targetExists {
				expected = string(apperr.CodeEnvironmentExists)
			}
			if e == nil {
				w.Model[target] = m
				delete(w.Model, env)
				e = w.Share(op.Device)
			}
		case "delete-env":
			current, err := a.CurrentEnvironment()
			if err != nil {
				return err
			}
			e = a.DeleteEnvironment(env)
			if current == env {
				expected = string(apperr.CodeInvalidArgument)
			} else if !present {
				expected = string(apperr.CodeEnvironmentMissing)
			}
			if e == nil {
				delete(w.Model, env)
				e = w.Share(op.Device)
			}
		case "compact":
			// The founder remains an admin throughout generated membership changes.
			out, e = w.Devices[0].App.CompactHistory(ctx, env, 1)
		case "members":
			out, e = a.ListMembers(ctx)
		case "role":
			target := 1 + op.Device%(len(w.Devices)-1)
			e = w.Devices[0].App.SetAdmin(ctx, w.Devices[target].ID, op.Key < "K_6")
		case "rejoin":
			target := 1 + op.Device%(len(w.Devices)-1)
			e = w.Devices[0].App.RemoveMember(ctx, w.Devices[target].ID)
			if e == nil {
				_, denied := w.Devices[target].App.ListSecrets(ctx, "default")
				if err := requireCode(denied, apperr.CodeNotMember); err != nil {
					return err
				}
				_, e = w.Devices[target].App.InitializeRepository(ctx)
			}
			if e == nil {
				e = w.Devices[0].App.ApproveMember(ctx, w.Devices[target].ID)
			}
		case "invalid":
			e = a.SwitchEnvironment("../invalid")
			expected = string(apperr.CodeInvalidArgument)
		default:
			return fmt.Errorf("unknown action %q", op.Kind)
		}
		code := ErrorCode(e)
		if te := w.Tape.Observe("workload", []any{step, op, expected}, []any{out, code}); te != nil {
			return te
		}
		if code != expected {
			return &Violation{Kind: "result/" + op.Kind + "/" + op.Key, Detail: fmt.Errorf("step %d %s: code %q want %q: %v", step, op.Kind, code, expected, e)}
		}
		names := make([]string, 0, len(w.Model))
		for name := range w.Model {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if e := w.Check(ctx, name); e != nil {
				return fmt.Errorf("after step %d %s: %w", step, op.Kind, e)
			}
		}
	}
	return nil
}

func lifecycleAction(kind string) bool {
	switch kind {
	case "create-env", "switch-env", "rename-env", "delete-env", "members", "role", "rejoin", "restart", "invalid":
		return true
	default:
		return false
	}
}

package simulation

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
)

type Action struct {
	Kind        string
	Parallel    *ConcurrentCase
	Device      int
	Key, Value  string
	Environment string
	Admin       bool
}

func Generate(seed uint64, steps, devices int) []Action {
	r := rand.New(rand.NewPCG(seed, 0x4f504552))
	out := make([]Action, 0, steps)
	kinds := []string{"add", "edit", "delete", "import", "read", "sync", "restart", "pull", "history", "invalid", "create-env", "switch-env", "rename-env", "delete-env", "compact", "members", "rejoin", "role"}
	for i := 0; i < steps; i++ {
		out = append(out, Action{Kind: kinds[r.IntN(len(kinds))], Device: r.IntN(devices), Key: fmt.Sprintf("K_%d", r.IntN(12)), Value: fmt.Sprintf("v_%d_%d", i, r.Uint64()), Environment: fmt.Sprintf("env_%d", r.IntN(3)), Admin: r.IntN(2) == 0})
		if i%16 == 7 {
			left := r.IntN(devices)
			right := (left + 1 + r.IntN(devices-1)) % devices
			out[len(out)-1].Kind = "parallel"
			out[len(out)-1].Parallel = &ConcurrentCase{Left: ConcurrentOperations[r.IntN(len(ConcurrentOperations))], Right: ConcurrentOperations[r.IntN(len(ConcurrentOperations))], SameKey: r.IntN(2) == 0, Devices: []int{left, right}}
			if devices >= 3 && r.IntN(2) == 0 {
				left = 1 + r.IntN(devices-1)
				right = 1 + (left-1+1+r.IntN(devices-2))%(devices-1)
				out[len(out)-1].Parallel.Devices = []int{left, right}
				out[len(out)-1].Parallel.Compact = true
			}
		}
		if devices >= 3 && i%32 == 15 {
			out[len(out)-1].Kind = "team-group"
			out[len(out)-1].Parallel = nil
			out[len(out)-1].Key = "TEAM_" + out[len(out)-1].Value
		}
	}
	return out
}

// Workload maintains a separate specification, with explicitly generated
// concurrent groups checked by the independent merge oracle. Errors never become
// acceptable just because the application returned them.
func (w *World) Workload(ctx context.Context, actions []Action) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	initialMembers, err := w.Devices[0].App.ListMembers(ctx)
	if err != nil {
		return err
	}
	membership := map[string]bool{}
	for _, member := range initialMembers {
		membership[member.DeviceID] = member.Admin
	}
	// written holds environments this workload has successfully written, so a
	// later empty history is a lost revision rather than an expected absence.
	written := map[string]bool{}
	// selected is each person's own environment choice, keyed by the local
	// state directory (devices of one person share it). Scenarios may already
	// have chosen one, so start from what is stored; afterwards only modelled
	// switch/create/rename change it. The effective current environment falls
	// back to the team default when the chosen name is gone, exactly as a
	// user's stale choice does.
	selected := map[string]string{}
	defaultEnv := "default"
	for _, d := range w.Devices {
		cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
		if err != nil {
			return err
		}
		if cfg.DefaultEnv != "" {
			defaultEnv = cfg.DefaultEnv
		}
		local, err := config.LoadLocalStateFrom(d.App.Runtime.LocalStateDir, cfg.WorkspaceID)
		if err != nil {
			return err
		}
		selected[d.App.Runtime.LocalStateDir] = local.Current
	}
	current := func(person string) string {
		if name := selected[person]; name != "" {
			if _, ok := w.Model[name]; ok {
				return name
			}
		}
		return defaultEnv
	}
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
			if written[env] && len(history) == 0 {
				return &Violation{Kind: "history/lost/" + op.Kind, Detail: fmt.Errorf("step %d: %s was written but has no history", step, env)}
			}
			// Revisions published only by sync or re-encryption are not modelled;
			// history may add them, but can never remove a modelled write.
			hasRevision = written[env] || len(history) > 0
		}
		_, exists := m[op.Key]
		expected := ""
		var out any
		var e error
		switch op.Kind {
		case "team-group":
			e = w.GeneratedTeamGroup(ctx, op.Key, op.Value)
			membership[w.Devices[len(w.Devices)-1].ID] = false
		case "parallel":
			if op.Parallel == nil {
				return fmt.Errorf("parallel group has no operations")
			}
			e = w.ConcurrentCase(ctx, *op.Parallel)
			if e == nil {
				// A clean merged read can still have sibling heads. Seal the
				// group before later sequential operations such as compaction.
				e = w.Devices[0].App.SyncSecrets(ctx, "default")
			}
		case "add":
			e = a.AddSecret(ctx, env, op.Key, op.Value)
			if exists {
				expected = string(apperr.CodeSecretExists)
			} else {
				m[op.Key] = op.Value
				written[env] = written[env] || e == nil
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
				written[env] = written[env] || e == nil
			}
		case "delete":
			e = a.DeleteSecret(ctx, env, op.Key)
			delete(m, op.Key)
		case "import":
			out, e = a.ImportSecrets(ctx, env, map[string]string{op.Key: op.Value}, true)
			m[op.Key] = op.Value
			written[env] = written[env] || e == nil
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
					return &Violation{Kind: "pull/reference/" + env, Detail: fmt.Errorf("step %d: pulled %v want %v", step, data.Secrets, m)}
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
				// Re-creating a name starts a new incarnation with no history.
				delete(written, env)
				selected[d.App.Runtime.LocalStateDir] = env
			}
			if e == nil {
				e = w.Share(op.Device)
			}
		case "switch-env":
			e = a.SwitchEnvironment(env)
			if !present {
				expected = string(apperr.CodeEnvironmentMissing)
			} else if e == nil {
				selected[d.App.Runtime.LocalStateDir] = env
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
				written[target] = written[env]
				delete(written, env)
				// Only the renaming user's own choice follows the rename.
				if selected[d.App.Runtime.LocalStateDir] == env {
					selected[d.App.Runtime.LocalStateDir] = target
				}
				e = w.Share(op.Device)
			}
		case "delete-env":
			actual, err := a.CurrentEnvironment()
			if err != nil {
				return err
			}
			if want := current(d.App.Runtime.LocalStateDir); actual != want {
				return &Violation{Kind: "environment/current", Detail: fmt.Errorf("step %d: device %d is on %q want %q", step, op.Device, actual, want)}
			}
			_, e = a.DeleteEnvironment(ctx, env, false)
			if actual == env {
				expected = string(apperr.CodeInvalidArgument)
			} else if !present {
				expected = string(apperr.CodeEnvironmentMissing)
			}
			if e == nil {
				delete(w.Model, env)
				delete(written, env)
				e = w.Share(op.Device)
			}
		case "compact":
			// The founder remains an admin throughout generated membership changes.
			out, e = w.Devices[0].App.CompactHistory(ctx, env, 1)
		case "members":
			out, e = a.ListMembers(ctx)
		case "role":
			target := 1 + op.Device%(len(w.Devices)-1)
			e = w.Devices[0].App.SetAdmin(ctx, w.Devices[target].ID, op.Admin)
			membership[w.Devices[target].ID] = op.Admin
		case "rejoin":
			target := 1 + op.Device%(len(w.Devices)-1)
			e = w.Devices[0].App.RemoveMember(ctx, w.Devices[target].ID)
			if e == nil {
				_, denied := w.Devices[target].App.ListSecrets(ctx, "default")
				if err := requireCode(denied, apperr.CodeNotMember); err != nil {
					return err
				}
				_, e = w.Devices[target].App.InitializeRepository(ctx, app.InitOptions{})
			}
			if e == nil {
				e = w.Devices[0].App.ApproveMember(ctx, w.Devices[target].ID)
			}
			membership[w.Devices[target].ID] = false
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
		if op.Kind == "role" || op.Kind == "rejoin" || op.Kind == "members" || op.Kind == "restart" {
			for _, device := range w.Devices {
				members, err := device.App.ListMembers(ctx)
				if err != nil {
					return err
				}
				actual := map[string]bool{}
				for _, member := range members {
					actual[member.DeviceID] = member.Admin
				}
				if !reflect.DeepEqual(actual, membership) {
					return &Violation{Kind: "membership/" + op.Kind, Detail: fmt.Errorf("got %v want %v", actual, membership)}
				}
			}
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

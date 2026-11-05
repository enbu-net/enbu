package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"math/rand/v2"
	"reflect"
)

type Action struct {
	Kind       string
	Device     int
	Key, Value string
}

func Generate(seed uint64, steps, devices int) []Action {
	r := rand.New(rand.NewPCG(seed, 0x4f504552))
	out := make([]Action, 0, steps)
	kinds := []string{"add", "edit", "delete", "import", "read", "sync", "restart", "pull", "history", "invalid"}
	for i := 0; i < steps; i++ {
		out = append(out, Action{Kind: kinds[r.IntN(len(kinds))], Device: r.IntN(devices), Key: fmt.Sprintf("K_%d", r.IntN(12)), Value: fmt.Sprintf("v_%d_%d", i, r.Uint64())})
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
		m := w.Model["default"]
		_, exists := m[op.Key]
		expected := ""
		var out any
		var e error
		switch op.Kind {
		case "add":
			e = a.AddSecret(ctx, "default", op.Key, op.Value)
			if exists {
				expected = string(apperr.CodeSecretExists)
			} else {
				m[op.Key] = op.Value
			}
		case "edit":
			e = a.EditSecret(ctx, "default", op.Key, op.Value)
			if !exists {
				expected = string(apperr.CodeSecretMissing)
			} else {
				m[op.Key] = op.Value
			}
		case "delete":
			e = a.DeleteSecret(ctx, "default", op.Key)
			delete(m, op.Key)
		case "import":
			out, e = a.ImportSecrets(ctx, "default", map[string]string{op.Key: op.Value}, true)
			m[op.Key] = op.Value
		case "read":
			out, e = a.ListSecrets(ctx, "default")
			if len(m) == 0 && e != nil {
				expected = string(apperr.CodeArtifactNotFound)
			}
		case "sync":
			e = a.SyncSecrets(ctx, "default")
			if len(m) == 0 && e != nil {
				expected = string(apperr.CodeArtifactNotFound)
			}
		case "restart":
			w.Restart(op.Device)
		case "pull":
			var data *app.PulledSecrets
			data, e = a.PullSecretsData(ctx, "default")
			out = data
			if e == nil {
				if !reflect.DeepEqual(data.Secrets, m) {
					return fmt.Errorf("pull reference mismatch")
				}
			} else if len(m) == 0 {
				expected = string(apperr.CodeArtifactNotFound)
			}
		case "history":
			out, e = a.ListHistory(ctx, "default")
			if len(m) == 0 && e != nil {
				expected = string(apperr.CodeArtifactNotFound)
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
		if e := w.Check(ctx, "default"); e != nil {
			return fmt.Errorf("after step %d %s: %w", step, op.Kind, e)
		}
	}
	return nil
}

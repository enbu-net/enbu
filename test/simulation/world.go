package simulation

import (
	"context"
	"errors"
	"fmt"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

type Device struct {
	App   *app.App
	Store *Store
	Keys  *Keys
	ID    string
}
type World struct {
	Tape      *Tape
	Scheduler *Scheduler
	Devices   []*Device
	Root      string
	Model     map[string]map[string]string
	tick, id  uint64
}

func NewWorld(root string, tape *Tape, n int) (*World, error) {
	w := &World{Tape: tape, Scheduler: NewScheduler(tape), Root: root, Model: map[string]map[string]string{"default": {}}}
	memory := storagetest.NewMemory()
	for i := 0; i < n; i++ {
		dir := filepath.Join(root, fmt.Sprintf("device-%d", i))
		if e := os.MkdirAll(dir, 0700); e != nil {
			return nil, e
		}
		k := &Keys{Tape: tape, Device: i}
		s := &Store{Store: memory, Tape: tape, Device: i}
		a := &app.App{Storage: s, Identities: k, RepositoryDir: dir, CheckpointDir: filepath.Join(dir, "checkpoints"), CacheDir: filepath.Join(dir, "cache"), StorageURL: "oci://simulation.invalid/workspace", RepoDetector: simulationRepo{}, TokenProvider: simulationToken{}}
		a.Runtime = &app.Runtime{LocalStateDir: filepath.Join(dir, "local"), Now: func() time.Time { w.tick++; return time.Unix(1700000000+int64(w.tick), 0) }, NewID: func() string {
			w.id++
			return fmt.Sprintf("%08x-0000-4000-8000-%012x", uint32(tape.Recording.Seed), w.id)
		}, Encrypt: func(p []byte, r []string) ([]byte, error) {
			var b []byte
			e := tape.Value("encrypt", []any{i, p, r}, func() (any, error) { return age.EncryptForPublicKeys(p, r) }, &b)
			return b, e
		}}
		w.Devices = append(w.Devices, &Device{App: a, Store: s, Keys: k})
	}
	return w, nil
}
func ErrorCode(e error) string {
	if e == nil {
		return ""
	}
	if errors.Is(e, ErrCrash) {
		return "crash"
	}
	var a *apperr.Error
	if errors.As(e, &a) {
		return string(a.Code())
	}
	if errors.Is(e, context.Canceled) {
		return "canceled"
	}
	return fmt.Sprintf("%T", e)
}
func (w *World) Observe(name string, input, output any, e error) error {
	if te := w.Tape.Observe("operation", []any{name, input}, []any{output, ErrorCode(e)}); te != nil {
		return fmt.Errorf("observing %s (operation error: %v): %w", name, e, te)
	}
	return e
}
func (w *World) Share(from int) error {
	c, e := config.LoadProjectFrom(w.Devices[from].App.RepositoryDir)
	if e != nil {
		return e
	}
	for i, d := range w.Devices {
		if i != from {
			if e := config.SaveProjectTo(d.App.RepositoryDir, c); e != nil {
				return e
			}
		}
	}
	return w.Tape.Observe("share-config", from, c)
}
func (w *World) Bootstrap(ctx context.Context) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	for i, d := range w.Devices {
		if i > 0 {
			if e := w.Share(0); e != nil {
				return e
			}
		}
		r, e := d.App.InitializeRepository(ctx)
		if e := w.Observe("init", i, r, e); e != nil {
			return e
		}
		if !r.KeyCreated {
			return fmt.Errorf("new device was not reported as newly created")
		}
		d.ID = r.DeviceID
		if i > 0 {
			if !r.Pending {
				return fmt.Errorf("unapproved device did not remain pending")
			}
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
				return fmt.Errorf("pending device could read: %v", err)
			}
			if err := requireCode(d.App.AddSecret(ctx, "default", "UNAPPROVED", "x"), apperr.CodeNotMember); err != nil {
				return err
			}
			e := w.Devices[0].App.ApproveMember(ctx, d.ID)
			if e := w.Observe("approve", i, nil, e); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w *World) Check(ctx context.Context, env string) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	want := w.Model[env]
	for i, d := range w.Devices {
		got, e := d.App.ListSecrets(ctx, env)
		if e != nil && len(want) == 0 && app.IsNotFoundError(e) {
			e = nil
			got = map[string]string{}
		}
		if e := w.Observe("check", []any{i, env, want}, got, e); e != nil {
			return e
		}
		if !reflect.DeepEqual(got, want) {
			kind := "model/" + env
			all := map[string]bool{}
			for key := range want {
				all[key] = true
			}
			for key := range got {
				all[key] = true
			}
			ordered := make([]string, 0, len(all))
			for key := range all {
				ordered = append(ordered, key)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				gv, gok := got[key]
				wv, wok := want[key]
				if gok != wok || gv != wv {
					kind += "/" + key
					break
				}
			}
			return &Violation{Kind: kind, Detail: fmt.Errorf("reference mismatch device %d env %s: got %v want %v", i, env, got, want)}
		}
	}
	return nil
}
func (w *World) runBatch(ctx context.Context, hold string, ops []func(int) error) ([]error, error) {
	jobs := make([]func(*Actor) error, len(ops))
	for i, op := range ops {
		jobs[i] = func(actor *Actor) error {
			w.Devices[i].Store.Actor = actor
			defer func() { w.Devices[i].Store.Actor = nil }()
			return op(i)
		}
	}
	w.Scheduler.Hold = hold
	results, e := w.Scheduler.Run(ctx, jobs)
	if e != nil {
		return nil, e
	}
	for i, e := range results {
		if te := w.Tape.Observe("batch-result", i, ErrorCode(e)); te != nil {
			return nil, te
		}
	}
	return results, nil
}
func (w *World) Batch(ctx context.Context, hold string, ops []func(int) error) error {
	results, e := w.runBatch(ctx, hold, ops)
	if e != nil {
		return e
	}
	for i, e := range results {
		if e != nil {
			return fmt.Errorf("actor %d: %w", i, e)
		}
	}
	return nil
}
func clone(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
func (w *World) Restart(i int) { d := w.Devices[i]; a := *d.App; d.App = &a }

type simulationRepo struct{}

func (simulationRepo) LoadRepo() (string, string, error) { return "team", "workspace", nil }

type simulationToken struct{}

func (simulationToken) LoadToken() (string, string, error) {
	return "synthetic-token", "simulation", nil
}

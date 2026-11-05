package simulation

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/wsp"
	"reflect"
)

// Probe explores a failure at one exact external call of a public operation.
// Both sides of an ambiguous commit are allowed before recovery; losing any
// other acknowledged data is never allowed.
type Probe struct {
	Operation string
	Fault     Fault
}

var ProbeOperations = []string{"add", "edit", "delete", "import", "sync", "pull", "history", "diff", "restore", "compact", "purge", "approve", "remove", "admin", "upgrade"}

func (w *World) Probe(ctx context.Context, p Probe) (map[string]int, error) {
	ctx = wsp.WithSerialHeadReads(ctx)
	a := w.Devices[0].App
	store := w.Devices[0].Store
	if e := a.AddSecret(ctx, "default", "BASE", "original"); e != nil {
		return nil, e
	}
	if e := a.EditSecret(ctx, "default", "BASE", "latest"); e != nil {
		return nil, e
	}
	before := map[string]string{"BASE": "latest"}
	after := clone(before)
	switch p.Operation {
	case "add", "import":
		after["NEXT"] = "new"
	case "edit":
		after["BASE"] = "edited"
	case "delete":
		delete(after, "BASE")
	case "restore":
		after["BASE"] = "original"
	}
	if p.Operation == "approve" {
		if e := a.RemoveMember(ctx, w.Devices[1].ID); e != nil {
			return nil, e
		}
		if _, e := w.Devices[1].App.InitializeRepository(ctx); e != nil {
			return nil, e
		}
	}
	if p.Operation == "purge" {
		if e := a.CreateEnvironment("temporary"); e != nil {
			return nil, e
		}
		if e := a.AddSecret(ctx, "temporary", "TEMP", "x"); e != nil {
			return nil, e
		}
		if e := a.SwitchEnvironment("default"); e != nil {
			return nil, e
		}
	}
	invoke := func() error {
		switch p.Operation {
		case "add":
			return a.AddSecret(ctx, "default", "NEXT", "new")
		case "edit":
			return a.EditSecret(ctx, "default", "BASE", "edited")
		case "delete":
			return a.DeleteSecret(ctx, "default", "BASE")
		case "import":
			_, e := a.ImportSecrets(ctx, "default", map[string]string{"NEXT": "new"}, true)
			return e
		case "sync":
			return a.SyncSecrets(ctx, "default")
		case "pull":
			_, e := a.PullSecretsData(ctx, "default")
			return e
		case "history":
			_, e := a.ListHistory(ctx, "default")
			return e
		case "diff":
			_, e := a.DiffHistory(ctx, "default", 1, 2)
			return e
		case "restore":
			return a.RestoreHistory(ctx, "default", 1)
		case "compact":
			_, e := a.CompactHistory(ctx, "default", 1)
			return e
		case "purge":
			_, e := a.DeleteEnvironmentPurging(ctx, "temporary")
			return e
		case "approve":
			return a.ApproveMember(ctx, w.Devices[1].ID)
		case "remove":
			return a.RemoveMember(ctx, w.Devices[1].ID)
		case "admin":
			return a.SetAdmin(ctx, w.Devices[1].ID, true)
		case "upgrade":
			_, e := a.UpgradeIdentity(ctx)
			return e
		default:
			return fmt.Errorf("unknown probe %s", p.Operation)
		}
	}
	store.Arm(p.Fault)
	result := catchCrash(invoke)
	if p.Fault.Method == "" && result != nil {
		return nil, fmt.Errorf("baseline %s: %w", p.Operation, result)
	}
	counts := map[string]int{}
	for method, n := range store.calls {
		counts[method] = n
	}
	if e := w.Tape.Observe("probe-result", p, ErrorCode(result)); e != nil {
		return nil, e
	}
	store.Arm(Fault{})
	if result == ErrCrash {
		w.Restart(0)
		a = w.Devices[0].App
	}
	if p.Fault.Method != "" && counts[p.Fault.Method] < p.Fault.At {
		return nil, fmt.Errorf("unreached fault: %+v calls %v", p, counts)
	}
	got, e := a.ListSecrets(ctx, "default")
	if e != nil {
		return nil, e
	}
	if err := w.Tape.Observe("probe-state", []any{before, after}, got); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
		return nil, fmt.Errorf("partial or lost acknowledged state after %+v: %v", p, got)
	}
	if result == nil && !reflect.DeepEqual(got, after) {
		return nil, fmt.Errorf("successful operation lost its effect: %+v", p)
	}
	// Retry only when the durable state says the effect has not committed.
	retry := !reflect.DeepEqual(got, after)
	switch p.Operation {
	case "approve", "remove", "admin", "upgrade":
		members, e := a.ListMembers(ctx)
		if e != nil {
			return nil, e
		}
		present, admin, pq := false, false, false
		for _, m := range members {
			if m.DeviceID == w.Devices[1].ID {
				present, admin = true, m.Admin
			}
			if m.DeviceID == w.Devices[0].ID {
				pq = age.IsPostQuantum(m.Recipient)
			}
		}
		switch p.Operation {
		case "approve":
			retry = !present
		case "remove":
			retry = present
		case "admin":
			retry = !admin
		case "upgrade":
			retry = !pq
		}
	case "purge":
		envs, e := a.ListEnvironments()
		if e != nil {
			return nil, e
		}
		for _, env := range envs {
			if env.Name == "temporary" {
				retry = true
			}
		}
	case "compact", "pull", "history", "diff", "sync":
		retry = result != nil
	}
	if result == nil && retry {
		return nil, fmt.Errorf("acknowledged %s had no durable effect", p.Operation)
	}
	if retry {
		if e := invoke(); e != nil {
			return nil, fmt.Errorf("recovery %+v: %w", p, e)
		}
	}
	if e := a.SyncSecrets(ctx, "default"); e != nil {
		return nil, e
	}
	if p.Operation == "remove" {
		if _, e := w.Devices[1].App.InitializeRepository(ctx); e != nil {
			return nil, e
		}
		if e := a.ApproveMember(ctx, w.Devices[1].ID); e != nil {
			return nil, e
		}
	}
	w.Model["default"] = after
	if e := w.Share(0); e != nil {
		return nil, e
	}
	if e := w.Check(ctx, "default"); e != nil {
		return nil, e
	}
	return counts, nil
}

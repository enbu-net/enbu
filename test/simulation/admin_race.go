package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

var AdminRaces = []string{"approve-two", "remove-two", "remove-versus-promote", "promote-two", "demote-admin", "remove-admin", "approve-same", "remove-same", "promote-versus-demote", "remove-versus-key-update"}

func (w *World) AdminRace(ctx context.Context, kind string) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	a, b := w.Devices[0].App, w.Devices[1].App
	if err := a.AddSecret(ctx, "default", "ACKNOWLEDGED", "kept"); err != nil {
		return err
	}
	w.Model["default"]["ACKNOWLEDGED"] = "kept"
	if err := a.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	expected := map[string]bool{}
	for i, d := range w.Devices {
		expected[d.ID] = i < 2
	}
	if kind == "promote-versus-demote" {
		if err := a.SetAdmin(ctx, w.Devices[2].ID, true); err != nil {
			return err
		}
	}
	if kind == "remove-versus-key-update" {
		if _, err := w.Devices[2].App.UpgradeIdentity(ctx); err != nil {
			return err
		}
	}
	if kind == "approve-two" || kind == "approve-same" {
		targets := []int{3, 4}
		if kind == "approve-same" {
			targets = []int{3}
		}
		for _, i := range targets {
			if err := a.RemoveMember(ctx, w.Devices[i].ID); err != nil {
				return err
			}
			if _, err := w.Devices[i].App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
				return err
			}
			delete(expected, w.Devices[i].ID)
		}
	}
	var left, right func(int) error
	switch kind {
	case "approve-two":
		left = func(int) error { return a.ApproveMember(ctx, w.Devices[3].ID) }
		right = func(int) error { return b.ApproveMember(ctx, w.Devices[4].ID) }
	case "approve-same":
		left = func(int) error { return a.ApproveMember(ctx, w.Devices[3].ID) }
		right = func(int) error { return b.ApproveMember(ctx, w.Devices[3].ID) }
		expected[w.Devices[3].ID] = false
	case "remove-same":
		left = func(int) error { return a.RemoveMember(ctx, w.Devices[2].ID) }
		right = func(int) error { return b.RemoveMember(ctx, w.Devices[2].ID) }
		delete(expected, w.Devices[2].ID)
	case "promote-versus-demote":
		left = func(int) error { return a.SetAdmin(ctx, w.Devices[2].ID, false) }
		right = func(int) error { return b.SetAdmin(ctx, w.Devices[2].ID, true) }
	case "remove-versus-key-update":
		left = func(int) error { return a.RemoveMember(ctx, w.Devices[2].ID) }
		right = func(int) error { return b.ApproveMember(ctx, w.Devices[2].ID) }
		delete(expected, w.Devices[2].ID)
	case "remove-two":
		left = func(int) error { return a.RemoveMember(ctx, w.Devices[2].ID) }
		right = func(int) error { return b.RemoveMember(ctx, w.Devices[3].ID) }
		delete(expected, w.Devices[2].ID)
		delete(expected, w.Devices[3].ID)
	case "remove-versus-promote":
		left = func(int) error { return a.RemoveMember(ctx, w.Devices[2].ID) }
		right = func(int) error { return b.SetAdmin(ctx, w.Devices[2].ID, true) }
		delete(expected, w.Devices[2].ID)
	case "promote-two":
		left = func(int) error { return a.SetAdmin(ctx, w.Devices[2].ID, true) }
		right = func(int) error { return b.SetAdmin(ctx, w.Devices[3].ID, true) }
	case "demote-admin":
		left = func(int) error { return a.SetAdmin(ctx, w.Devices[1].ID, false) }
		right = func(int) error { return b.SetAdmin(ctx, w.Devices[2].ID, true) }
		expected[w.Devices[1].ID] = false
	case "remove-admin":
		left = func(int) error { return a.RemoveMember(ctx, w.Devices[1].ID) }
		right = func(int) error { return b.SetAdmin(ctx, w.Devices[2].ID, true) }
		delete(expected, w.Devices[1].ID)
	default:
		return fmt.Errorf("unknown admin race %s", kind)
	}
	results, err := w.runBatch(ctx, "publish", []func(int) error{left, right})
	if err != nil {
		return err
	}
	for _, result := range results {
		code := ErrorCode(result)
		if code != "" && code != string(apperr.CodeControlForked) && code != string(apperr.CodeReencryptIncomplete) {
			return fmt.Errorf("admin race %s: %w", kind, result)
		}
	}
	for _, d := range w.Devices {
		if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeControlForked) != nil {
			return fmt.Errorf("fork did not stop reads: %v", err)
		}
		if err := requireCode(d.App.AddSecret(ctx, "default", "FORBIDDEN", "x"), apperr.CodeControlForked); err != nil {
			return err
		}
	}
	if kind == "demote-admin" || kind == "remove-admin" {
		if err := requireCode(b.ResolveControlFork(ctx), apperr.CodeAccessDenied); err != nil {
			return err
		}
	}
	if err := a.ResolveControlFork(ctx); err != nil {
		return err
	}
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, m := range members {
		actual[m.DeviceID] = m.Admin
	}
	if err := w.Tape.Observe("admin-race", []any{kind, expected}, actual); err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("fork resolution expanded membership or privilege: got %v want %v", actual, expected)
	}
	for _, d := range w.Devices {
		if _, ok := expected[d.ID]; !ok {
			if err := requireCode(d.App.AddSecret(ctx, "default", "REMOVED", "x"), apperr.CodeNotMember); err != nil {
				return err
			}
			if _, err := d.App.InitializeRepository(ctx, app.InitOptions{}); err != nil {
				return err
			}
			if err := a.ApproveMember(ctx, d.ID); err != nil {
				return err
			}
		}
	}
	return w.Check(ctx, "default")
}

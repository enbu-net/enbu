package simulation

import (
	"context"
	"fmt"
	"reflect"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
)

type TeamCase struct{ Control, Write string }

var TeamWrites = []string{"add", "edit", "delete", "import", "sync"}

var TeamControls = []string{"approve-joiner", "remove-other", "remove-writer", "promote-other", "demote-writer", "approve-key-update"}

// TeamCase overlaps membership administration with a separate member's write.
// Revocation can discard an unaccepted old-control branch; it cannot discard
// unrelated accepted data or authorize any new write by the removed device.
func (w *World) TeamCase(ctx context.Context, c TeamCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	a, b := w.Devices[0].App, w.Devices[1].App
	before := map[string]string{"BASE": "original", "UNRELATED": "acknowledged"}
	if _, err := a.ImportSecrets(ctx, "default", before, true); err != nil {
		return err
	}
	w.Model["default"] = clone(before)
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	switch c.Control {
	case "approve-joiner":
		if err := a.RemoveMember(ctx, w.Devices[3].ID); err != nil {
			return err
		}
		if _, err := w.Devices[3].App.InitializeRepository(ctx); err != nil {
			return err
		}
	case "demote-writer":
		if err := a.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
			return err
		}
	case "approve-key-update":
		if _, err := b.UpgradeIdentity(ctx); err != nil {
			return err
		}
	}
	control := func(int) error {
		switch c.Control {
		case "approve-joiner":
			return a.ApproveMember(ctx, w.Devices[3].ID)
		case "remove-other":
			return a.RemoveMember(ctx, w.Devices[2].ID)
		case "remove-writer":
			return a.RemoveMember(ctx, w.Devices[1].ID)
		case "promote-other":
			return a.SetAdmin(ctx, w.Devices[2].ID, true)
		case "demote-writer":
			return a.SetAdmin(ctx, w.Devices[1].ID, false)
		case "approve-key-update":
			return a.ApproveMember(ctx, w.Devices[1].ID)
		default:
			return fmt.Errorf("unknown team control %s", c.Control)
		}
	}
	after := clone(before)
	write := func(int) error {
		switch c.Write {
		case "add":
			return b.AddSecret(ctx, "default", "NEW", "changed")
		case "edit":
			return b.EditSecret(ctx, "default", "BASE", "changed")
		case "delete":
			return b.DeleteSecret(ctx, "default", "BASE")
		case "import":
			_, err := b.ImportSecrets(ctx, "default", map[string]string{"BASE": "changed"}, true)
			return err
		case "sync":
			return b.SyncSecrets(ctx, "default")
		default:
			return fmt.Errorf("unknown team write %s", c.Write)
		}
	}
	switch c.Write {
	case "add":
		after["NEW"] = "changed"
	case "edit", "import":
		after["BASE"] = "changed"
	case "delete":
		delete(after, "BASE")
	}
	results, err := w.runBatch(ctx, "publish", []func(int) error{control, write})
	if err != nil {
		return err
	}
	if results[0] != nil {
		return fmt.Errorf("team control %+v: %w", c, results[0])
	}
	if results[1] != nil && (c.Control != "remove-writer" || ErrorCode(results[1]) != string(apperr.CodeNotMember)) {
		return fmt.Errorf("team writer %+v: %w", c, results[1])
	}
	removed := -1
	switch c.Control {
	case "remove-writer":
		removed = 1
	case "remove-other":
		removed = 2
	}
	if removed >= 0 {
		if err := requireCode(w.Devices[removed].App.AddSecret(ctx, "default", "UNAUTHORIZED", "x"), apperr.CodeNotMember); err != nil {
			return err
		}
		if _, err := w.Devices[removed].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("removed device can still read: %v", err)
		}
	}
	got, err := a.ListSecrets(ctx, "default")
	if err != nil {
		return err
	}
	want := after
	if c.Control == "remove-writer" {
		if !reflect.DeepEqual(got, before) && !reflect.DeepEqual(got, after) {
			return fmt.Errorf("revocation lost unrelated state: got %v", got)
		}
		want = clone(got)
	} else if !reflect.DeepEqual(got, after) {
		return fmt.Errorf("membership race lost acknowledged write: got %v want %v", got, after)
	}
	if err := w.Tape.Observe("team-result", []any{c, before, after}, []any{got, ErrorCode(results[1])}); err != nil {
		return err
	}
	w.Model["default"] = want
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	actual := map[string]bool{}
	for _, member := range members {
		actual[member.DeviceID] = member.Admin
	}
	expected := map[string]bool{}
	for i, d := range w.Devices {
		if i != removed {
			expected[d.ID] = i == 0 || (i == 2 && c.Control == "promote-other")
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("team membership: got %v want %v", actual, expected)
	}
	if removed >= 0 {
		if _, err := w.Devices[removed].App.InitializeRepository(ctx); err != nil {
			return err
		}
		if err := a.ApproveMember(ctx, w.Devices[removed].ID); err != nil {
			return err
		}
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		if err := w.Devices[removed].App.AddSecret(ctx, "default", "AFTER_READMISSION", "new-control"); err != nil {
			return err
		}
		w.Model["default"]["AFTER_READMISSION"] = "new-control"
	}
	return w.Check(ctx, "default")
}

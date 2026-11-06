package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// RequestFlood makes untrusted Discover claim more requests than the protocol
// permits. The refs need not exist: even fetching nonexistent garbage is work.
func (w *World) RequestFlood(ctx context.Context) error {
	admin := w.Devices[0].App
	target := len(w.Devices) - 1
	if err := admin.RemoveMember(ctx, w.Devices[target].ID); err != nil {
		return err
	}
	result, err := w.Devices[target].App.InitializeRepository(ctx)
	if err != nil {
		return err
	}
	if !result.Pending {
		return fmt.Errorf("removed device did not require readmission")
	}
	before, err := admin.ListMembers(ctx)
	if err != nil {
		return err
	}
	refs := make([]digest.Digest, 10001)
	for i := range refs {
		refs[i] = digest.FromString(fmt.Sprintf("attacker-request-%d", i))
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	requestReads := 0
	base := w.Devices[0].Store.Store
	attacked := storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindRequest {
				return refs, nil
			}
			return next.Discover(ctx, kind, scope)
		},
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if kind == storage.KindRequest {
				requestReads++
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
	})
	for _, d := range w.Devices {
		d.Store.Store = attacked
	}
	path := filepath.Join(w.Devices[target].App.RepositoryDir, ".env")
	local := []byte("LOCAL_ONLY=personal\nBASE=before-flood\n")
	if err := os.WriteFile(path, local, 0600); err != nil {
		return err
	}
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"list", func() error { _, err := admin.ListJoinRequests(ctx); return err }},
		{"approve", func() error { return admin.ApproveMember(ctx, w.Devices[target].ID) }},
		{"rejoin", func() error { _, err := w.Devices[target].App.InitializeRepository(ctx); return err }},
	} {
		err := op.run()
		if requireCode(err, apperr.CodeUntrusted) != nil || !errors.Is(err, wsp.ErrInvalid) {
			return fmt.Errorf("request flood %s bypassed work limit: %v", op.name, err)
		}
		if err := w.Tape.Observe("request-flood-denial", op.name, ErrorCode(err)); err != nil {
			return err
		}
	}
	if requestReads != 0 {
		return fmt.Errorf("request flood fetched %d attacker objects", requestReads)
	}
	after, err := admin.ListMembers(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("request flood changed membership")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(got) != string(local) {
		return fmt.Errorf("rejected rejoin modified local secrets")
	}
	if _, err := w.Devices[target].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("request flood implicitly readmitted attacker: %v", err)
	}
	// Only membership discovery is refused: acknowledged team work remains usable.
	if err := admin.EditSecret(ctx, "default", "BASE", "teammate-during-flood"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "teammate-during-flood"
	for i, d := range w.Devices {
		if i == target {
			continue
		}
		secrets, err := d.App.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(secrets, w.Model["default"]) {
			return fmt.Errorf("flood interrupted continuing member %d: %v", i, err)
		}
	}
	// Once the operator removes the malicious listing, explicit approval must
	// resume with the genuine request and preserve the teammate's newer state.
	for _, d := range w.Devices {
		d.Store.Store = base
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[target].ID); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Devices[target].App.PullSecretsToFile(ctx, "default"); err != nil {
		return err
	}
	expected := clone(w.Model["default"])
	expected["LOCAL_ONLY"] = "personal"
	return w.checkOutput("request-flood-recovery", path, expected)
}

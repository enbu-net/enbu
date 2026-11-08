package simulation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
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
	result, err := w.Devices[target].App.InitializeRepository(ctx, app.InitOptions{})
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
		{"rejoin", func() error { _, err := w.Devices[target].App.InitializeRepository(ctx, app.InitOptions{}); return err }},
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

// HiddenRequestConflict puts the target's second valid request just outside the
// display window. Discovery order is not authority and need not be sorted.
func (w *World) HiddenRequestConflict(ctx context.Context) error {
	target := len(w.Devices) - 1
	admin := w.Devices[0].App
	if err := admin.RemoveMember(ctx, w.Devices[target].ID); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(admin.RepositoryDir)
	if err != nil {
		return err
	}
	signer, err := w.Devices[target].Keys.Signer(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	current, err := w.Devices[target].Keys.Info(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	firstBlob, err := wsp.NewJoinRequest(cfg.WorkspaceID, current.Recipient, w.Devices[target].App.Runtime.Clock.Now(), signer)
	if err != nil {
		return err
	}
	first, err := wsp.PublishJoinRequest(ctx, w.Devices[0].Store, firstBlob)
	if err != nil {
		return err
	}
	ordered := []digest.Digest{first}
	spammer := &Keys{Tape: w.Tape, Device: len(w.Devices)}
	if _, _, _, err := spammer.Create(cfg.WorkspaceID); err != nil {
		return err
	}
	spamSigner, err := spammer.Signer(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = spamSigner.Close() }()
	// These are genuine, distinct, self-signed requests of another non-member.
	// They fill the display window without adding another request of the target.
	for i := 0; i < 255; i++ {
		id, info, _, err := spammer.Create(fmt.Sprintf("%s/filler-%d", cfg.WorkspaceID, i))
		if err != nil {
			return err
		}
		_ = id.Close()
		blob, err := wsp.NewJoinRequest(cfg.WorkspaceID, info.Recipient, w.Devices[target].App.Runtime.Clock.Now(), spamSigner)
		if err != nil {
			return err
		}
		rev, err := wsp.PublishJoinRequest(ctx, w.Devices[0].Store, blob)
		if err != nil {
			return err
		}
		ordered = append(ordered, rev)
	}
	alternate, info, _, err := spammer.Create(cfg.WorkspaceID + "/target-alternate")
	if err != nil {
		return err
	}
	_ = alternate.Close()
	secondBlob, err := wsp.NewJoinRequest(cfg.WorkspaceID, info.Recipient, w.Devices[target].App.Runtime.Clock.Now(), signer)
	if err != nil {
		return err
	}
	second, err := wsp.PublishJoinRequest(ctx, w.Devices[0].Store, secondBlob)
	if err != nil {
		return err
	}
	ordered = append(ordered, second)
	base := w.Devices[0].Store.Store
	reordered := storagetest.Wrap(base, storagetest.Hooks{Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
		if kind == storage.KindRequest {
			return append([]digest.Digest(nil), ordered...), nil
		}
		return next.Discover(ctx, kind, scope)
	}})
	for _, d := range w.Devices {
		d.Store.Store = reordered
	}
	before, err := admin.ListMembers(ctx)
	if err != nil {
		return err
	}
	visible, err := admin.ListJoinRequests(ctx)
	if err != nil || len(visible) != 256 {
		return fmt.Errorf("request display window = %d: %v", len(visible), err)
	}
	for _, request := range visible {
		if request.DeviceID == w.Devices[target].ID && request.Recipient == info.Recipient {
			return fmt.Errorf("conflicting request fixture was not hidden")
		}
	}
	if err := requireCode(admin.ApproveMember(ctx, w.Devices[target].ID), apperr.CodeInvalidArgument); err != nil {
		return fmt.Errorf("approval ignored undisplayed conflict: %w", err)
	}
	after, err := admin.ListMembers(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("ambiguous approval changed membership: %v", err)
	}
	if _, err := w.Devices[target].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("hidden conflict implicitly admitted device: %v", err)
	}
	if err := admin.EditSecret(ctx, "default", "BASE", "teammate-during-conflict"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "teammate-during-conflict"
	// Resolve explicitly by removing the conflicting request and the filler
	// objects, not by picking whichever request a registry lists first.
	for _, d := range w.Devices {
		d.Store.Store = base
	}
	for _, rev := range ordered[1:] {
		if err := w.Devices[0].Store.Delete(ctx, storage.KindRequest, "", rev); err != nil {
			return err
		}
	}
	if err := admin.ApproveMember(ctx, w.Devices[target].ID); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	return w.Check(ctx, "default")
}

package simulation

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

func firstContactPins(d *Device, workspace string, want wsp.Root) error {
	path, err := config.ProjectConfigPathFrom(d.App.RepositoryDir)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, pin := range []*wsp.TrustRoot{
		wsp.OpenTrustRoot(d.App.CheckpointDir, workspace, d.App.Runtime.Clock),
		wsp.OpenRepositoryTrustRoot(d.App.CheckpointDir, path, d.App.Runtime.Clock),
	} {
		got, err := pin.Pinned()
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("unexpected first-contact pin: got %v want %v", got, want)
		}
	}
	return nil
}

// The last three devices are two first-time joiners and an attacker. Expected
// roots/fingerprints represent independent out-of-band information, not a UI
// confirmation or a claim that TOFU authenticates a malicious first invitation.
func (w *World) FirstContact(ctx context.Context, cold bool) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	team := len(w.Devices) - 3
	if team < 2 {
		return fmt.Errorf("first contact needs a team, two joiners and an attacker")
	}
	all := w.Devices
	w.Devices = all[:team]
	err := w.Bootstrap(ctx)
	w.Devices = all
	if err != nil {
		return err
	}
	honest := *w
	honest.Devices = all[:team]
	admin := w.Devices[0]
	if _, err := admin.App.ImportSecrets(ctx, "default", map[string]string{"BASE": "team-before-join", "TEAM_ONLY": "acknowledged"}, true); err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"BASE": "team-before-join", "TEAM_ONLY": "acknowledged"}
	if err := honest.Check(ctx, "default"); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(admin.App.RepositoryDir)
	if err != nil {
		return err
	}
	goodRoot := wsp.Root{Workspace: cfg.WorkspaceID, Genesis: digest.Digest(cfg.ControlGenesis)}
	if err := w.Tape.Observe("independent-invitation-root", nil, goodRoot); err != nil {
		return err
	}
	verified, fooled, attacker := team, team+1, team+2
	legitimate := admin.Store.Store
	malicious := storagetest.NewMemory()
	adversary := w.Devices[attacker]
	adversary.Store.Store = malicious
	key, _, _, err := adversary.Keys.Create(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()
	signer, err := adversary.Keys.Signer(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	genesis, root, err := wsp.NewGenesis(cfg.WorkspaceID, wsp.Principal{ID: signer.Public().DeviceID(), Signing: signer.Public(), Recipient: key.Identity.Recipient().String(), Admin: true}, signer)
	if err != nil {
		return err
	}
	badRoot := wsp.Root{Workspace: cfg.WorkspaceID, Genesis: root}
	if badRoot == goodRoot {
		return fmt.Errorf("attacker did not create an independent root")
	}
	if err := adversary.Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: root, Head: genesis}); err != nil {
		return err
	}
	badConfig := *cfg
	badConfig.ControlGenesis = string(root)
	if err := config.SaveProjectTo(adversary.App.RepositoryDir, &badConfig); err != nil {
		return err
	}
	r, err := adversary.App.InitializeRepository(ctx)
	if err != nil || r == nil || r.Pending || r.ControlGenesis != string(root) {
		return fmt.Errorf("attacker initialization: %v", err)
	}
	adversary.ID = r.DeviceID
	bait := map[string]string{"ATTACKER_BAIT": "unverified-invitation"}
	if _, err := adversary.App.ImportSecrets(ctx, "default", bait, true); err != nil {
		return err
	}
	restart := func(index int) error {
		if cold {
			if err := os.RemoveAll(w.Devices[index].App.CacheDir); err != nil {
				return err
			}
		}
		w.Restart(index)
		return nil
	}
	// Correct bootstrap information must not follow a storage-discovered root,
	// or accept its signed bytes under the independently expected digest.
	newcomer := w.Devices[verified]
	newcomer.Store.Store = malicious
	if err := config.SaveProjectTo(newcomer.App.RepositoryDir, cfg); err != nil {
		return err
	}
	var firstID, firstRecipient string
	for _, substitution := range []bool{false, true} {
		newcomer.Store.Store = malicious
		code := apperr.CodeIncompatibleStorage
		if substitution {
			code = apperr.CodeUntrusted
			newcomer.Store.Store = storagetest.Wrap(malicious, storagetest.Hooks{
				Discover: func(c context.Context, next storage.Store, k storage.Kind, scope string) ([]digest.Digest, error) {
					refs, err := next.Discover(c, k, scope)
					if err == nil && k == storage.KindControl {
						refs = append(refs, goodRoot.Genesis)
					}
					return refs, err
				},
				FetchHead: func(c context.Context, next storage.Store, k storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
					if k == storage.KindControl && rev == goodRoot.Genesis {
						return slices.Clone(genesis), nil
					}
					return next.FetchHead(c, k, scope, rev)
				},
			})
		}
		if err := restart(verified); err != nil {
			return err
		}
		newcomer = w.Devices[verified]
		start := len(w.Tape.Recording.Entries)
		result, err := newcomer.App.InitializeRepository(ctx)
		if e := requireCode(err, code); e != nil || result != nil {
			return fmt.Errorf("verified invitation accepted substituted genesis: %v", err)
		}
		if err := requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:]); err != nil {
			return err
		}
		if err := firstContactPins(newcomer, cfg.WorkspaceID, wsp.Root{}); err != nil {
			return err
		}
		info, err := newcomer.Keys.Info(cfg.WorkspaceID)
		if err != nil {
			return err
		}
		signer, err := newcomer.Keys.Signer(cfg.WorkspaceID)
		if err != nil {
			return err
		}
		id := string(signer.Public().DeviceID())
		_ = signer.Close()
		if firstID == "" {
			firstID, firstRecipient = id, info.Recipient
		}
		if id != firstID || info.Recipient != firstRecipient {
			return fmt.Errorf("failed first contact regenerated device keys")
		}
	}
	newcomer.Store.Store = legitimate
	r, err = newcomer.App.InitializeRepository(ctx)
	if err != nil || r == nil || !r.Pending || r.Founded || r.KeyCreated || r.ControlGenesis != cfg.ControlGenesis || r.ReplacedGenesis != "" || r.DeviceID != firstID || r.PublicKey != firstRecipient {
		return fmt.Errorf("verified newcomer recovery: %v", err)
	}
	newcomer.ID = r.DeviceID
	if err := firstContactPins(newcomer, cfg.WorkspaceID, goodRoot); err != nil {
		return err
	}
	// A malicious but internally valid first invitation is trusted by TOFU.
	// No protocol oracle may pretend to know the independent correct root.
	victim := w.Devices[fooled]
	victim.Store.Store = malicious
	if err := config.SaveProjectTo(victim.App.RepositoryDir, &badConfig); err != nil {
		return err
	}
	r, err = victim.App.InitializeRepository(ctx)
	if err != nil || r == nil || !r.Pending || r.ControlGenesis != string(root) {
		return fmt.Errorf("malicious first-invitation contract: %v", err)
	}
	victim.ID = r.DeviceID
	if err := firstContactPins(victim, cfg.WorkspaceID, badRoot); err != nil {
		return err
	}
	if err := adversary.App.ApproveMember(ctx, victim.ID); err != nil {
		return err
	}
	if err := adversary.App.SetAdmin(ctx, victim.ID, true); err != nil {
		return err
	}
	if err := victim.App.SetAdmin(ctx, adversary.ID, false); err != nil {
		return fmt.Errorf("foreign-root admin fixture has no real authority: %w", err)
	}
	if err := victim.App.AddSecret(ctx, "default", "POISON", "foreign-root-publication"); err != nil {
		return err
	}
	bait["POISON"] = "foreign-root-publication"
	got, err := victim.App.ListSecrets(ctx, "default")
	if err != nil || !reflect.DeepEqual(got, bait) {
		return fmt.Errorf("TOFU did not expose the attacker-authorized snapshot: %v", err)
	}
	if err := restart(fooled); err != nil {
		return err
	}
	victim = w.Devices[fooled]
	victim.Store.Store = legitimate
	if err := config.SaveProjectTo(victim.App.RepositoryDir, cfg); err != nil {
		return err
	}
	start := len(w.Tape.Recording.Entries)
	r, err = victim.App.InitializeRepository(ctx)
	if e := requireCode(err, apperr.CodeTrustRootChanged); e != nil || r != nil {
		return fmt.Errorf("correcting an unverified invitation silently replaced its pin: %v", err)
	}
	if got, err := victim.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeTrustRootChanged) != nil || got != nil {
		return fmt.Errorf("unconfirmed root correction returned secrets: %v", err)
	}
	if err := requireCode(victim.App.AddSecret(ctx, "default", "MUST_NOT_WRITE", "first-contact-canary"), apperr.CodeTrustRootChanged); err != nil {
		return err
	}
	// Pin rejects again later during acceptance. Requiring only its final
	// error would miss fetching the new root before the local trust check.
	for _, entry := range w.Tape.Recording.Entries[start:] {
		if entry.Kind == "storage-request" {
			return fmt.Errorf("root correction contacted storage before local confirmation")
		}
	}
	if err := firstContactPins(victim, cfg.WorkspaceID, badRoot); err != nil {
		return err
	}
	// Explicit root confirmation changes trust, never membership. Old authority
	// at the attacker's root cannot approve access to the legitimate team.
	victim.App.AcceptNewGenesis = true
	r, err = victim.App.InitializeRepository(ctx)
	if err != nil || r == nil || !r.Pending || r.ReplacedGenesis != string(root) || r.DeviceID != victim.ID {
		return fmt.Errorf("explicit invitation repair: %v", err)
	}
	if err := firstContactPins(victim, cfg.WorkspaceID, goodRoot); err != nil {
		return err
	}
	if err := restart(fooled); err != nil {
		return err
	}
	pending := func(index int) error {
		d := w.Devices[index]
		start := len(w.Tape.Recording.Entries)
		got, err := d.App.ListSecrets(ctx, "default")
		if requireCode(err, apperr.CodeNotMember) != nil || got != nil {
			return fmt.Errorf("unapproved first-contact device read secrets: %v", err)
		}
		if err := requireCode(d.App.AddSecret(ctx, "default", "MUST_NOT_WRITE", "unapproved-canary"), apperr.CodeNotMember); err != nil {
			return err
		}
		if err := requireCode(d.App.SyncSecrets(ctx, "default"), apperr.CodeNotMember); err != nil {
			return err
		}
		return requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:])
	}
	if err := pending(verified); err != nil {
		return err
	}
	if err := pending(fooled); err != nil {
		return err
	}
	requests, err := admin.App.ListJoinRequests(ctx)
	if err != nil || len(requests) != 2 {
		return fmt.Errorf("unexpected first-contact requests: %d %v", len(requests), err)
	}
	for _, index := range []int{verified, fooled} {
		d := w.Devices[index]
		key, err := d.Keys.Load(cfg.WorkspaceID)
		if err != nil {
			return err
		}
		id := key.Signer.Public().DeviceID()
		recipient := key.Identity.Recipient().String()
		_ = key.Close()
		found := false
		for _, request := range requests {
			if request.DeviceID == string(id) {
				if request.Fingerprint != id.Fingerprint() || request.Recipient != recipient {
					return fmt.Errorf("request did not match independently known identity")
				}
				found = true
			}
		}
		if !found || d.ID != string(id) {
			return fmt.Errorf("expected first-contact identity missing")
		}
	}
	if err := admin.App.ApproveMember(ctx, w.Devices[verified].ID); err != nil {
		return err
	}
	if err := pending(fooled); err != nil {
		return err
	}
	if _, err := w.Devices[1].App.ImportSecrets(ctx, "default", map[string]string{"BASE": "peer-during-onboarding", "PEER_ACK": "retained"}, true); err != nil {
		return err
	}
	w.Model["default"]["BASE"], w.Model["default"]["PEER_ACK"] = "peer-during-onboarding", "retained"
	if err := w.Devices[verified].App.AddSecret(ctx, "default", "VERIFIED_JOINER", "acknowledged"); err != nil {
		return err
	}
	w.Model["default"]["VERIFIED_JOINER"] = "acknowledged"
	if err := admin.App.ApproveMember(ctx, w.Devices[fooled].ID); err != nil {
		return err
	}
	// Replay the complete foreign Control/State branches into the real team's
	// namespace. The author is now a legitimate member with the same keys,
	// workspace ID and environment incarnation, but the signed Control differs.
	foreign, err := w.replayFirstContactBranch(ctx, adversary.Store, cfg.WorkspaceID, cfg.Resource("default"), root)
	if err != nil {
		return err
	}
	var openedForeign atomic.Bool
	guard := storagetest.Wrap(legitimate, storagetest.Hooks{OpenBlob: func(c context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
		if kind == storage.KindState && slices.Contains(foreign, rev) {
			openedForeign.Store(true)
		}
		return next.OpenBlob(c, kind, scope, rev, index)
	}})
	for _, d := range w.Devices[:len(w.Devices)-1] {
		d.Store.Store = guard
	}
	// Exercise the guard using an actual recorded foreign payload read, then
	// require subsequent application operations never to fetch those payloads.
	probe, err := admin.Store.OpenBlob(ctx, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")), foreign[0], 0)
	if err != nil {
		return err
	}
	if err := probe.Close(); err != nil {
		return err
	}
	if !openedForeign.Load() {
		return fmt.Errorf("foreign payload guard did not detect its positive control")
	}
	openedForeign.Store(false)
	honest.Devices = w.Devices[:len(w.Devices)-1]
	// A State naming an unknown Control is explicitly ErrRollback in the
	// protocol. Require fail-closed behavior, rather than weakening that check
	// to silently discard a possibly newer legitimate membership epoch.
	for i := range honest.Devices {
		if err := restart(i); err != nil {
			return err
		}
		d := w.Devices[i]
		checkpoint := wsp.OpenCheckpoints(d.App.CheckpointDir, cfg.WorkspaceID, goodRoot.Genesis, d.App.Runtime.Clock)
		before, err := checkpoint.Accepted(cfg.Resource("default"))
		if err != nil {
			return err
		}
		start := len(w.Tape.Recording.Entries)
		got, err := d.App.ListSecrets(ctx, "default")
		if requireCode(err, apperr.CodeRollback) != nil || got != nil {
			return fmt.Errorf("foreign root replay did not fail closed: %v", err)
		}
		if err := requireCode(d.App.AddSecret(ctx, "default", "MUST_NOT_WRITE", "foreign-control-canary"), apperr.CodeRollback); err != nil {
			return err
		}
		if err := requireCode(d.App.SyncSecrets(ctx, "default"), apperr.CodeRollback); err != nil {
			return err
		}
		if err := requireMetadataOnlyStorage(w.Tape.Recording.Entries[start:]); err != nil {
			return err
		}
		after, err := checkpoint.Accepted(cfg.Resource("default"))
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			return fmt.Errorf("rejected foreign branch changed accepted State heads")
		}
		if err := firstContactPins(d, cfg.WorkspaceID, goodRoot); err != nil {
			return err
		}
	}
	for _, rev := range foreign {
		if err := admin.Store.Delete(ctx, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")), rev); err != nil {
			return err
		}
	}
	controls, err := adversary.Store.Discover(ctx, storage.KindControl, "")
	if err != nil {
		return err
	}
	for _, rev := range controls {
		if err := admin.Store.Delete(ctx, storage.KindControl, "", rev); err != nil {
			return err
		}
	}
	if err := honest.Check(ctx, "default"); err != nil {
		return err
	}
	expectedRoles := map[string]bool{}
	for i, d := range honest.Devices {
		expectedRoles[d.ID] = i == 0
	}
	for _, d := range honest.Devices {
		members, err := d.App.ListMembers(ctx)
		if err != nil {
			return err
		}
		actual := map[string]bool{}
		for _, member := range members {
			actual[member.DeviceID] = member.Admin
		}
		if len(members) != len(expectedRoles) || !maps.Equal(actual, expectedRoles) {
			return fmt.Errorf("first-contact membership or roles changed")
		}
	}
	for i := range honest.Devices {
		if err := restart(i); err != nil {
			return err
		}
		key := fmt.Sprintf("AFTER_FIRST_CONTACT_%d", i)
		if err := w.Devices[i].App.AddSecret(ctx, "default", key, "acknowledged"); err != nil {
			return err
		}
		w.Model["default"][key] = "acknowledged"
	}
	if err := honest.Check(ctx, "default"); err != nil {
		return err
	}
	if openedForeign.Load() {
		return fmt.Errorf("application fetched foreign-root ciphertext after invitation repair")
	}
	return nil
}

func (w *World) replayFirstContactBranch(ctx context.Context, source *Store, workspace, resource string, root digest.Digest) ([]digest.Digest, error) {
	controls, err := source.Discover(ctx, storage.KindControl, "")
	if err != nil {
		return nil, err
	}
	for _, rev := range controls {
		body, err := source.FetchHead(ctx, storage.KindControl, "", rev)
		if err != nil {
			return nil, err
		}
		if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: rev, Head: body}); err != nil {
			return nil, err
		}
	}
	view, err := wsp.LoadControl(ctx, source, workspace, root, nil)
	if err != nil {
		return nil, err
	}
	states, err := wsp.LoadStates(ctx, source, view, workspace, resource)
	if err != nil {
		return nil, err
	}
	scope := storage.StateScope(workspace, resource)
	refs, err := source.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 || len(refs) != len(states.States) {
		return nil, fmt.Errorf("foreign-root replay fixture is incomplete")
	}
	for _, rev := range refs {
		head := states.States[rev]
		if head == nil {
			return nil, fmt.Errorf("foreign replay state did not verify")
		}
		body, err := source.FetchHead(ctx, storage.KindState, scope, rev)
		if err != nil {
			return nil, err
		}
		ciphertext, err := wsp.ReadCiphertext(ctx, source, head)
		if err != nil {
			return nil, err
		}
		if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindState, Scope: scope, Rev: rev, Head: body, Blobs: [][]byte{ciphertext}}); err != nil {
			return nil, err
		}
	}
	if err := w.Tape.Observe("replay-first-contact-branch", controls, refs); err != nil {
		return nil, err
	}
	return refs, nil
}

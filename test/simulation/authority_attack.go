package simulation

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

var AuthorityAttacks = []string{"member-promotes-self", "member-removes-admin", "demoted-admin-promotes-self", "removed-admin-rejoins-self", "member-excuses-rollback", "fork-promotes-member", "fork-swaps-recipient"}

// AuthorityAttack publishes canonical objects signed by real retained keys.
// These objects pass structural and cryptographic checks; parent authority or
// compaction authority is what must reject them.
func (w *World) AuthorityAttack(ctx context.Context, mode string) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	a := w.Devices[0].App
	if err := a.AddSecret(ctx, "default", "BASE", "accepted"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "accepted"
	if err := a.CreateEnvironment("sentinel"); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "sentinel", "SENTINEL", "kept"); err != nil {
		return err
	}
	w.Model["sentinel"] = map[string]string{"SENTINEL": "kept"}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if mode == "demoted-admin-promotes-self" || mode == "removed-admin-rejoins-self" {
		if err := a.SetAdmin(ctx, w.Devices[1].ID, true); err != nil {
			return err
		}
		if mode == "demoted-admin-promotes-self" {
			if err := a.SetAdmin(ctx, w.Devices[1].ID, false); err != nil {
				return err
			}
		} else {
			if err := a.RemoveMember(ctx, w.Devices[1].ID); err != nil {
				return err
			}
		}
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	head, err := view.Head()
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, p := range head.Principals {
		expected[string(p.ID)] = p.Admin
	}
	signer, err := w.Devices[1].Keys.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	if mode == "member-excuses-rollback" {
		states, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
		if err != nil {
			return err
		}
		if len(states.Heads) != 1 {
			return fmt.Errorf("expected single accepted head")
		}
		current := states.Heads[0]
		// Keep a different genuine state visible as the forged compaction floor.
		floor, err := w.publishMergeNode(ctx, 0, map[string]string{"BASE": "rolled-back"})
		if err != nil {
			return err
		}
		record := wsp.Compaction{Workspace: cfg.WorkspaceID, Resource: cfg.Resource("default"), Floor: floor.Rev, Removed: []digest.Digest{current.Digest}, Control: head.Digest, Author: signer.Public().DeviceID()}
		signed, err := wsp.SignCompaction(record, signer)
		if err != nil {
			return err
		}
		if err := w.Devices[1].Store.Publish(ctx, storage.Object{Kind: storage.KindCompaction, Scope: record.Scope(), Rev: digest.FromBytes(signed), Head: signed}); err != nil {
			return err
		}
		blob, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, current)
		if err != nil {
			return err
		}
		signedState, err := w.Devices[0].Store.FetchHead(ctx, storage.KindState, current.Scope(), current.Digest)
		if err != nil {
			return err
		}
		if err := w.Devices[1].Store.Delete(ctx, storage.KindState, current.Scope(), current.Digest); err != nil {
			return err
		}
		for i := range w.Devices {
			w.Restart(i)
			d := w.Devices[i]
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeRollback) != nil {
				return fmt.Errorf("unauthorized compaction excused rollback: %v", err)
			}
		}
		if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindState, Scope: current.Scope(), Rev: current.Digest, Head: signedState, Payload: blob}); err != nil {
			return err
		}
		if err := w.Devices[0].Store.Delete(ctx, floor.Kind, floor.Scope, floor.Rev); err != nil {
			return err
		}
	} else if strings.HasPrefix(mode, "fork-") {
		if err := w.forkResolutionAttack(ctx, mode, cfg, head); err != nil {
			return err
		}
	} else {
		next := head.Control
		next.Principals = slices.Clone(head.Principals)
		next.Parents = []digest.Digest{head.Digest}
		next.Height++
		next.Author = signer.Public().DeviceID()
		switch mode {
		case "member-removes-admin":
			next.Principals = slices.DeleteFunc(next.Principals, func(p wsp.Principal) bool { return string(p.ID) == w.Devices[0].ID })
			// The forged resulting set still has an admin; parser rejection is not enough.
			for i := range next.Principals {
				if next.Principals[i].ID == next.Author {
					next.Principals[i].Admin = true
				}
			}
		case "member-promotes-self", "demoted-admin-promotes-self":
			for i := range next.Principals {
				if next.Principals[i].ID == next.Author {
					next.Principals[i].Admin = true
				}
			}
		case "removed-admin-rejoins-self":
			// The attacker's former principal remains available in their signed history.
			var former wsp.Principal
			for _, rev := range view.Digests() {
				v, _ := view.Get(rev)
				if p, ok := v.Principal(signing.DeviceID(w.Devices[1].ID)); ok {
					former = p
					break
				}
			}
			former.Admin = true
			next.Principals = append(next.Principals, former)
		default:
			return fmt.Errorf("unknown authority attack %q", mode)
		}
		signed, err := wsp.SignControl(next, signer)
		if err != nil {
			return err
		}
		if err := w.Devices[1].Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(signed), Head: signed}); err != nil {
			return err
		}
	}
	if err := w.Tape.Observe("authority-attack", mode, expected); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
		members, err := w.Devices[i].App.ListMembers(ctx)
		if err != nil {
			return err
		}
		actual := map[string]bool{}
		for _, m := range members {
			actual[m.DeviceID] = m.Admin
		}
		if !reflect.DeepEqual(actual, expected) {
			return fmt.Errorf("authority attack %s changed membership: %v", mode, actual)
		}
	}
	if mode == "removed-admin-rejoins-self" {
		if _, err := w.Devices[1].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("removed attacker regained access: %v", err)
		}
		if _, err := w.Devices[1].App.InitializeRepository(ctx); err != nil {
			return err
		}
		if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[1].ID); err != nil {
			return err
		}
	}
	for _, env := range []string{"default", "sentinel"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
		if err := w.Devices[0].App.AddSecret(ctx, env, "AFTER_ATTACK", "legitimate"); err != nil {
			return err
		}
		w.Model[env]["AFTER_ATTACK"] = "legitimate"
		if _, err := w.Devices[0].App.CompactHistory(ctx, env, 1); err != nil {
			return err
		}
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

// Even a genuine admin cannot smuggle new authority or a replacement recipient
// through fork resolution; that action must only reconcile existing authority.
func (w *World) forkResolutionAttack(ctx context.Context, mode string, cfg *config.ProjectConfig, head *wsp.Verified) error {
	signer, err := w.Devices[0].Keys.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	var parents []digest.Digest
	for _, admin := range []bool{false, true} {
		child := head.Control
		child.Parents = []digest.Digest{head.Digest}
		child.Height++
		child.Principals = slices.Clone(head.Principals)
		child.Author = signer.Public().DeviceID()
		for i := range child.Principals {
			if string(child.Principals[i].ID) == w.Devices[2].ID {
				child.Principals[i].Admin = admin
			}
		}
		signed, err := wsp.SignControl(child, signer)
		if err != nil {
			return err
		}
		rev := digest.FromBytes(signed)
		if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: rev, Head: signed}); err != nil {
			return err
		}
		parents = append(parents, rev)
	}
	slices.Sort(parents)
	malicious := head.Control
	malicious.Parents = parents
	malicious.Height += 2
	malicious.Principals = slices.Clone(head.Principals)
	malicious.Author = signer.Public().DeviceID()
	for i := range malicious.Principals {
		if string(malicious.Principals[i].ID) == w.Devices[1].ID {
			if mode == "fork-promotes-member" {
				malicious.Principals[i].Admin = true
			} else {
				malicious.Principals[i].Recipient = head.Principals[0].Recipient
				if malicious.Principals[i].Recipient == head.Principals[i].Recipient {
					malicious.Principals[i].Recipient = head.Principals[len(head.Principals)-1].Recipient
				}
			}
		}
	}
	signed, err := wsp.SignControl(malicious, signer)
	if err != nil {
		return err
	}
	if err := w.Devices[0].Store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: digest.FromBytes(signed), Head: signed}); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
		if _, err := w.Devices[i].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeControlForked) != nil {
			return fmt.Errorf("malicious resolution bypassed fork: %v", err)
		}
	}
	return w.Devices[0].App.ResolveControlFork(ctx)
}

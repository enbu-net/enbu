package simulation

import (
	"context"
	"fmt"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

func (w *World) RequestSignatureAttack(ctx context.Context) error {
	attacker := len(w.Devices) - 1
	if err := w.Devices[0].App.RemoveMember(ctx, w.Devices[attacker].ID); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	// Bootstrap approvals may leave the original valid request in storage.
	// Remove it so this oracle measures forged requests, not a replay of proof
	// of possession that still legitimately needs an explicit admin approval.
	var replayedRequest []byte
	previous, err := wsp.ListJoinRequests(ctx, w.Devices[0].Store, cfg.WorkspaceID)
	if err != nil {
		return err
	}
	for _, request := range previous {
		if string(request.DeviceID()) == w.Devices[attacker].ID {
			replayedRequest, err = w.Devices[0].Store.FetchHead(ctx, storage.KindRequest, "", request.Rev)
			if err != nil {
				return err
			}
			if err := w.Devices[0].Store.Delete(ctx, storage.KindRequest, "", request.Rev); err != nil {
				return err
			}
		}
	}
	signer, err := w.Devices[attacker].Keys.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	id, err := w.Devices[attacker].Keys.Load(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = id.Close() }()
	for _, mode := range []string{"bit-flip", "wrong-signer", "wrong-domain", "foreign-workspace"} {
		workspace := cfg.WorkspaceID
		if mode == "foreign-workspace" {
			workspace = "00000000-0000-4000-8000-000000000000"
		}
		signed, err := wsp.NewJoinRequest(workspace, id.Recipient().String(), w.Devices[attacker].App.Runtime.Clock.Now(), signer)
		if err != nil {
			return err
		}
		object, err := wsp.DecodeSigned(signed)
		if err != nil {
			return err
		}
		switch mode {
		case "bit-flip":
			object.Signature[0] ^= 1
		case "wrong-domain":
			object.Signature, err = signer.Sign(signing.DomainControl, object.Body)
		case "wrong-signer":
			other, e := w.Devices[0].Keys.LoadSigner(cfg.WorkspaceID)
			if e != nil {
				return e
			}
			object.Signature, err = other.Sign(signing.DomainJoin, object.Body)
			_ = other.Close()
		}
		if err != nil {
			return err
		}
		signed, err = object.Encode()
		if err != nil {
			return err
		}
		if _, err := wsp.PublishJoinRequest(ctx, w.Devices[attacker].Store, signed); err != nil {
			return err
		}
		requests, err := w.Devices[0].App.ListJoinRequests(ctx)
		if err != nil {
			return err
		}
		if len(requests) != 0 {
			return fmt.Errorf("forged %s request became approvable: %v", mode, requests)
		}
		if err := w.Tape.Observe("request-attack", mode, len(requests)); err != nil {
			return err
		}
	}
	// Replaying a formerly approved request must never restore membership.
	if len(replayedRequest) > 0 {
		if _, err := wsp.PublishJoinRequest(ctx, w.Devices[attacker].Store, replayedRequest); err != nil {
			return err
		}
		if _, err := w.Devices[attacker].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("replayed request restored membership: %v", err)
		}
		if err := requireCode(w.Devices[attacker].App.AddSecret(ctx, "default", "REPLAYED_REQUEST", "must-not-commit"), apperr.CodeNotMember); err != nil {
			return err
		}
	}
	// Two genuinely signed requests for one device with different recipients
	// must not be chosen using listing order or a future-looking timestamp.
	other, err := w.Devices[0].Keys.Load(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	ambiguous, err := wsp.NewJoinRequest(cfg.WorkspaceID, other.Recipient().String(), w.Devices[attacker].App.Runtime.Clock.Now().AddDate(10, 0, 0), signer)
	_ = other.Close()
	if err != nil {
		return err
	}
	if _, err := wsp.PublishJoinRequest(ctx, w.Devices[attacker].Store, ambiguous); err != nil {
		return err
	}
	if len(replayedRequest) == 0 {
		actual, err := wsp.NewJoinRequest(cfg.WorkspaceID, id.Recipient().String(), w.Devices[attacker].App.Runtime.Clock.Now(), signer)
		if err != nil {
			return err
		}
		if _, err := wsp.PublishJoinRequest(ctx, w.Devices[attacker].Store, actual); err != nil {
			return err
		}
	}
	if err := requireCode(w.Devices[0].App.ApproveMember(ctx, w.Devices[attacker].ID), apperr.CodeInvalidArgument); err != nil {
		return fmt.Errorf("ambiguous requests accepted: %w", err)
	}
	if _, err := w.Devices[attacker].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("ambiguous requester gained access: %v", err)
	}
	// Valid proof of possession still grants no read/write authority until approval.
	result, err := w.Devices[attacker].App.InitializeRepository(ctx)
	if err != nil {
		return err
	}
	if !result.Pending {
		return fmt.Errorf("request implicitly approved")
	}
	if _, err := w.Devices[attacker].App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeNotMember) != nil {
		return fmt.Errorf("pending requester gained access: %v", err)
	}
	requests, err := w.Devices[0].App.ListJoinRequests(ctx)
	if err != nil {
		return err
	}
	if len(requests) != 1 || requests[0].DeviceID != w.Devices[attacker].ID {
		return fmt.Errorf("legitimate request lost among attacks: %v", requests)
	}
	if err := w.Devices[0].App.ApproveMember(ctx, w.Devices[attacker].ID); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}

package simulation

import (
	"context"
	"fmt"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// StateSignatureAttack keeps a canonical body and matching ciphertext digest.
// Only the cryptographic signature is invalid, so a parser rejection cannot
// accidentally stand in for actually checking author and signature authority.
func (w *World) StateSignatureAttack(ctx context.Context) error {
	for index, mode := range []string{"bit-flip", "wrong-signer", "wrong-domain", "truncated"} {
		d := w.Devices[1]
		cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
		if err != nil {
			return err
		}
		control, err := wsp.LoadControl(ctx, d.Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
		if err != nil {
			return err
		}
		states, err := wsp.LoadStates(ctx, d.Store, control, cfg.WorkspaceID, cfg.Resource("default"))
		if err != nil {
			return err
		}
		var parents []digest.Digest
		for _, head := range states.Heads {
			parents = append(parents, head.Digest)
		}
		values := clone(w.Model["default"])
		values["BASE"] = "forged value"
		values["INJECTED"] = "must never appear"
		object, err := w.publishMergeNode(ctx, 1, values, parents...)
		if err != nil {
			return err
		}
		// No App has accepted this staging object; replace it before any read.
		if err := d.Store.Delete(ctx, object.Kind, object.Scope, object.Rev); err != nil {
			return err
		}
		signed, err := wsp.DecodeSigned(object.Head)
		if err != nil {
			return err
		}
		switch mode {
		case "bit-flip":
			signed.Signature[0] ^= 1
		case "truncated":
			signed.Signature = signed.Signature[:len(signed.Signature)-1]
		case "wrong-signer", "wrong-domain":
			who, domain := 1, signing.DomainControl
			if mode == "wrong-signer" {
				// The forged author is device 1. Full generated plans also
				// include two-device worlds, where device 0 is the other signer.
				who, domain = (1+1)%len(w.Devices), signing.DomainState
			}
			signer, err := w.Devices[who].Keys.LoadSigner(cfg.WorkspaceID)
			if err != nil {
				return err
			}
			signed.Signature, err = signer.Sign(domain, signed.Body)
			_ = signer.Close()
			if err != nil {
				return err
			}
		}
		object.Head, err = signed.Encode()
		if err != nil {
			return err
		}
		object.Rev = digest.FromBytes(object.Head)
		if err := d.Store.Publish(ctx, object); err != nil {
			return err
		}
		if err := w.Tape.Observe("state-signature-attack", mode, object.Rev); err != nil {
			return err
		}
		for i := range w.Devices {
			w.Restart(i)
		}
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		key := fmt.Sprintf("VALID_AFTER_ATTACK_%d", index)
		if err := w.Devices[(index+1)%len(w.Devices)].App.AddSecret(ctx, "default", key, "accepted"); err != nil {
			return err
		}
		w.Model["default"][key] = "accepted"
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
	}
	// Reclaiming malformed authority must not remove legitimate data.
	if _, err := w.Devices[0].App.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	return nil
}

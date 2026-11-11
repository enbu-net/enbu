package simulation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

var wireModes = []string{"duplicate-envelope", "unknown-envelope", "nonminimal-envelope", "indefinite-envelope", "tagged-envelope", "trailing-envelope", "unknown-body", "duplicate-body", "nonminimal-body", "invalid-utf8-body", "deep-body", "future-domain", "future-recipient", "future-signing-key"}

// Malformed bodies are re-signed by the legitimate author. Rejection must not
// depend on accidentally invalidating a signature when testing the parser.
func malformedWire(enc cbor.EncMode, blob []byte, mode, domain string, kind storage.Kind, signer signing.Signer) ([]byte, error) {
	s, err := wsp.DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	changeMap := func(raw []byte, duplicate bool) ([]byte, error) {
		var fields map[string]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
		if !duplicate {
			fields["protocol_version"] = cbor.RawMessage{0x02}
			return enc.Marshal(fields)
		}
		key := "workspace"
		if _, ok := fields[key]; !ok {
			key = "body"
		}
		encodedKey, err := enc.Marshal(key)
		if err != nil {
			return nil, err
		}
		if raw[0] < 0xa0 || raw[0] >= 0xb7 {
			return nil, fmt.Errorf("wire fixture must be a short CBOR map")
		}
		out := append([]byte{raw[0] + 1}, raw[1:]...)
		out = append(out, encodedKey...)
		return append(out, fields[key]...), nil
	}
	switch mode {
	case "duplicate-envelope":
		return changeMap(blob, true)
	case "unknown-envelope":
		return changeMap(blob, false)
	case "nonminimal-envelope":
		return append([]byte{0xb8, blob[0] - 0xa0}, blob[1:]...), nil
	case "indefinite-envelope":
		return append(append([]byte{0xbf}, blob[1:]...), 0xff), nil
	case "tagged-envelope":
		return append([]byte{0xc0}, blob...), nil
	case "trailing-envelope":
		return append(slices.Clone(blob), 0), nil
	case "unknown-body", "duplicate-body":
		s.Body, err = changeMap(s.Body, mode == "duplicate-body")
	case "nonminimal-body":
		s.Body = append([]byte{0xb8, s.Body[0] - 0xa0}, s.Body[1:]...)
	case "invalid-utf8-body", "deep-body":
		var fields map[string]cbor.RawMessage
		if err := cbor.Unmarshal(s.Body, &fields); err != nil {
			return nil, err
		}
		key, err := enc.Marshal("workspace")
		if err != nil {
			return nil, err
		}
		needle := append(slices.Clone(key), fields["workspace"]...)
		at := bytes.Index(s.Body, needle)
		if at < 0 {
			return nil, fmt.Errorf("wire fixture lacks workspace field")
		}
		value := []byte{0x61, 0xff}
		if mode == "deep-body" {
			value = append(bytes.Repeat([]byte{0x81}, 10), 0)
		}
		out := append(slices.Clone(s.Body[:at]), key...)
		out = append(out, value...)
		s.Body = append(out, s.Body[at+len(needle):]...)
	case "future-domain":
		domain += ".future"
	case "future-recipient", "future-signing-key":
		if kind == storage.KindControl {
			var c wsp.Control
			if err = cbor.Unmarshal(s.Body, &c); err == nil {
				if mode == "future-recipient" {
					c.Principals[1].Recipient = "age1unsupportedfuturealgorithm"
				} else {
					c.Principals[1].Signing.Alg = "future-signing-algorithm"
				}
				s.Body, err = enc.Marshal(c)
			}
		} else {
			var r wsp.JoinRequest
			if err = cbor.Unmarshal(s.Body, &r); err == nil {
				if mode == "future-recipient" {
					r.Recipient = "age1unsupportedfuturealgorithm"
				} else {
					r.Signing.Alg = "future-signing-algorithm"
				}
				s.Body, err = enc.Marshal(r)
			}
		}
	default:
		return nil, fmt.Errorf("unknown wire attack %q", mode)
	}
	if err != nil {
		return nil, err
	}
	s.Signature, err = signer.Sign(domain, s.Body)
	if err != nil {
		return nil, err
	}
	return s.Encode()
}

func (w *World) WireAttacks(ctx context.Context, cold bool) error {
	a := w.Devices[0].App
	if err := w.Check(ctx, "default"); err != nil {
		return err
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
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	for i := range members {
		members[i].Self = false
	}
	signer, err := w.Devices[0].Keys.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()
	next := head.Control
	next.Principals = slices.Clone(head.Principals)
	for i := range next.Principals {
		if string(next.Principals[i].ID) == w.Devices[1].ID {
			next.Principals[i].Admin = true
		}
	}
	next.Parents, next.Height = []digest.Digest{head.Digest}, head.Height+1
	next.Author = signer.Public().DeviceID()
	control, err := wsp.SignControl(next, signer)
	if err != nil {
		return err
	}
	states, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
	if err != nil || len(states.Heads) != 1 {
		return fmt.Errorf("wire fixture requires one accepted head: %v", err)
	}
	accepted := states.Heads[0]
	originalHead, err := w.Devices[0].Store.FetchHead(ctx, storage.KindState, accepted.Scope(), accepted.Digest)
	if err != nil {
		return err
	}
	originalCipher, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, accepted)
	if err != nil {
		return err
	}
	original := storage.Object{Kind: storage.KindState, Scope: accepted.Scope(), Rev: accepted.Digest, Head: originalHead, Payload: originalCipher}
	floor, err := w.publishMergeNode(ctx, 0, map[string]string{"BASE": "must-not-accept"})
	if err != nil {
		return err
	}
	if err := w.Devices[0].Store.Delete(ctx, floor.Kind, floor.Scope, floor.Rev); err != nil {
		return err
	}
	compaction, err := wsp.SignCompaction(wsp.Compaction{Workspace: cfg.WorkspaceID, Resource: cfg.Resource("default"), Control: head.Digest, Author: signer.Public().DeviceID(), Floor: floor.Rev, Removed: []digest.Digest{accepted.Digest}}, signer)
	if err != nil {
		return err
	}
	keys := &Keys{Tape: w.Tape, Device: len(w.Devices)}
	id, _, _, err := keys.Create(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = id.Close() }()
	requestSigner, _, _, err := keys.CreateSigner(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = requestSigner.Close() }()
	request, err := wsp.NewJoinRequest(cfg.WorkspaceID, id.Recipient().String(), a.Runtime.Clock.Now(), requestSigner)
	if err != nil {
		return err
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return err
	}
	base := w.Devices[0].Store.Store
	var rejected digest.Digest
	badBlobs := 0
	observed := storagetest.Wrap(base, storagetest.Hooks{OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
		if rev == rejected {
			badBlobs++
		}
		return next.OpenPayload(ctx, kind, scope, rev)
	}})
	for _, d := range w.Devices {
		d.Store.Store = observed
	}
	defer func() {
		for _, d := range w.Devices {
			d.Store.Store = base
		}
	}()
	sources := []struct {
		kind   storage.Kind
		blob   []byte
		domain string
		signer signing.Signer
		verify func([]byte) error
	}{
		{storage.KindControl, control, signing.DomainControl, signer, func(b []byte) error { _, err := wsp.VerifyChild([]*wsp.Verified{head}, b, nil); return err }},
		{storage.KindState, floor.Head, signing.DomainState, signer, func(b []byte) error {
			_, err := wsp.VerifyRevision(view, cfg.WorkspaceID, cfg.Resource("default"), digest.FromBytes(b), b)
			return err
		}},
		{storage.KindRequest, request, signing.DomainJoin, requestSigner, func(b []byte) error { _, err := wsp.VerifyJoinRequest(cfg.WorkspaceID, b); return err }},
		{storage.KindCompaction, compaction, signing.DomainCompact, signer, func(b []byte) error {
			_, err := wsp.VerifyCompaction(view, cfg.WorkspaceID, cfg.Resource("default"), digest.FromBytes(b), b)
			return err
		}},
	}
	for _, source := range sources {
		if err := source.verify(source.blob); err != nil {
			return fmt.Errorf("unmodified %s control failed: %w", source.kind, err)
		}
		for _, mode := range wireModes {
			if (mode == "future-recipient" || mode == "future-signing-key") && source.kind != storage.KindControl && source.kind != storage.KindRequest {
				continue
			}
			bad, err := malformedWire(enc, source.blob, mode, source.domain, source.kind, source.signer)
			if err != nil {
				return err
			}
			if err := source.verify(bad); !errors.Is(err, wsp.ErrInvalid) {
				return fmt.Errorf("%s/%s wire attack accepted: %v", source.kind, mode, err)
			}
			object := storage.Object{Kind: source.kind, Head: bad, Rev: digest.FromBytes(bad)}
			rejected, badBlobs = object.Rev, 0
			if source.kind == storage.KindState || source.kind == storage.KindCompaction {
				object.Scope = floor.Scope
			}
			if source.kind == storage.KindState {
				object.Scope, object.Payload = floor.Scope, floor.Payload
			}
			if err := w.Devices[0].Store.Publish(ctx, object); err != nil {
				return err
			}
			if source.kind == storage.KindCompaction {
				if err := w.Devices[0].Store.Publish(ctx, floor); err != nil {
					return err
				}
				if err := w.Devices[0].Store.Delete(ctx, original.Kind, original.Scope, original.Rev); err != nil {
					return err
				}
			}
			for _, d := range w.Devices {
				if cold {
					if err := os.RemoveAll(d.App.CacheDir); err != nil {
						return err
					}
				}
				switch source.kind {
				case storage.KindCompaction:
					if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeRollback) != nil {
						return fmt.Errorf("malformed compaction excused rollback: %v", err)
					}
				case storage.KindRequest:
					requests, err := d.App.ListJoinRequests(ctx)
					if err != nil || len(requests) != 0 {
						return fmt.Errorf("malformed request listed: %v %v", requests, err)
					}
				default:
					got, err := d.App.ListSecrets(ctx, "default")
					if err != nil || !reflect.DeepEqual(got, w.Model["default"]) {
						return fmt.Errorf("malformed %s affected data: %v", source.kind, err)
					}
				}
				got, err := d.App.ListMembers(ctx)
				for i := range got {
					if got[i].Self != (got[i].DeviceID == d.ID) {
						return fmt.Errorf("wire attack changed observer identity")
					}
					got[i].Self = false
				}
				if err != nil || !reflect.DeepEqual(got, members) {
					return fmt.Errorf("malformed %s/%s changed authority: %v", source.kind, mode, err)
				}
			}
			if badBlobs != 0 {
				return fmt.Errorf("malformed %s/%s opened %d ciphertexts", source.kind, mode, badBlobs)
			}
			if source.kind == storage.KindCompaction {
				if err := w.Devices[0].Store.Publish(ctx, original); err != nil {
					return err
				}
				if err := w.Devices[0].Store.Delete(ctx, floor.Kind, floor.Scope, floor.Rev); err != nil {
					return err
				}
			}
			if err := w.Devices[0].Store.Delete(ctx, object.Kind, object.Scope, object.Rev); err != nil {
				return err
			}
			if err := w.Tape.Observe("rejected-wire", []any{source.kind, mode, cold}, object.Rev); err != nil {
				return err
			}
		}
	}
	if err := w.Devices[1].App.EditSecret(ctx, "default", "BASE", "team-after-wire-attacks"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "team-after-wire-attacks"
	for i := range w.Devices {
		w.Restart(i)
	}
	return w.Check(ctx, "default")
}

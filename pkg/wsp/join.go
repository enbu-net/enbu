package wsp

import (
	"context"
	"errors"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// JoinRequest is signed by the requesting device's own key, proving it holds
// the signing key it names. That proves possession, not membership.
type JoinRequest struct {
	Workspace string            `cbor:"workspace"`
	Signing   signing.PublicKey `cbor:"signing"`
	Recipient string            `cbor:"recipient"`
	CreatedAt int64             `cbor:"created_at"` // unix seconds, display only
}

func (r JoinRequest) DeviceID() signing.DeviceID { return r.Signing.DeviceID() }

// NewJoinRequest returns the stored bytes of a request signed by signer.
func NewJoinRequest(workspace, recipient string, now time.Time, signer signing.Signer) ([]byte, error) {
	r := JoinRequest{Workspace: workspace, Signing: signer.Public(), Recipient: recipient, CreatedAt: now.Unix()}
	body, err := encMode.Marshal(r)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainJoin, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

// VerifyJoinRequest checks a stored request. The device it names is derived
// from the key inside, so nobody can file a request under another device.
func VerifyJoinRequest(workspace string, blob []byte) (*JoinRequest, error) {
	s, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	var r JoinRequest
	if err := decodeCanonical(s.Body, &r); err != nil {
		return nil, err
	}
	if r.Workspace != workspace {
		return nil, invalid("join request is for another workspace")
	}
	if err := r.Signing.Validate(); err != nil {
		return nil, invalid("join request key: %v", err)
	}
	if _, err := age.ParseRecipient(r.Recipient); err != nil {
		return nil, invalid("join request recipient: %v", err)
	}
	if err := signing.Verify(r.Signing, signing.DomainJoin, s.Body, s.Signature); err != nil {
		return nil, invalid("join request signature: %v", err)
	}
	return &r, nil
}

// PublishJoinRequest stores a request from NewJoinRequest and returns its revision.
func PublishJoinRequest(ctx context.Context, store storage.Store, blob []byte) (digest.Digest, error) {
	rev := digest.FromBytes(blob)
	return rev, store.Publish(ctx, storage.Object{Kind: storage.KindRequest, Rev: rev, Signed: blob})
}

// PendingRequest is a verified request together with the revision it is stored under.
type PendingRequest struct {
	JoinRequest
	Rev digest.Digest
}

// ListJoinRequests returns the verified requests storage shows, sorted by
// revision. Several requests from one device are all returned: storage listing
// order says nothing about which is newest, so the admin chooses. Damaged or
// foreign objects are skipped.
func ListJoinRequests(ctx context.Context, store storage.Store, workspace string) ([]PendingRequest, error) {
	revs, err := store.Discover(ctx, storage.KindRequest, "")
	if err != nil {
		return nil, err
	}
	var out []PendingRequest
	for _, rev := range revs {
		o, err := store.Fetch(ctx, storage.KindRequest, "", rev)
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrCorrupt) {
			continue
		}
		if err != nil {
			return nil, err
		}
		r, err := VerifyJoinRequest(workspace, o.Signed)
		if err != nil {
			continue
		}
		out = append(out, PendingRequest{JoinRequest: *r, Rev: rev})
	}
	return out, nil
}

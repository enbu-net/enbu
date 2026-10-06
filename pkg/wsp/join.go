package wsp

import (
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
)

// JoinRequestPrefix names refs where a device asks to join a workspace. A
// request carries no authority: it only lets an admin choose from a list
// instead of typing keys. Only a signed Control adds a principal.
const JoinRequestPrefix = "request-"

func JoinRequestRef(id signing.DeviceID) string { return JoinRequestPrefix + string(id) }

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

// VerifyJoinRequest checks a request read from the ref named for device.
func VerifyJoinRequest(workspace string, device signing.DeviceID, blob []byte) (*JoinRequest, error) {
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
	if r.DeviceID() != device {
		return nil, invalid("join request does not match device %s", device)
	}
	if _, err := age.ParseRecipient(r.Recipient); err != nil {
		return nil, invalid("join request recipient: %v", err)
	}
	if err := signing.Verify(r.Signing, signing.DomainJoin, s.Body, s.Signature); err != nil {
		return nil, invalid("join request signature: %v", err)
	}
	return &r, nil
}

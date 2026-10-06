package wsp

import (
	"fmt"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/opencontainers/go-digest"
)

// State binds one ciphertext blob to the device that published it. The
// resource names what the ciphertext is (for example "secrets/prod"); it is a
// plain string so authorization can later be decided per resource by policy.
type State struct {
	Workspace         string           `cbor:"workspace"`
	Resource          string           `cbor:"resource"`
	Sequence          uint64           `cbor:"sequence"` // 1 for the first state of a resource
	Previous          digest.Digest    `cbor:"previous"` // SignedState blob replaced; empty at sequence 1
	ControlGeneration uint64           `cbor:"control_generation"`
	Control           digest.Digest    `cbor:"control"` // SignedControl blob the author saw
	Ciphertext        digest.Digest    `cbor:"ciphertext"`
	Author            signing.DeviceID `cbor:"author"`
}

// VerifiedState is a State whose author and signature have been checked
// against a verified Control. Digest is the digest of the SignedState blob.
type VerifiedState struct {
	State
	Digest digest.Digest
}

func (s State) validate() error {
	if s.Workspace == "" || s.Resource == "" {
		return invalid("state has no workspace or resource")
	}
	if s.Sequence == 0 {
		return invalid("state sequence starts at 1")
	}
	if (s.Sequence == 1) != (s.Previous == "") {
		return invalid("state previous is set exactly when sequence > 1")
	}
	if s.Previous != "" {
		if err := validDigest(s.Previous); err != nil {
			return invalid("state previous: %v", err)
		}
	}
	if err := validDigest(s.Control); err != nil {
		return invalid("state control: %v", err)
	}
	if err := validDigest(s.Ciphertext); err != nil {
		return invalid("state ciphertext: %v", err)
	}
	if err := s.Author.Validate(); err != nil {
		return invalid("state author: %v", err)
	}
	return nil
}

// SignState signs s, whose Author must be signer, and returns the stored bytes.
func SignState(s State, signer signing.Signer) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if signer.Public().DeviceID() != s.Author {
		return nil, invalid("signer is not the state author")
	}
	body, err := encMode.Marshal(s)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainState, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

// VerifyState checks a stored SignedState for workspace and resource against
// the current verified Control: the author must be a principal now, and the
// signature must verify under the key the Control lists for that author.
//
// A state that claims a newer Control than the head means storage served an
// older control-head than the author saw, so it is reported as a rollback.
func VerifyState(ctrl *Verified, workspace, resource string, blob []byte) (*VerifiedState, error) {
	signed, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	var s State
	if err := decodeCanonical(signed.Body, &s); err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	if s.Workspace != workspace || s.Resource != resource {
		return nil, invalid("state is for %s/%s, not %s/%s", s.Workspace, s.Resource, workspace, resource)
	}
	author, ok := ctrl.Principal(s.Author)
	if !ok {
		return nil, invalid("state author %s is not a principal of the workspace", s.Author)
	}
	if err := signing.Verify(author.Signing, signing.DomainState, signed.Body, signed.Signature); err != nil {
		return nil, invalid("state signature: %v", err)
	}
	switch {
	case s.ControlGeneration > ctrl.Generation:
		return nil, fmt.Errorf("%w: state was signed under control generation %d but the head is %d", ErrRollback, s.ControlGeneration, ctrl.Generation)
	case s.ControlGeneration == ctrl.Generation && s.Control != ctrl.Digest:
		return nil, invalid("state names a control that is not the verified generation %d", ctrl.Generation)
	}
	return &VerifiedState{State: s, Digest: digest.FromBytes(blob)}, nil
}

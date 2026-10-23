package wsp

import (
	"errors"
	"testing"
	"time"
)

func TestJoinRequestRoundTrip(t *testing.T) {
	bob := newActor(t, false)
	blob, err := NewJoinRequest(testWorkspace, bob.p.Recipient, time.Unix(1700000000, 0), bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	req, err := VerifyJoinRequest(testWorkspace, blob)
	if err != nil {
		t.Fatal(err)
	}
	if req.DeviceID() != bob.p.ID || req.Recipient != bob.p.Recipient || req.CreatedAt != 1700000000 {
		t.Fatalf("unexpected request: %+v", req)
	}
}

// A request proves only that its sender holds the signing key it names. It must
// not be accepted for another workspace or with a swapped key. The device it
// names is derived from that key, so a request cannot be filed for another device.
func TestJoinRequestIsBoundToItsSender(t *testing.T) {
	bob, mallory := newActor(t, false), newActor(t, false)
	blob, err := NewJoinRequest(testWorkspace, bob.p.Recipient, time.Now(), bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJoinRequest("0192f3a0-7c1e-7a55-9d3c-000000000000", blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("request accepted for another workspace: %v", err)
	}
	signed, _ := DecodeSigned(blob)
	other, _ := NewJoinRequest(testWorkspace, mallory.p.Recipient, time.Now(), mallory.signer)
	otherSigned, _ := DecodeSigned(other)
	// bob's body (his recipient) under mallory's signature.
	forged, _ := Signed{Body: signed.Body, Signature: otherSigned.Signature}.Encode()
	if _, err := VerifyJoinRequest(testWorkspace, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("request with a foreign signature accepted: %v", err)
	}
}

func TestJoinRequestRejectsBadRecipient(t *testing.T) {
	bob := newActor(t, false)
	blob, err := NewJoinRequest(testWorkspace, "not an age recipient", time.Now(), bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJoinRequest(testWorkspace, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("request with an invalid recipient accepted: %v", err)
	}
}

func TestKeyUpdateRequest(t *testing.T) {
	bob, carol := newActor(t, false), newActor(t, false)
	blob, err := NewKeyUpdateRequest(testWorkspace, carol.p.Recipient, bob.p.Recipient, time.Now(), bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	req, err := VerifyJoinRequest(testWorkspace, blob)
	if err != nil {
		t.Fatal(err)
	}
	if req.DeviceID() != bob.p.ID || req.Recipient != carol.p.Recipient || req.Replaces != bob.p.Recipient {
		t.Fatalf("unexpected request: %+v", req)
	}
	// A plain join request encodes as before: no replaces field at all.
	plain, _ := NewJoinRequest(testWorkspace, bob.p.Recipient, time.Now(), bob.signer)
	signed, _ := DecodeSigned(plain)
	var fields map[string]any
	if err := decMode.Unmarshal(signed.Body, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["replaces"]; ok {
		t.Fatal("a join request carries a replaces field")
	}
	for _, replaces := range []string{"", carol.p.Recipient} {
		if _, err := NewKeyUpdateRequest(testWorkspace, carol.p.Recipient, replaces, time.Now(), bob.signer); !errors.Is(err, ErrInvalid) {
			t.Fatalf("key update replacing %q accepted: %v", replaces, err)
		}
	}
	// A signed update that replaces its own or a malformed recipient is refused.
	for _, replaces := range []string{carol.p.Recipient, "not an age recipient"} {
		body, _ := encMode.Marshal(JoinRequest{Workspace: testWorkspace, Signing: bob.signer.Public(), Recipient: carol.p.Recipient, Replaces: replaces})
		sig, _ := bob.signer.Sign("enbu.join-request.v1", body)
		forged, _ := Signed{Body: body, Signature: sig}.Encode()
		if _, err := VerifyJoinRequest(testWorkspace, forged); !errors.Is(err, ErrInvalid) {
			t.Fatalf("key update replacing %q verified: %v", replaces, err)
		}
	}
}

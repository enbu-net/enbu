package commit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const testActor = "github:subject:123456789"

type testSigner struct {
	id         artifact.UUID
	privateKey ed25519.PrivateKey
	recipient  string
}

func newTestSigner(id int, seed byte) testSigner {
	recipient, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	return testSigner{
		id:         testUUID(id),
		privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)),
		recipient:  recipient.Recipient().String(),
	}
}

func (s testSigner) DeviceID() artifact.UUID { return s.id }
func (s testSigner) SigningPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.privateKey.Public().(ed25519.PublicKey)...)
}
func (s testSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, message), nil
}

type staticResolver struct {
	assertion []byte
	claims    artifact.EnrollmentClaims
	err       error
}

func (r staticResolver) VerifyEnrollment(_ context.Context, assertion []byte) (artifact.EnrollmentClaims, error) {
	if r.err != nil {
		return artifact.EnrollmentClaims{}, r.err
	}
	if !bytes.Equal(assertion, r.assertion) {
		return artifact.EnrollmentClaims{}, errors.New("unknown assertion")
	}
	claims := r.claims
	claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
	return claims, nil
}

func resolverFor(signer testSigner) staticResolver {
	assertion := []byte("test-enrollment:" + string(signer.id))
	return staticResolver{
		assertion: assertion,
		claims: artifact.EnrollmentClaims{
			DeviceID:         signer.id,
			Subject:          testActor,
			X25519Recipient:  signer.recipient,
			Ed25519PublicKey: signer.SigningPublicKey(),
		},
	}
}

func authorFor(t testing.TB, signer testSigner) artifact.VerifiedDevice {
	t.Helper()
	resolver := resolverFor(signer)
	author, err := artifact.VerifyEnrollment(context.Background(), resolver, resolver.assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	return author
}

func testUUID(id int) artifact.UUID {
	value := artifact.UUID(fmt.Sprintf("00000000-0000-4000-8000-%012x", id))
	if err := value.Validate(); err != nil {
		panic(err)
	}
	return value
}

func testSealed(label string) artifact.SealedRef {
	return artifact.SealedRef{
		Revision: digest.FromString(label + ":revision"),
		Material: digest.FromString(label + ":material"),
		Grant:    digest.FromString(label + ":grant"),
	}
}

func updateAction() artifact.TypeRef {
	return artifact.TypeRef{Group: "operations.enbu.net", Version: "v1alpha1", Kind: "Update"}
}

func baseCommit(sequence int, parents []digest.Digest) Commit {
	root := testSealed(fmt.Sprintf("root-%d", sequence))
	value := Commit{
		APIVersion:  APIVersion,
		Kind:        Kind,
		WorkspaceID: testUUID(1),
		Root:        root,
		Policy:      testSealed("policy"),
		Parents:     append([]digest.Digest(nil), parents...),
		Actor:       testActor,
		DeviceID:    testUUID(2),
		OperationID: testUUID(1000 + sequence),
		Timestamp:   NewTimestamp(time.Date(2026, time.August, 8, 10, 0, 0, sequence, time.UTC)),
	}
	if len(parents) == 0 {
		value.Provenance = []MutationProvenance{{
			ID:     testUUID(2000 + sequence),
			Action: InitializeAction(),
			Target: testUUID(3),
			After:  sealedPointer(root),
		}}
		return value
	}
	value.Provenance = []MutationProvenance{{
		ID:     testUUID(2000 + sequence),
		Action: updateAction(),
		Target: testUUID(3),
		Before: sealedPointer(testSealed(fmt.Sprintf("root-before-%d", sequence))),
		After:  sealedPointer(root),
	}}
	return value
}

func sealedPointer(value artifact.SealedRef) *artifact.SealedRef {
	return &value
}

func signForTest(t *testing.T, value Commit, signer testSigner) ([]byte, digest.Digest) {
	t.Helper()
	encoded, err := SignCommit(value, signer, authorFor(t, signer))
	if err != nil {
		t.Fatalf("SignCommit: %v", err)
	}
	return encoded, digest.FromBytes(encoded)
}

func TestSignedCommitRoundTripCanonicalizesSets(t *testing.T) {
	signer := newTestSigner(2, 7)
	parentA := digest.FromString("parent-a")
	parentB := digest.FromString("parent-b")
	value := baseCommit(1, []digest.Digest{parentB, parentA})
	recordA := value.Provenance[0]
	recordA.ID = testUUID(2102)
	recordA.Inputs = []PinnedInput{
		{Role: artifact.TypeRef{Group: "inputs.example.com", Version: "v1alpha1", Kind: "Right"}, UID: testUUID(12), Sealed: testSealed("input-b")},
		{Role: artifact.TypeRef{Group: "inputs.example.com", Version: "v1alpha1", Kind: "Left"}, UID: testUUID(12), Sealed: testSealed("input-a")},
	}
	recordB := recordA
	recordB.ID = testUUID(2101)
	recordB.Target = testUUID(4)
	value.Provenance = []MutationProvenance{recordA, recordB}

	author := authorFor(t, signer)
	encoded, err := SignCommit(value, signer, author)
	if err != nil {
		t.Fatalf("SignCommit: %v", err)
	}
	value.Parents = []digest.Digest{parentA, parentB}
	value.Provenance = []MutationProvenance{recordB, recordA}
	value.Provenance[1].Inputs[0], value.Provenance[1].Inputs[1] = value.Provenance[1].Inputs[1], value.Provenance[1].Inputs[0]
	encodedReordered, err := SignCommit(value, signer, author)
	if err != nil {
		t.Fatalf("SignCommit reordered: %v", err)
	}
	if !bytes.Equal(encoded, encodedReordered) {
		t.Fatal("set-like parent, provenance, or input order changed canonical bytes")
	}

	verified, err := VerifySignedCommit(context.Background(), encoded, resolverFor(signer))
	if err != nil {
		t.Fatalf("VerifySignedCommit: %v", err)
	}
	if verified.Digest() != digest.FromBytes(encoded) {
		t.Fatalf("digest = %s, want %s", verified.Digest(), digest.FromBytes(encoded))
	}
	got := verified.Commit()
	if got.Parents[0].String() > got.Parents[1].String() {
		t.Fatalf("parents are not canonical: %v", got.Parents)
	}
	if got.Provenance[0].ID > got.Provenance[1].ID {
		t.Fatalf("provenance is not canonical: %v", got.Provenance)
	}
	got.Parents[0] = digest.FromString("mutated")
	if verified.Commit().Parents[0] == got.Parents[0] {
		t.Fatal("VerifiedCommit exposed mutable parent storage")
	}
}

func TestPinnedInputsAllowSameUIDWithDistinctMergeRoles(t *testing.T) {
	record := baseCommit(1, []digest.Digest{digest.FromString("parent")}).Provenance[0]
	uid := testUUID(55)
	left := PinnedInput{
		Role:   artifact.TypeRef{Group: "inputs.enbu.net", Version: "v1alpha1", Kind: "MergeLeft"},
		UID:    uid,
		Sealed: testSealed("left"),
	}
	right := PinnedInput{
		Role:   artifact.TypeRef{Group: "inputs.enbu.net", Version: "v1alpha1", Kind: "MergeRight"},
		UID:    uid,
		Sealed: testSealed("right"),
	}
	record.Inputs = []PinnedInput{right, left}
	if err := record.Validate(); err != nil {
		t.Fatalf("role-addressed same-UID inputs: %v", err)
	}
	record.Inputs = append(record.Inputs, left)
	if err := record.Validate(); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("duplicate role and UID error = %v, want ErrInvalidCommit", err)
	}
	record.Inputs = []PinnedInput{left, {
		Role:   left.Role,
		UID:    left.UID,
		Sealed: testSealed("new-left-revision"),
	}}
	if err := record.Validate(); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("ambiguous role and UID error = %v, want ErrInvalidCommit", err)
	}
}

func TestSignCommitRejectsWrongDeviceAndFaultySigner(t *testing.T) {
	value := baseCommit(0, nil)
	wrongDevice := newTestSigner(99, 1)
	if _, err := SignCommit(value, wrongDevice, authorFor(t, wrongDevice)); !errors.Is(err, ErrSigningKeyBinding) {
		t.Fatalf("wrong device error = %v, want %v", err, ErrSigningKeyBinding)
	}

	faulty := badSignatureSigner{testSigner: newTestSigner(2, 1)}
	if _, err := SignCommit(value, faulty, authorFor(t, faulty.testSigner)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("faulty signer error = %v, want %v", err, ErrInvalidSignature)
	}
}

type badSignatureSigner struct{ testSigner }

func (s badSignatureSigner) Sign([]byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestVerifySignedCommitRejectsEnrollmentBindingFailures(t *testing.T) {
	signer := newTestSigner(2, 7)
	encoded, _ := signForTest(t, baseCommit(0, nil), signer)
	valid := resolverFor(signer)
	wrongKey := resolverFor(signer)
	wrongKey.claims.Ed25519PublicKey = newTestSigner(4, 8).SigningPublicKey()
	wrongActor := resolverFor(signer)
	wrongActor.claims.Subject = "github:subject:other"
	wrongDevice := resolverFor(signer)
	wrongDevice.claims.DeviceID = testUUID(99)
	tests := []struct {
		name     string
		verifier artifact.EnrollmentVerifier
	}{
		{name: "nil", verifier: nil},
		{name: "missing", verifier: staticResolver{}},
		{name: "wrong key", verifier: wrongKey},
		{name: "wrong actor", verifier: wrongActor},
		{name: "wrong device", verifier: wrongDevice},
		{name: "verifier error", verifier: staticResolver{assertion: valid.assertion, err: errors.New("offline")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifySignedCommit(context.Background(), encoded, test.verifier); !errors.Is(err, ErrSigningKeyBinding) {
				t.Fatalf("VerifySignedCommit error = %v, want %v", err, ErrSigningKeyBinding)
			}
		})
	}
}

func TestDecodeSignedCommitRejectsTamperUnknownAndNonCanonical(t *testing.T) {
	signer := newTestSigner(2, 7)
	value := baseCommit(3, []digest.Digest{digest.FromString("a"), digest.FromString("b")})
	encoded, _ := signForTest(t, value, signer)
	decoded, err := DecodeSignedCommit(encoded)
	if err != nil {
		t.Fatalf("DecodeSignedCommit: %v", err)
	}

	t.Run("commit tamper", func(t *testing.T) {
		tampered := decoded
		tampered.Commit.Root = testSealed("attacker")
		data, marshalErr := artifact.MarshalCanonical(tampered)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, decodeErr := DecodeSignedCommit(data); !errors.Is(decodeErr, ErrInvalidSignature) {
			t.Fatalf("error = %v, want %v", decodeErr, ErrInvalidSignature)
		}
	})

	t.Run("signature tamper", func(t *testing.T) {
		tampered := decoded
		tampered.Signature = append([]byte(nil), decoded.Signature...)
		tampered.Signature[0] ^= 0xff
		data, marshalErr := artifact.MarshalCanonical(tampered)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, decodeErr := DecodeSignedCommit(data); !errors.Is(decodeErr, ErrInvalidSignature) {
			t.Fatalf("error = %v, want %v", decodeErr, ErrInvalidSignature)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		data, marshalErr := artifact.MarshalCanonical(struct {
			Commit     Commit            `cbor:"commit"`
			SigningKey ed25519.PublicKey `cbor:"signingKey"`
			Signature  []byte            `cbor:"signature"`
			Unexpected string            `cbor:"unexpected"`
		}{decoded.Commit, decoded.SigningKey, decoded.Signature, "rejected"})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, decodeErr := DecodeSignedCommit(data); decodeErr == nil {
			t.Fatal("unknown field was accepted")
		}
	})

	t.Run("non-canonical parent order", func(t *testing.T) {
		nonCanonical := decoded
		nonCanonical.Commit.Parents = append([]digest.Digest(nil), decoded.Commit.Parents...)
		nonCanonical.Commit.Parents[0], nonCanonical.Commit.Parents[1] = nonCanonical.Commit.Parents[1], nonCanonical.Commit.Parents[0]
		data, marshalErr := artifact.MarshalCanonical(nonCanonical)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, decodeErr := DecodeSignedCommit(data); !errors.Is(decodeErr, ErrNonCanonicalCommit) {
			t.Fatalf("error = %v, want %v", decodeErr, ErrNonCanonicalCommit)
		}
	})
}

func TestDecodeSignedCommitRejectsOversizedInputBeforeCBORDecode(t *testing.T) {
	if _, err := DecodeSignedCommit(make([]byte, MaxCommitBytes+1)); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidCommit)
	}
}

func TestTimestampRequiresExactUTCNanoseconds(t *testing.T) {
	value := time.Date(2026, time.August, 8, 12, 34, 56, 123, time.FixedZone("JST", 9*60*60))
	canonical := NewTimestamp(value)
	if canonical != "2026-08-08T03:34:56.000000123Z" {
		t.Fatalf("NewTimestamp = %q", canonical)
	}
	if _, err := ParseTimestamp(string(canonical)); err != nil {
		t.Fatalf("ParseTimestamp: %v", err)
	}
	invalid := []string{
		"2026-08-08T03:34:56Z",
		"2026-08-08T03:34:56.123Z",
		"2026-08-08T12:34:56.000000123+09:00",
		"2026-08-08t03:34:56.000000123z",
		"2026-02-30T03:34:56.000000123Z",
	}
	for _, candidate := range invalid {
		if _, err := ParseTimestamp(candidate); !errors.Is(err, ErrInvalidCommit) {
			t.Errorf("ParseTimestamp(%q) error = %v", candidate, err)
		}
	}
}

func TestCommitValidationLimitsAndInitialization(t *testing.T) {
	valid := baseCommit(0, nil)
	tests := []struct {
		name   string
		mutate func(*Commit)
	}{
		{name: "too many parents", mutate: func(c *Commit) {
			c.Parents = make([]digest.Digest, MaxParents+1)
			for index := range c.Parents {
				c.Parents[index] = digest.FromString(fmt.Sprintf("parent-%d", index))
			}
		}},
		{name: "duplicate parent", mutate: func(c *Commit) {
			parent := digest.FromString("parent")
			c.Parents = []digest.Digest{parent, parent}
			c.Provenance[0].Action = updateAction()
		}},
		{name: "too many provenance records", mutate: func(c *Commit) {
			record := c.Provenance[0]
			record.Action = updateAction()
			c.Parents = []digest.Digest{digest.FromString("parent")}
			c.Provenance = make([]MutationProvenance, MaxProvenanceRecords+1)
			for index := range c.Provenance {
				item := record
				item.ID = testUUID(10_000 + index)
				c.Provenance[index] = item
			}
		}},
		{name: "too many inputs", mutate: func(c *Commit) {
			c.Parents = []digest.Digest{digest.FromString("parent")}
			c.Provenance[0].Action = updateAction()
			c.Provenance[0].Inputs = make([]PinnedInput, MaxInputsPerRecord+1)
		}},
		{name: "long actor", mutate: func(c *Commit) { c.Actor = string(bytes.Repeat([]byte{'a'}, MaxActorBytes+1)) }},
		{name: "parentless mutation", mutate: func(c *Commit) { c.Provenance[0].Action = updateAction() }},
		{name: "initialization with before", mutate: func(c *Commit) { c.Provenance[0].Before = sealedPointer(testSealed("before")) }},
		{name: "initialization root mismatch", mutate: func(c *Commit) { c.Provenance[0].After = sealedPointer(testSealed("other-root")) }},
		{name: "duplicate provenance", mutate: func(c *Commit) {
			c.Parents = []digest.Digest{digest.FromString("parent")}
			c.Provenance[0].Action = updateAction()
			c.Provenance = append(c.Provenance, c.Provenance[0])
		}},
		{name: "identical mutation", mutate: func(c *Commit) {
			c.Parents = []digest.Digest{digest.FromString("parent")}
			c.Provenance[0].Action = updateAction()
			c.Provenance[0].Before = sealedPointer(*c.Provenance[0].After)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneCommit(valid)
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidCommit) {
				t.Fatalf("Validate error = %v, want %v", err, ErrInvalidCommit)
			}
		})
	}
}

package artifact

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUUID(t *testing.T) {
	t.Parallel()

	if got, err := ParseUUID(string(testResourceUID)); err != nil || got != testResourceUID {
		t.Fatalf("ParseUUID(valid) = %q, %v", got, err)
	}

	invalid := []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"11111111-1111-4111-7111-111111111111",
		"11111111-1111-0111-8111-111111111111",
		"11111111-1111-4111-8111-11111111111A",
	}
	for _, value := range invalid {
		if _, err := ParseUUID(value); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("ParseUUID(%q) error = %v, want ErrInvalidArtifact", value, err)
		}
	}
}

func TestTypeRefValidation(t *testing.T) {
	t.Parallel()

	got, err := ParseTypeRef("customer.example/v2beta3/DatabaseDump")
	if err != nil {
		t.Fatalf("ParseTypeRef(valid): %v", err)
	}
	if got.String() != "customer.example/v2beta3/DatabaseDump" {
		t.Fatalf("String() = %q", got.String())
	}
	if err := got.ValidateExtension(); err != nil {
		t.Fatalf("ValidateExtension(custom): %v", err)
	}

	reserved, err := ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	if err != nil {
		t.Fatalf("ParseTypeRef(reserved): %v", err)
	}
	if err := reserved.ValidateExtension(); !errors.Is(err, ErrReservedNamespace) {
		t.Fatalf("ValidateExtension(reserved) = %v, want ErrReservedNamespace", err)
	}

	for _, value := range []string{
		"example.com/v1",
		"Example.com/v1/Opaque",
		"example.com/1/Opaque",
		"example.com/v0/Opaque",
		"example.com/v1/opaque",
	} {
		if _, err := ParseTypeRef(value); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("ParseTypeRef(%q) error = %v, want ErrInvalidArtifact", value, err)
		}
	}
}

func TestMetadataValidation(t *testing.T) {
	t.Parallel()

	valid := validResource().Metadata
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid metadata: %v", err)
	}

	tests := map[string]Metadata{
		"path separator": {Name: "ssh/key"},
		"non NFC":        {Name: "e\u0301"},
		"bad label":      {Name: "name", Labels: map[string]string{"Bad Prefix/key": "value"}},
		"annotation NUL": {Name: "name", Annotations: map[string]string{"note": "a\x00b"}},
	}
	for name, metadata := range tests {
		if err := metadata.Validate(); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("%s: Validate() = %v, want ErrInvalidArtifact", name, err)
		}
	}

	extension := Metadata{Name: "name", Labels: map[string]string{"enbu.net/internal": "true"}}
	if err := extension.ValidateExtension(); !errors.Is(err, ErrReservedNamespace) {
		t.Fatalf("ValidateExtension() = %v, want ErrReservedNamespace", err)
	}

	tooLarge := Metadata{Name: "name", Annotations: map[string]string{"note": strings.Repeat("x", MaxMetadataBytes)}}
	if err := tooLarge.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("oversized metadata = %v, want ErrInvalidArtifact", err)
	}
}

func TestRevisionKindAndUniqueness(t *testing.T) {
	t.Parallel()

	resource := validResource()
	if err := resource.Validate(); err != nil {
		t.Fatalf("valid Resource: %v", err)
	}

	collection := Revision{
		APIVersion: APIVersion,
		Kind:       KindCollection,
		UID:        testChildUID,
		Schema:     TypeRef{Group: "example.com", Version: "v1", Kind: "Environment"},
		Metadata:   Metadata{Name: "production"},
	}
	if err := collection.Validate(); err != nil {
		t.Fatalf("valid Collection: %v", err)
	}

	emptyResource := resource
	emptyResource.Payloads = nil
	if err := emptyResource.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("empty Resource = %v, want ErrInvalidArtifact", err)
	}

	collection.Payloads = resource.Payloads
	if err := collection.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("Collection payload = %v, want ErrInvalidArtifact", err)
	}

	duplicatePayload := resource
	duplicatePayload.Payloads = append(duplicatePayload.Payloads, duplicatePayload.Payloads[0])
	if err := duplicatePayload.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("duplicate payload = %v, want ErrInvalidArtifact", err)
	}

	logicalMember := resource
	logicalMember.Edges = []Edge{{
		ID:       testEdgeID,
		Name:     "member",
		Relation: MemberRelation(),
		Strength: EdgeLogical,
		Target:   testChildUID,
	}}
	if err := logicalMember.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("logical Member = %v, want ErrInvalidArtifact", err)
	}
}

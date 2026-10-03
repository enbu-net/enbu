package artifact

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
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
		"empty name":         {Name: ""},
		"long name":          {Name: strings.Repeat("x", 254)},
		"invalid UTF-8 name": {Name: string([]byte{0xff})},
		"path separator":     {Name: "ssh/key"},
		"backslash":          {Name: "ssh\\key"},
		"control character":  {Name: "name\x7f"},
		"non NFC":            {Name: "e\u0301"},
		"bad label":          {Name: "name", Labels: map[string]string{"Bad Prefix/key": "value"}},
		"bad qualified name": {Name: "name", Labels: map[string]string{"example.com/": "value"}},
		"long label":         {Name: "name", Labels: map[string]string{"key": strings.Repeat("x", 64)}},
		"bad label value":    {Name: "name", Labels: map[string]string{"key": "has spaces"}},
		"bad annotation key": {Name: "name", Annotations: map[string]string{"bad/key/extra": "value"}},
		"annotation NUL":     {Name: "name", Annotations: map[string]string{"note": "a\x00b"}},
		"annotation UTF-8":   {Name: "name", Annotations: map[string]string{"note": string([]byte{0xff})}},
		"annotation NFC":     {Name: "name", Annotations: map[string]string{"note": "e\u0301"}},
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

func TestMetadataExtensionNamespace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		key      string
		reserved bool
	}{
		{"enbu.net/internal", true},
		{"schemas.enbu.net/internal", true},
		{"not-enbu.net/internal", false},
		{"enbu.net.example/internal", false},
		{"internal", false},
	} {
		t.Run(tc.key, func(t *testing.T) {
			m := Metadata{Name: "name", Annotations: map[string]string{tc.key: "value"}}
			err := m.ValidateExtension()
			if tc.reserved {
				if !errors.Is(err, ErrReservedNamespace) {
					t.Fatalf("error = %v, want reserved namespace", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMetadataEntryLimit(t *testing.T) {
	t.Parallel()
	m := Metadata{Name: "name", Labels: make(map[string]string)}
	for i := range MaxMetadataEntries {
		m.Labels[fmt.Sprintf("key%d", i)] = ""
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("exact entry limit: %v", err)
	}
	m.Annotations = map[string]string{"extra": "value"}
	if err := m.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("over entry limit: %v", err)
	}
}

func TestPayloadValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*PayloadRef)
	}{
		{"empty name", func(p *PayloadRef) { p.Name = "" }},
		{"long name", func(p *PayloadRef) { p.Name = strings.Repeat("x", 254) }},
		{"path name", func(p *PayloadRef) { p.Name = "a/b" }},
		{"empty media type", func(p *PayloadRef) { p.MediaType = "" }},
		{"invalid media type", func(p *PayloadRef) { p.MediaType = "text/plain; bad=" }},
		{"non sha256", func(p *PayloadRef) {
			sum := sha512.Sum512([]byte("content"))
			p.Digest = digest.Digest(fmt.Sprintf("sha512:%x", sum))
		}},
		{"negative size", func(p *PayloadRef) { p.Size = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validResource().Payloads[0]
			tc.mutate(&p)
			if err := p.Validate(); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
	p := validResource().Payloads[0]
	p.Name = strings.Repeat("x", 253)
	p.Size = 0
	p.MediaType = "text/plain; charset=utf-8"
	if err := p.Validate(); err != nil {
		t.Fatalf("valid boundary payload: %v", err)
	}
}

func TestRevisionRejectsInvalidFieldsAndEdges(t *testing.T) {
	t.Parallel()
	validEdge := func() Edge {
		return Edge{ID: testEdgeID, Name: "related", Relation: TypeRef{Group: "example.com", Version: "v1", Kind: "Related"}, Strength: EdgeLogical, Target: testChildUID}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Revision)
	}{
		{"API version", func(r *Revision) { r.APIVersion = "v2" }},
		{"kind", func(r *Revision) { r.Kind = "Unknown" }},
		{"UID", func(r *Revision) { r.UID = "invalid" }},
		{"schema", func(r *Revision) { r.Schema.Version = "v0" }},
		{"metadata", func(r *Revision) { r.Metadata.Name = "" }},
		{"payload count", func(r *Revision) { r.Payloads = make([]PayloadRef, MaxPayloads+1) }},
		{"edge count", func(r *Revision) { r.Edges = make([]Edge, MaxEdges+1) }},
		{"payload", func(r *Revision) { r.Payloads[0].Size = -1 }},
		{"edge ID", func(r *Revision) { r.Edges[0].ID = "invalid" }},
		{"edge name", func(r *Revision) { r.Edges[0].Name = "" }},
		{"edge relation", func(r *Revision) { r.Edges[0].Relation.Kind = "invalid" }},
		{"edge target", func(r *Revision) { r.Edges[0].Target = "invalid" }},
		{"edge strength", func(r *Revision) { r.Edges[0].Strength = "unknown" }},
		{"missing pinned ref", func(r *Revision) { r.Edges[0].Strength = EdgePinned }},
		{"logical pinned ref", func(r *Revision) { r.Edges[0].Pinned = &SealedRef{} }},
		{"pinned revision", func(r *Revision) { r.Edges[0].Strength = EdgePinned; r.Edges[0].Pinned = &SealedRef{} }},
		{"pinned material", func(r *Revision) {
			r.Edges[0].Strength = EdgePinned
			r.Edges[0].Pinned = &SealedRef{Revision: digest.FromString("r")}
		}},
		{"pinned grant", func(r *Revision) {
			r.Edges[0].Strength = EdgePinned
			r.Edges[0].Pinned = &SealedRef{Revision: digest.FromString("r"), Material: digest.FromString("m")}
		}},
		{"duplicate edge ID", func(r *Revision) { e := validEdge(); e.Name = "other"; r.Edges = append(r.Edges, e) }},
		{"duplicate edge name", func(r *Revision) { e := validEdge(); e.ID = testResourceUID; r.Edges = append(r.Edges, e) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validResource()
			r.Edges = []Edge{validEdge()}
			tc.mutate(&r)
			if err := r.Validate(); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Validate() = %v", err)
			}
		})
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

func TestDigestValidationPreservesNestedCause(t *testing.T) {
	t.Parallel()

	invalid := digest.Digest("sha256:" + strings.Repeat("z", 64))
	payload := PayloadRef{Name: "content", MediaType: "text/plain", Digest: invalid}
	if err := payload.Validate(); !errors.Is(err, digest.ErrDigestInvalidFormat) {
		t.Fatalf("PayloadRef.Validate() = %v, want ErrDigestInvalidFormat", err)
	}

	sealed := SealedRef{Revision: invalid, Material: digest.FromString("material"), Grant: digest.FromString("grant")}
	if err := sealed.Validate(); !errors.Is(err, digest.ErrDigestInvalidFormat) {
		t.Fatalf("SealedRef.Validate() = %v, want ErrDigestInvalidFormat", err)
	}
}

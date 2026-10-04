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

	if got, err := ParseUUID(string(testArtifactUID)); err != nil || got != testArtifactUID {
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

	for _, value := range []string{
		"example.com/v1",
		"Example.com/v1/Opaque",
		"example.com/1/Opaque",
		"example.com/v0/Opaque",
		"example.com/v" + strings.Repeat("1", 63) + "/Opaque",
		"example.com/v1/opaque",
	} {
		if _, err := ParseTypeRef(value); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("ParseTypeRef(%q) error = %v, want ErrInvalidArtifact", value, err)
		}
	}
}

func TestMetadataValidation(t *testing.T) {
	t.Parallel()

	valid := validArtifact().Metadata
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

	tooLarge := Metadata{Name: "name", Annotations: map[string]string{"note": strings.Repeat("x", MaxMetadataBytes)}}
	if err := tooLarge.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("oversized metadata = %v, want ErrInvalidArtifact", err)
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
		{"long media type", func(p *PayloadRef) { p.MediaType = "text/plain; note=" + strings.Repeat("a", MaxMediaTypeBytes-16) }},
		{"non sha256", func(p *PayloadRef) {
			sum := sha512.Sum512([]byte("content"))
			p.Digest = digest.Digest(fmt.Sprintf("sha512:%x", sum))
		}},
		{"uppercase digest", func(p *PayloadRef) { p.Digest = digest.Digest("sha256:" + strings.Repeat("A", 64)) }},
		{"short digest", func(p *PayloadRef) { p.Digest = "sha256:abc" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validArtifact().Payloads[0]
			tc.mutate(&p)
			if err := p.Validate(); !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
	p := validArtifact().Payloads[0]
	p.Name = strings.Repeat("x", 253)
	p.Size = 0
	p.MediaType = "text/plain; charset=utf-8"
	if err := p.Validate(); err != nil {
		t.Fatalf("valid boundary payload: %v", err)
	}
}

func TestDigestValidationPreservesNestedCause(t *testing.T) {
	t.Parallel()

	invalid := digest.Digest("sha256:" + strings.Repeat("z", 64))
	payload := PayloadRef{Name: "content", MediaType: "text/plain", Digest: invalid}
	if err := payload.Validate(); !errors.Is(err, digest.ErrDigestInvalidFormat) {
		t.Fatalf("PayloadRef.Validate() = %v, want ErrDigestInvalidFormat", err)
	}

}

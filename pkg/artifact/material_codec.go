package artifact

import (
	"bytes"
	"fmt"
)

// EncodeMaterialManifest returns the canonical plaintext representation that
// is encrypted by SealMaterialManifest. Payload order has no wire meaning.
func EncodeMaterialManifest(manifest MaterialManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	encoded, err := MarshalCanonical(canonicalMaterialManifest(manifest))
	if err != nil {
		return nil, fmt.Errorf("encode material manifest: %w", err)
	}
	if len(encoded) > MaxMaterialBytes {
		return nil, fmt.Errorf("%w: material manifest exceeds %d bytes", ErrInvalidArtifact, MaxMaterialBytes)
	}
	return encoded, nil
}

// DecodeMaterialManifest accepts only the canonical, strictly validated wire
// representation emitted by EncodeMaterialManifest.
func DecodeMaterialManifest(data []byte) (MaterialManifest, error) {
	if len(data) > MaxMaterialBytes {
		return MaterialManifest{}, fmt.Errorf("%w: material manifest exceeds %d bytes", ErrInvalidArtifact, MaxMaterialBytes)
	}
	var manifest MaterialManifest
	if err := UnmarshalStrict(data, &manifest); err != nil {
		return MaterialManifest{}, err
	}
	canonical, err := EncodeMaterialManifest(manifest)
	if err != nil {
		return MaterialManifest{}, err
	}
	if !bytes.Equal(data, canonical) {
		return MaterialManifest{}, ErrNonCanonicalEncoding
	}
	return manifest, nil
}

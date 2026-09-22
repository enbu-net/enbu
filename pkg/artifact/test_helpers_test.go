package artifact

import "github.com/opencontainers/go-digest"

const (
	testResourceUID UUID = "11111111-1111-4111-8111-111111111111"
	testChildUID    UUID = "22222222-2222-4222-8222-222222222222"
	testEdgeID      UUID = "33333333-3333-4333-8333-333333333333"
)

func validResource() Revision {
	return Revision{
		APIVersion: APIVersion,
		Kind:       KindResource,
		UID:        testResourceUID,
		Schema: TypeRef{
			Group:   "example.com",
			Version: "v1alpha1",
			Kind:    "Opaque",
		},
		Metadata: Metadata{
			Name: "database-password",
			Labels: map[string]string{
				"example.com/tier": "backend",
			},
			Annotations: map[string]string{
				"description": "integration fixture",
			},
		},
		Payloads: []PayloadRef{{
			Name:      "content",
			MediaType: "application/octet-stream",
			Digest:    digest.FromString("plaintext"),
			Size:      9,
		}},
	}
}

func sealedFor(revision Revision, materialSeed, grantSeed string) SealedRef {
	revisionDigest, err := CanonicalDigest(revision)
	if err != nil {
		panic(err)
	}
	return SealedRef{
		Revision: revisionDigest,
		Material: digest.FromString(materialSeed),
		Grant:    digest.FromString(grantSeed),
	}
}

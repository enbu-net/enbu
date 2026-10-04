package artifact

import "github.com/opencontainers/go-digest"

const (
	testArtifactUID UUID = "11111111-1111-4111-8111-111111111111"
)

func validArtifact() Artifact {
	return Artifact{
		APIVersion: APIVersion,
		UID:        testArtifactUID,
		Schema: TypeRef{
			Group:   "schemas.example.com",
			Version: "v1",
			Kind:    "Foo",
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

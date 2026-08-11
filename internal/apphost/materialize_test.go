package apphost

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func TestSelectMaterializePayloadRequiresExactNameForMultipleStreams(t *testing.T) {
	payloads := []artifact.PayloadRef{
		{Name: "ssid", MediaType: "text/plain", Digest: digest.FromString("ssid"), Size: 4},
		{Name: "password", MediaType: "text/plain", Digest: digest.FromString("password"), Size: 8},
	}
	if _, err := selectMaterializePayload(payloads, ""); err == nil {
		t.Fatal("multi-stream selection without a name succeeded")
	}
	selected, err := selectMaterializePayload(payloads, "password")
	if err != nil || selected.Name != "password" {
		t.Fatalf("selected = %#v, %v", selected, err)
	}
	if _, err := selectMaterializePayload(payloads, "missing"); err == nil {
		t.Fatal("missing payload selection succeeded")
	}
}

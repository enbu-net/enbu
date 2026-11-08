package cli

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
)

func TestGHCRAccessHint(t *testing.T) {
	founded := &app.InitResult{Storage: "oci://ghcr.io/enbu-net/app-enbu", Founded: true}
	if hint := ghcrAccessHint(founded); !strings.Contains(hint, "app-enbu") || !strings.Contains(hint, "Inherit access from repository") {
		t.Fatalf("hint for a new GHCR workspace: %q", hint)
	}
	for _, result := range []*app.InitResult{
		{Storage: "oci://ghcr.io/enbu-net/app-enbu"},                    // joined, not founded
		{Storage: "oci://registry.example.com/team/app", Founded: true}, // not GHCR
		{Storage: "s3://bucket/team", Founded: true},
	} {
		if hint := ghcrAccessHint(result); hint != "" {
			t.Errorf("%+v: unexpected hint %q", result, hint)
		}
	}
}

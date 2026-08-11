package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/host"
)

func TestModelRendersMetadataWithoutPayloadValues(t *testing.T) {
	uid, _ := artifact.ParseUUID("22222222-2222-4222-8222-222222222222")
	subject := &model{ctx: context.Background()}
	updated, _ := subject.Update(loadedMsg{
		snapshot:  host.WorkspaceSnapshot{ResourceCount: 1, CommitCount: 1},
		resources: []host.ResourceMetadata{{Kind: artifact.KindResource, UID: uid, Metadata: artifact.Metadata{Name: "wifi-credentials"}}},
	})
	view := updated.(*model).View().Content
	if !strings.Contains(view, "wifi-credentials") || strings.Contains(view, "super-secret-password") {
		t.Fatalf("view = %q", view)
	}
	if next, command := updated.(*model).Update(tea.KeyPressMsg{Code: 'q', Text: "q"}); next == nil || command == nil {
		t.Fatal("quit key did not return a command")
	}
}

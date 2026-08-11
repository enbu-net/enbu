//go:build legacy

package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

type hostCommandRemote struct{}

func (hostCommandRemote) Push(context.Context, artifact.Descriptor, io.Reader) error { return nil }
func (hostCommandRemote) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}
func (hostCommandRemote) Has(context.Context, digest.Digest) (bool, error) { return false, nil }
func (hostCommandRemote) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return nil
}
func (hostCommandRemote) ListAnnouncements(context.Context, string, int, *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	return registry.AnnouncementPage{}, nil
}

type hostCommandSource struct{}

func (hostCommandSource) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}

type hostCommandSink struct{}

func (hostCommandSink) Ingest(context.Context, string, io.Reader) (artifact.Descriptor, error) {
	return artifact.Descriptor{}, errors.New("unused")
}

func TestHostCommandUsesControllerAndSafeOutput(t *testing.T) {
	h := host.New()
	session, err := h.OpenSession(context.Background(), host.SessionOptions{
		WorkspaceID: "01234567-89ab-4def-8123-456789abcdef", Root: t.TempDir(),
		Remote: hostCommandRemote{}, Source: hostCommandSource{}, Sink: hostCommandSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := client.NewController(h, session)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewHostCommand(HostCommandOptions{Controller: controller, Actions: map[string]host.Action{
		"inspect": func(_ context.Context, r *host.Reporter) error { return r.Report("done", "secret") },
	}})
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"run", "inspect"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "done") || strings.Contains(out.String(), "secret") {
		t.Fatalf("unsafe host output: %q", out.String())
	}
}

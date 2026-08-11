//go:build legacy

package desktop

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

type operationRemote struct{}

func (operationRemote) Push(context.Context, artifact.Descriptor, io.Reader) error { return nil }
func (operationRemote) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}
func (operationRemote) Has(context.Context, digest.Digest) (bool, error) { return false, nil }
func (operationRemote) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return nil
}
func (operationRemote) ListAnnouncements(context.Context, string, int, *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	return registry.AnnouncementPage{}, nil
}

type operationSource struct{}

func (operationSource) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}

type operationSink struct{}

func (operationSink) Ingest(context.Context, string, io.Reader) (artifact.Descriptor, error) {
	return artifact.Descriptor{}, errors.New("unused")
}

func TestHostOperationsPollDoesNotExposeReporterMessages(t *testing.T) {
	h := host.New()
	session, err := h.OpenSession(context.Background(), host.SessionOptions{
		WorkspaceID: "01234567-89ab-4def-8123-456789abcdef", Root: t.TempDir(),
		Remote: operationRemote{}, Source: operationSource{}, Sink: operationSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := client.NewController(h, session)
	if err != nil {
		t.Fatal(err)
	}
	operations := NewHostOperations(controller)
	if err := operations.Register("test", func(_ context.Context, r *host.Reporter) error {
		return r.Report("finished", "secret-value")
	}); err != nil {
		t.Fatal(err)
	}
	started, err := operations.Start(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	var status HostOperationStatus
	for !status.Done {
		status, err = operations.Poll(started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range status.Events {
		if event.Phase == "secret-value" {
			t.Fatal("unsafe message crossed Wails boundary")
		}
	}
}

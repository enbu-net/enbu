//go:build legacy

package tui

import (
	"context"
	"errors"
	"io"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

type tuiRemote struct{}

func (tuiRemote) Push(context.Context, artifact.Descriptor, io.Reader) error { return nil }
func (tuiRemote) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}
func (tuiRemote) Has(context.Context, digest.Digest) (bool, error) { return false, nil }
func (tuiRemote) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return nil
}
func (tuiRemote) ListAnnouncements(context.Context, string, int, *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	return registry.AnnouncementPage{}, nil
}

type tuiSource struct{}

func (tuiSource) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}

type tuiSink struct{}

func (tuiSink) Ingest(context.Context, string, io.Reader) (artifact.Descriptor, error) {
	return artifact.Descriptor{}, errors.New("unused")
}

func TestHostModelUsesSafeProgress(t *testing.T) {
	h := host.New()
	session, err := h.OpenSession(context.Background(), host.SessionOptions{
		WorkspaceID: "01234567-89ab-4def-8123-456789abcdef", Root: t.TempDir(),
		Remote: tuiRemote{}, Source: tuiSource{}, Sink: tuiSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := client.NewController(h, session)
	if err != nil {
		t.Fatal(err)
	}
	m := NewHostModel(context.Background(), controller, "inspect", func(_ context.Context, r *host.Reporter) error {
		return r.Report("phase", "secret")
	})
	msg := m.Init()()
	var cmd tea.Cmd
	updated, cmd := m.Update(msg)
	m = updated.(*HostModel)
	for !m.Done() && cmd != nil {
		updated, next := m.Update(cmd())
		m = updated.(*HostModel)
		cmd = next
	}
	if m.Err() != nil {
		t.Fatal(m.Err())
	}
	if m.LastEvent().Phase != "succeeded" {
		t.Fatalf("phase = %q", m.LastEvent().Phase)
	}
}

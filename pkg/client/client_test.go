//go:build legacy

package client

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

type remote struct{}

func (remote) Push(context.Context, artifact.Descriptor, io.Reader) error { return nil }
func (remote) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}
func (remote) Has(context.Context, digest.Digest) (bool, error) { return false, nil }
func (remote) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return nil
}
func (remote) ListAnnouncements(context.Context, string, int, *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	return registry.AnnouncementPage{}, nil
}

type remoteSource struct{}

func (remoteSource) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("unused")
}

type remoteSink struct{}

func (remoteSink) Ingest(context.Context, string, io.Reader) (artifact.Descriptor, error) {
	return artifact.Descriptor{}, errors.New("unused")
}

func TestControllerDropsReporterMessages(t *testing.T) {
	h := host.New()
	root := t.TempDir()
	session, err := h.OpenSession(context.Background(), host.SessionOptions{
		WorkspaceID: "01234567-89ab-4def-8123-456789abcdef",
		Root:        root,
		Remote:      remote{},
		Source:      remoteSource{},
		Sink:        remoteSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(h, session)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.Start(context.Background(), "inspect", func(_ context.Context, r *host.Reporter) error {
		if err := r.Report("safe", "secret-value"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for event := range op.Progress {
		events = append(events, event)
	}
	if err := c.Wait(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Phase == "secret-value" {
			t.Fatal("reporter message crossed client boundary")
		}
	}
}

func TestRunCLIOutputsOnlyPhases(t *testing.T) {
	h := host.New()
	session, err := h.OpenSession(context.Background(), host.SessionOptions{
		WorkspaceID: "01234567-89ab-4def-8123-456789abcdef",
		Root:        t.TempDir(), Remote: remote{}, Source: remoteSource{}, Sink: remoteSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewController(h, session)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := c.RunCLI(context.Background(), "publish", func(_ context.Context, _ *host.Reporter) error {
		return errors.New("secret-value")
	}, &out); err == nil || !strings.Contains(out.String(), "failed") {
		t.Fatalf("expected failed phase and action error, output=%q err=%v", out.String(), err)
	}
	if strings.Contains(out.String(), "secret-value") {
		t.Fatal("action error crossed CLI boundary")
	}
}

package host

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

type emptySource struct{}

func (emptySource) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("not found")
}

type emptySink struct{}

func (emptySink) Ingest(context.Context, string, io.Reader) (artifact.Descriptor, error) {
	return artifact.Descriptor{}, errors.New("not implemented")
}

type emptyRemote struct{}

func (emptyRemote) Push(context.Context, artifact.Descriptor, io.Reader) error { return nil }
func (emptyRemote) Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	return nil, artifact.Descriptor{}, errors.New("not found")
}
func (emptyRemote) Has(context.Context, digest.Digest) (bool, error) { return false, nil }
func (emptyRemote) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return nil
}
func (emptyRemote) ListAnnouncements(context.Context, string, int, *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	return registry.AnnouncementPage{}, nil
}

func TestSessionIsImmutableAndOperationsShareContext(t *testing.T) {
	workspace, err := artifact.ParseUUID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	host := New()
	session, err := host.OpenSession(context.Background(), SessionOptions{WorkspaceID: workspace, Root: filepath.Join(t.TempDir(), "workspace"), Remote: emptyRemote{}, Source: emptySource{}, Sink: emptySink{}, ConfigRevision: "config-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if session.WorkspaceID() != workspace || session.ConfigRevision() != "config-v1" {
		t.Fatal("session accessors changed")
	}
	operation, err := host.Start(context.Background(), session, "sync", func(ctx context.Context, reporter *Reporter) error {
		if err := reporter.Report("working", "bounded progress"); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	result := <-operation.Done
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.OperationID != operation.ID {
		t.Fatal("operation ID mismatch")
	}
	if err := host.CloseSession(session); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Start(context.Background(), session, "sync", func(context.Context, *Reporter) error { return nil }); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("closed session error = %v", err)
	}
}

func TestProgressFieldsAreBounded(t *testing.T) {
	reporter := &Reporter{id: "11111111-1111-4111-8111-111111111111", output: make(chan Progress, 1)}
	if err := reporter.Report("phase", strings.Repeat("x", MaxProgressMessage+1)); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("oversized progress = %v", err)
	}
}

func TestOpenSessionRejectsLegacyConfigurationBeforeCreatingPrivateDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "enbu.toml"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := artifact.ParseUUID("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	h := New()
	_, err = h.OpenSession(context.Background(), SessionOptions{WorkspaceID: workspace, Root: root, Remote: emptyRemote{}, Source: emptySource{}, Sink: emptySink{}})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported legacy format, got %v", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 && runtime.GOOS != "windows" {
		t.Fatalf("legacy rejection mutated directory mode: %o", info.Mode().Perm())
	}
}

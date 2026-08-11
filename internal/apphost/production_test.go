package apphost

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
)

func TestProductionAuditFactoryPersistsIdentityAndReopens(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	stateDir := t.TempDir()
	objects, err := cas.New(filepath.Join(stateDir, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Errorf("close CAS: %v", err)
		}
	})
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	credentials := newTestCredentials()
	factory := productionAuditFactory{}
	trail, closer, err := factory.Open(ctx, workspaceID, stateDir, objects, device, credentials, "github:12345", true)
	if err != nil {
		t.Fatalf("initialize audit: %v", err)
	}
	if trail == nil || closer == nil {
		t.Fatal("factory returned nil audit capability")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := artifact.AuditIdentityCredentialKey(workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Load(ctx, key); err != nil {
		t.Fatalf("load persisted identity: %v", err)
	}
	_, reopened, err := factory.Open(ctx, workspaceID, stateDir, objects, device, credentials, "github:12345", false)
	if err != nil {
		t.Fatalf("reopen audit: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionAuditFactoryNeverCreatesIdentityWhileOpening(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	objects, err := cas.New(filepath.Join(stateDir, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Errorf("close CAS: %v", err)
		}
	})
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	credentials := newTestCredentials()
	_, _, err = (productionAuditFactory{}).Open(context.Background(), workspaceID, stateDir, objects, device, credentials, "github:12345", false)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open = %v, want fs.ErrNotExist", err)
	}
	credentials.mu.Lock()
	count := len(credentials.values)
	credentials.mu.Unlock()
	if count != 0 {
		t.Fatalf("opening missing audit identity wrote %d credentials", count)
	}
}

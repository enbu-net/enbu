package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSyncReturnsNonNotFoundSecretPullErrors(t *testing.T) {
	a, rec := newSeededApp(t, map[string]string{"KEY": "value"})
	rec.failStates = errors.New("unauthorized")

	err := a.SyncSecrets(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "pulling secrets") || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected pulling secrets unauthorized error, got %v", err)
	}
}

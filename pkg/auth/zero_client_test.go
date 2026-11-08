package auth

import (
	"context"
	"errors"
	"testing"
)

func TestZeroClientHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := Client{}
	if _, err := c.Login(ctx, func(DeviceAuthorization) error { t.Fatal("prompted after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("device login: %v", err)
	}
}

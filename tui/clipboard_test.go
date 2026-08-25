package tui

import (
	"context"
	"errors"
	"slices"
	"testing"

	"golang.design/x/clipboard"
)

func TestCopyToClipboardWritesTextAfterInitialization(t *testing.T) {
	var calls []string
	setClipboardFunctions(t, func() error {
		calls = append(calls, "init")
		return nil
	}, func(ctx context.Context, format clipboard.Format, data []byte, _ ...clipboard.Option) (<-chan struct{}, error) {
		calls = append(calls, "write")
		if ctx == nil {
			t.Fatal("clipboard write context is nil")
		}
		if format != clipboard.FmtText {
			t.Fatalf("clipboard format = %v, want %v", format, clipboard.FmtText)
		}
		if got := string(data); got != "secret" {
			t.Fatalf("clipboard data = %q, want %q", got, "secret")
		}
		return make(chan struct{}), nil
	})

	if err := copyToClipboard("secret"); err != nil {
		t.Fatalf("copyToClipboard() error = %v", err)
	}
	if want := []string{"init", "write"}; !slices.Equal(calls, want) {
		t.Fatalf("clipboard calls = %v, want %v", calls, want)
	}
}

func TestCopyToClipboardReturnsInitializationErrorWithoutWriting(t *testing.T) {
	initErr := errors.New("init clipboard")
	writeCalled := false
	setClipboardFunctions(t, func() error {
		return initErr
	}, func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error) {
		writeCalled = true
		return nil, nil
	})

	err := copyToClipboard("secret")
	if !errors.Is(err, initErr) {
		t.Fatalf("copyToClipboard() error = %v, want %v", err, initErr)
	}
	if writeCalled {
		t.Fatal("clipboard write called after initialization failed")
	}
}

func TestCopyToClipboardReturnsWriteError(t *testing.T) {
	writeErr := errors.New("write clipboard")
	setClipboardFunctions(t, func() error {
		return nil
	}, func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error) {
		return nil, writeErr
	})

	if err := copyToClipboard("secret"); !errors.Is(err, writeErr) {
		t.Fatalf("copyToClipboard() error = %v, want %v", err, writeErr)
	}
}

func setClipboardFunctions(
	t *testing.T,
	initFn func() error,
	writeFn func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error),
) {
	t.Helper()
	originalInit := clipboardInit
	originalWrite := clipboardWrite
	clipboardInit = initFn
	clipboardWrite = writeFn
	t.Cleanup(func() {
		clipboardInit = originalInit
		clipboardWrite = originalWrite
	})
}

package tui

import (
	"context"
	"errors"
	"testing"

	"golang.design/x/clipboard"
)

func TestCopyToClipboardWithWritesText(t *testing.T) {
	var gotContext context.Context
	var gotFormat clipboard.Format
	var gotText string

	err := copyToClipboardWith(context.Background(), "secret", func() error {
		return nil
	}, func(ctx context.Context, format clipboard.Format, data []byte, _ ...clipboard.Option) (<-chan struct{}, error) {
		gotContext = ctx
		gotFormat = format
		gotText = string(data)
		return make(chan struct{}), nil
	})
	if err != nil {
		t.Fatalf("copyToClipboardWith() error = %v", err)
	}
	if gotContext == nil {
		t.Fatal("clipboard write context is nil")
	}
	if gotFormat != clipboard.FmtText {
		t.Fatalf("clipboard format = %v, want %v", gotFormat, clipboard.FmtText)
	}
	if gotText != "secret" {
		t.Fatalf("clipboard text = %q, want %q", gotText, "secret")
	}
}

func TestCopyToClipboardWithReturnsErrors(t *testing.T) {
	initErr := errors.New("init clipboard")
	writeCalled := false
	err := copyToClipboardWith(context.Background(), "secret", func() error {
		return initErr
	}, func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error) {
		writeCalled = true
		return nil, nil
	})
	if !errors.Is(err, initErr) {
		t.Fatalf("copyToClipboardWith() error = %v, want %v", err, initErr)
	}
	if writeCalled {
		t.Fatal("clipboard write called after initialization failed")
	}

	writeErr := errors.New("write clipboard")
	err = copyToClipboardWith(context.Background(), "secret", func() error {
		return nil
	}, func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error) {
		return nil, writeErr
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("copyToClipboardWith() error = %v, want %v", err, writeErr)
	}
}

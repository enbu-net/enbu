package main

import (
	"context"
	"errors"
	"github.com/ncruces/zenity"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// Wails v3.0.0's Windows picker returns an internal, unexported cancellation
// sentinel. Use the native picker with an exported ErrCanceled instead, so
// genuine failures remain errors and cancellation needs no message matching.
// Return to Wails when its public picker represents cancellation as empty/nil
// or exposes the sentinel; do not match its internal error text.
func pickDirectory(ctx context.Context, _ *application.App, window *application.WebviewWindow) (string, error) {
	var owner uintptr
	if window != nil {
		owner = uintptr(window.NativeWindow())
	}
	return selectDirectory(ctx, owner, zenity.SelectFile)
}
func selectDirectory(ctx context.Context, owner uintptr, selectFile func(...zenity.Option) (string, error)) (string, error) {
	path, err := selectFile(zenity.Context(ctx), zenity.Title("Select folder"), zenity.Directory(), zenity.Attach(owner))
	if errors.Is(err, zenity.ErrCanceled) {
		return "", nil
	}
	return path, err
}

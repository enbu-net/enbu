//go:build !windows

package main

import (
	"context"
	"github.com/wailsapp/wails/v3/pkg/application"
)

func pickDirectory(_ context.Context, app *application.App, window *application.WebviewWindow) (string, error) {
	return app.Dialog.OpenFile().SetTitle("Select folder").AttachToWindow(window).CanChooseFiles(false).CanChooseDirectories(true).CanCreateDirectories(true).PromptForSingleSelection()
}

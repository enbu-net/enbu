package tui

import (
	"context"

	"golang.design/x/clipboard"
)

// Keep the OS boundary replaceable so the adapter contract can be tested
// without accessing a developer or CI runner's real clipboard.
var (
	clipboardInit  = clipboard.Init
	clipboardWrite = clipboard.Write
)

func copyToClipboard(text string) error {
	if err := clipboardInit(); err != nil {
		return err
	}
	_, err := clipboardWrite(context.Background(), clipboard.FmtText, []byte(text))
	return err
}

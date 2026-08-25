package tui

import (
	"context"

	"golang.design/x/clipboard"
)

func copyToClipboard(text string) error {
	if err := clipboard.Init(); err != nil {
		return err
	}
	_, err := clipboard.Write(context.Background(), clipboard.FmtText, []byte(text))
	return err
}

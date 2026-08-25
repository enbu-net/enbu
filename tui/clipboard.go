package tui

import (
	"context"

	"golang.design/x/clipboard"
)

type clipboardWriteFunc func(context.Context, clipboard.Format, []byte, ...clipboard.Option) (<-chan struct{}, error)

func copyToClipboard(text string) error {
	return copyToClipboardWith(context.Background(), text, clipboard.Init, clipboard.Write)
}

func copyToClipboardWith(ctx context.Context, text string, initClipboard func() error, write clipboardWriteFunc) error {
	if err := initClipboard(); err != nil {
		return err
	}
	_, err := write(ctx, clipboard.FmtText, []byte(text))
	return err
}

//go:build legacy

package tui

import "golang.design/x/clipboard"

func copyToClipboard(text string) error {
	if err := clipboard.Init(); err != nil {
		return err
	}
	clipboard.Write(clipboard.FmtText, []byte(text))
	return nil
}

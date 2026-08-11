//go:build legacy

package tui

import "github.com/enbu-net/enbu/internal/application"

type workspaceLoadedMsg struct {
	secrets    map[string]string
	envs       []envItem
	current    string
	repository string
}

type recipientsLoadedMsg struct{ recipients []app.RecipientInfo }
type configLoadedMsg struct{ content string }
type configSavedMsg struct{}
type operationDoneMsg struct{ message string }
type clipboardDoneMsg struct{ message string }
type errMsg struct{ err error }

type envItem struct {
	name      string
	isCurrent bool
}

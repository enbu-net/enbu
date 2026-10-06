package tui

import "github.com/enbu-net/enbu/app"

type workspaceLoadedMsg struct {
	secrets    map[string]string
	envs       []envItem
	current    string
	repository string
}

type recipientsLoadedMsg struct {
	recipients []app.RecipientInfo
	requests   []app.JoinRequestInfo
}
type memberApprovedMsg struct{ message string }
type configLoadedMsg struct{ content string }
type configSavedMsg struct{}
type operationDoneMsg struct{ message string }
type clipboardDoneMsg struct{ message string }
type errMsg struct{ err error }

type envItem struct {
	name      string
	isCurrent bool
}

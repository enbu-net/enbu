package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	Up, Down, Add, Edit, Delete, Switch, Refresh, Pull, Export key.Binding
	Enter, Escape, Quit, Tab, TabNext, TabPrev                 key.Binding
	SecretsTab, MembersTab, SettingsTab                        key.Binding
	Reveal, CopyValue, CopyKey, ToggleView, Save               key.Binding
}

func binding(keys ...string) key.Binding { return key.NewBinding(key.WithKeys(keys...)) }

var keys = keyMap{
	Up: binding("up", "k"), Down: binding("down", "j"),
	Add: binding("a"), Edit: binding("e"), Delete: binding("d"), Switch: binding("s"),
	Refresh: binding("r"), Pull: binding("p"), Export: binding("x"), Enter: binding("enter"), Escape: binding("esc"),
	Quit: binding("q", "ctrl+c"), Tab: binding("tab"), TabNext: binding("right", "l"), TabPrev: binding("left", "h"),
	SecretsTab: binding("1"), MembersTab: binding("2"), SettingsTab: binding("3"),
	Reveal: binding("space", "v"), CopyValue: binding("y"), CopyKey: binding("Y"), ToggleView: binding("v"),
	Save: binding("ctrl+s"),
}

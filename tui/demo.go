package tui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	"github.com/enbu-net/enbu/app"
)

var (
	demoSecretsByEnv = map[string][]secretEntry{
		"development": {
			{key: "API_KEY", value: "sk-demo-abc123"},
			{key: "DATABASE_URL", value: "postgres://localhost:5432/enbu"},
			{key: "SECRET_TOKEN", value: "tok-enbu-xyz789"},
		},
		"production": {
			{key: "API_KEY", value: "sk-prod-abc123"},
			{key: "DATABASE_URL", value: "postgres://prod.example.com:5432/enbu"},
		},
		"staging": {{key: "API_KEY", value: "sk-stg-abc123"}},
	}
	demoEnvs = []envItem{
		{name: "development", isCurrent: true},
		{name: "production"},
		{name: "staging"},
	}
	demoCurrent    = "development"
	demoRecipients = []app.RecipientInfo{
		{Username: "octocat", Fingerprint: "abc123def456"},
		{Username: "hubot", Fingerprint: "xyz789ghi012"},
	}
	demoConfigContent = `version = "v1alpha1"
default_env = "development"

[env.development]
output = ".env.development"

[env.production]
output = ".env.production"

[env.staging]
output = ".env.staging"
`
)

func RunDemo() error {
	m := newDemoModel()
	p := tea.NewProgram(m, demoProgramOptions()...)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui demo: %w", err)
	}
	return nil
}

func newDemoModel() *model {
	m := newModel(nil)
	m.animateSpinner = false
	m.loading = false
	m.current = demoCurrent
	m.repository = "enbu-net/enbu"
	m.secrets = append([]secretEntry(nil), demoSecretsByEnv[demoCurrent]...)
	m.envs = append([]envItem(nil), demoEnvs...)
	return m
}

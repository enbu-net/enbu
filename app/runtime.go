package app

import (
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"time"
	"uuid"
)

// Runtime isolates clocks, identifiers, encryption and personal state without
// changing process globals. Unset dependencies retain production behavior.
// Encryption injection never bypasses decryption or protocol verification.
type Runtime struct {
	Clock         clock.Clock
	NewID         func() string
	Encrypt       func([]byte, []string) ([]byte, error)
	LocalStateDir string
}

func (a *App) now() time.Time {
	return a.clock().Now()
}
func (a *App) clock() clock.Clock {
	if a.Runtime != nil && a.Runtime.Clock != nil {
		return a.Runtime.Clock
	}
	return clock.New()
}
func (a *App) newID() string {
	if a.Runtime != nil && a.Runtime.NewID != nil {
		return a.Runtime.NewID()
	}
	return uuid.NewV4().String()
}
func (a *App) encrypt(p []byte, recipients []string) ([]byte, error) {
	if a.Runtime != nil && a.Runtime.Encrypt != nil {
		return a.Runtime.Encrypt(p, recipients)
	}
	return age.EncryptForPublicKeys(p, recipients)
}
func (a *App) localStateDir() string {
	if a.Runtime != nil && a.Runtime.LocalStateDir != "" {
		return a.Runtime.LocalStateDir
	}
	return config.DataDir()
}
func (a *App) loadLocalState(id string) (*config.LocalConfig, error) {
	return config.LoadLocalStateFrom(a.localStateDir(), id)
}
func (a *App) saveLocalState(id string, c *config.LocalConfig) error {
	return config.SaveLocalStateTo(a.localStateDir(), id, c)
}
func (a *App) newProject(name string) *config.ProjectConfig {
	return config.NewProjectWithIDs(name, a.newID)
}

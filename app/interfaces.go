package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/identity"
)

type TokenProvider interface {
	LoadToken() (accessToken string, username string, err error)
}

// IdentityStore keeps this device's keys, one set per workspace.
type IdentityStore interface {
	Create(workspaceID string) (*identity.Device, identity.PublicInfo, string, error)
	Load(workspaceID string) (*identity.Device, error)
	Info(workspaceID string) (identity.PublicInfo, error)
	Doctor(context.Context) identity.Diagnosis
}

type RepoDetector interface {
	LoadRepo() (owner, repo string, err error)
}

type ProgressStep struct {
	Op     string `json:"op"`     // "add" | "pull" | "sync" | "delete"
	Step   string `json:"step"`   // "encrypt" | "push" | "pull_secrets" | "pull_recipients" | "reencrypt" | "decrypt" | "write"
	Status string `json:"status"` // "start" | "done"
}

type EventHandler interface {
	OnProgress(msg string)
	OnStepProgress(step ProgressStep)
	OnConflictRetry(attempt, maxAttempts int)
}

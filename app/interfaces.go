package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/provider"
	"github.com/enbu-net/enbu/pkg/signing"
)

type TokenProvider interface {
	LoadToken() (accessToken string, username string, err error)
}

type IdentityStore interface {
	Create(workspaceID string) (identity.Identity, identity.PublicInfo, string, error)
	Load(workspaceID string) (identity.Identity, error)
	Info(workspaceID string) (identity.PublicInfo, error)
	Doctor() identity.Diagnosis
	// The signing key is a separate keypair from the encryption identity.
	CreateSigner(workspaceID string) (signing.Signer, identity.SignerInfo, string, error)
	LoadSigner(workspaceID string) (signing.Signer, error)
	SignerInfo(workspaceID string) (identity.SignerInfo, error)
}

type RepoDetector interface {
	LoadRepo() (owner, repo string, err error)
}

type PlatformClient interface {
	GetUser(ctx context.Context) (*provider.User, error)
	IsOrganization(ctx context.Context, login string) bool
	SourceRepoURL(owner, repo string) string
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

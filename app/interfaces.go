package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/oci"
	"github.com/enbu-net/enbu/pkg/provider"
)

type Registry interface {
	Push(ctx context.Context, ref string, mediaType string, data []byte, token string, opts *oci.PushOptions) error
	Pull(ctx context.Context, ref string, token string) ([]byte, error)
	ListTags(ctx context.Context, ref string, token string) ([]string, error)
	GetDigest(ctx context.Context, ref string, token string) (string, error)
}

type TokenProvider interface {
	LoadToken() (accessToken string, username string, err error)
}

type IdentityStore interface {
	Create(owner, repo string) (identity.Identity, identity.PublicInfo, string, error)
	Load(owner, repo string) (identity.Identity, error)
	Info(owner, repo string) (identity.PublicInfo, error)
	Doctor() identity.Diagnosis
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

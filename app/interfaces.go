package app

import (
	"context"

	"github.com/enbu-net/enbu/provider"
	"github.com/enbu-net/enbu/utils/oci"
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

type KeyStore interface {
	Store(service, key string, value []byte) error
	Load(service, key string) ([]byte, error)
}

type SecretCache interface {
	Load(ref string) ([]byte, error)
	Store(ref string, ciphertext []byte) error
	Delete(ref string) error
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
	Op     string `json:"op"`     // "add" | "pull" | "export" | "sync" | "delete"
	Step   string `json:"step"`   // "download" | "validate" | "cache" | "load" | "decrypt" | "export" | ...
	Status string `json:"status"` // "start" | "done"
}

type EventHandler interface {
	OnProgress(msg string)
	OnStepProgress(step ProgressStep)
	OnConflictRetry(attempt, maxAttempts int)
}

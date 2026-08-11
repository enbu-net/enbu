package apphost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/audit"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/platform"
	"github.com/enbu-net/enbu/pkg/registry"
)

// ProductionIdentity is the provider-qualified identity used for enrollment.
// The immutable provider ID, rather than the mutable username, is signed into
// device assertions and commits.
type ProductionIdentity struct {
	Subject  string
	Username string
}

// NewProduction constructs the trusted process-wide runtime using only the
// native OS credential store, the authenticated exact OCI repository factory,
// and a per-workspace encrypted audit journal. It deliberately has no
// plaintext credential or filesystem fallback.
func NewProduction(ctx context.Context) (*Runtime, ProductionIdentity, error) {
	if ctx == nil {
		return nil, ProductionIdentity{}, errors.New("apphost: nil production context")
	}
	if err := ctx.Err(); err != nil {
		return nil, ProductionIdentity{}, err
	}
	backend, err := keystore.New()
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	credentials, err := keystore.NewCredentialStore(backend)
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	token, err := auth.LoadToken()
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	// A mutable username is not an enrollment identity. Environment-only bot
	// tokens do not carry a verified immutable user ID and are rejected here.
	if token.UserID <= 0 || token.Username == "" || token.AccessToken == "" {
		return nil, ProductionIdentity{}, errors.New("apphost: authenticated GitHub user ID is required")
	}
	dataDir, err := platform.DataDir()
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	catalog, err := newFilePluginCatalog(filepath.Join(dataDir, "plugins"))
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	runtime, err := New(Dependencies{
		Credentials: credentials,
		Remotes:     productionRemoteProvider{username: token.Username, token: token.AccessToken},
		Audits:      productionAuditFactory{},
		Plugins:     catalog,
		DataDir:     dataDir,
	})
	if err != nil {
		return nil, ProductionIdentity{}, err
	}
	return runtime, ProductionIdentity{
		Subject:  fmt.Sprintf("github:%d", token.UserID),
		Username: token.Username,
	}, nil
}

type productionRemoteProvider struct {
	username string
	token    string
}

func (provider productionRemoteProvider) Open(ctx context.Context, reference string) (registry.Remote, error) {
	if ctx == nil {
		return nil, errors.New("apphost: nil registry context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return registry.NewRepositoryRemote(reference, registry.RepositoryAuth{
		Username: provider.username,
		Password: provider.token,
	})
}

type productionAuditFactory struct{}

func (productionAuditFactory) Open(
	ctx context.Context,
	workspaceID artifact.UUID,
	stateDir string,
	objects *cas.Store,
	device *artifact.DeviceIdentity,
	credentials artifact.CredentialStore,
	actor string,
	initialize bool,
) (engine.AuditTrail, io.Closer, error) {
	if ctx == nil || objects == nil || device == nil {
		return nil, nil, errors.New("apphost: invalid audit dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	identity, err := artifact.LoadAuditIdentity(ctx, credentials, workspaceID)
	if err != nil {
		if !initialize || !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		identity, err = artifact.GenerateMaterialIdentity()
		if err != nil {
			return nil, nil, err
		}
		if err := artifact.SaveAuditIdentity(ctx, credentials, workspaceID, identity); err != nil {
			return nil, nil, err
		}
	}
	journal, err := audit.NewJournal(filepath.Join(stateDir, "audit.journal"), objects, objects, identity, device)
	if err != nil {
		return nil, nil, err
	}
	trail, err := engine.NewJournalAuditTrail(journal, device, actor, nil)
	if err != nil {
		_ = journal.Close()
		return nil, nil, err
	}
	return trail, journal, nil
}

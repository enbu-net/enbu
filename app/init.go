package app

import (
	"context"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/google/uuid"
)

type InitResult struct {
	PublicKey   string   `json:"public_key"`
	Username    string   `json:"username"`
	Environment string   `json:"environment"`
	WorkspaceID string   `json:"workspace_id"`
	Storage     string   `json:"storage"`
	KeyCreated  bool     `json:"key_created"`
	Mode        string   `json:"mode"`
	HasSecrets  bool     `json:"has_secrets"`
	CanDecrypt  *bool    `json:"can_decrypt"`
	Warnings    []string `json:"-"`
}

func (a *App) InitializeRepository(ctx context.Context) (result *InitResult, err error) {
	defer apperr.NormalizeInto(&err)
	cfg, err := a.loadProject()
	missing := apperr.Is(err, apperr.CodeConfigNotFound)
	if err != nil && !missing {
		return nil, err
	}
	if missing {
		cfg = config.NewProjectWithEnvironment(DefaultEnvironment)
	}
	if a.InitStorage != nil {
		cfg.Storage = *a.InitStorage
	}
	if a.StorageURL != "" {
		cfg.Storage.URL = a.StorageURL
	}
	store, err := a.openStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	metadata, _, err := store.Get(ctx, workspaceKey)
	if errors.Is(err, storage.ErrNotFound) {
		if cfg.WorkspaceID == "" {
			cfg.WorkspaceID = uuid.NewString()
		}
		if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
			return nil, err
		}
		err = store.Put(ctx, workspaceKey, storage.Object{MediaType: workspaceMediaType, Data: []byte(cfg.WorkspaceID)}, "")
		if errors.Is(err, storage.ErrConflict) {
			metadata, _, err = store.Get(ctx, workspaceKey)
		} else if err == nil {
			metadata = storage.Object{MediaType: workspaceMediaType, Data: []byte(cfg.WorkspaceID)}
		}
	}
	if err != nil {
		return nil, storageError(err)
	}
	if metadata.MediaType != workspaceMediaType {
		return nil, fmt.Errorf("invalid workspace metadata")
	}
	if _, err := uuid.Parse(string(metadata.Data)); err != nil {
		return nil, fmt.Errorf("invalid stored workspace ID: %w", err)
	}
	if missing {
		cfg.WorkspaceID = string(metadata.Data)
	}
	if cfg.WorkspaceID != string(metadata.Data) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "storage belongs to a different workspace", nil)
	}
	// Save the workspace binding before registration, so a failed registration
	// retries the same local identity rather than generating another key.
	if err := a.saveProject(cfg); err != nil {
		return nil, err
	}
	id, info, warning, err := a.Identities.Create(cfg.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = id.Close() }()
	publicKey := id.Recipient().String()
	key := RecipientKey(publicKey)
	o, _, err := store.Get(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		o = storage.Object{MediaType: recipientMediaType, Data: []byte(publicKey)}
		err = store.Put(ctx, key, o, "")
	}
	if errors.Is(err, storage.ErrConflict) {
		o, _, err = store.Get(ctx, key)
	}
	if err != nil {
		return nil, storageError(err)
	}
	if o.MediaType != recipientMediaType || string(o.Data) != publicKey {
		return nil, fmt.Errorf("recipient fingerprint collision or corrupt record")
	}
	result = &InitResult{PublicKey: publicKey, Username: publicKey, Environment: cfg.CurrentEnvironment(), WorkspaceID: cfg.WorkspaceID, Storage: cfg.Storage.URL, KeyCreated: info.Created, Mode: "initialize"}
	if warning != "" {
		result.Warnings = append(result.Warnings, warning)
		a.emit(warning)
	}
	secret, _, err := store.Get(ctx, secretsTag(cfg.CurrentEnvironment()))
	if err == nil {
		result.Mode = "join"
		result.HasSecrets = true
		_, decryptErr := decryptSecretsObject(secret, id)
		var noMatch *agecrypto.NoIdentityMatchError
		if decryptErr != nil && !errors.As(decryptErr, &noMatch) {
			return nil, decryptErr
		}
		canDecrypt := decryptErr == nil
		result.CanDecrypt = &canDecrypt
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, storageError(err)
	}
	return result, nil
}

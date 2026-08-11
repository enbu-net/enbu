package artifact

import (
	"bytes"
	"context"
	"fmt"

	"github.com/opencontainers/go-digest"
)

const (
	auditCredentialAPIVersion = "credentials.enbu.net/v1alpha1"
	auditCredentialKind       = "AuditIdentity"
	maxAuditCredentialBytes   = 1024
)

type auditCredential struct {
	APIVersion string `cbor:"apiVersion"`
	Kind       string `cbor:"kind"`
	Workspace  UUID   `cbor:"workspace"`
	Identity   string `cbor:"identity"`
}

// AuditIdentityCredentialKey returns the fixed per-workspace keychain key.
// Workspace-controlled strings cannot select a service namespace or arbitrary
// credential key.
func AuditIdentityCredentialKey(workspace UUID) (string, error) {
	if err := workspace.Validate(); err != nil {
		return "", fmt.Errorf("audit identity workspace: %w", err)
	}
	return "audit-identity-v1-" + digest.FromString(string(workspace)).Encoded(), nil
}

// SaveAuditIdentity persists only the long-lived identity used to decrypt the
// local hash-chained audit journal. Per-material and per-Commit identities must
// never use this API.
func SaveAuditIdentity(ctx context.Context, store CredentialStore, workspace UUID, identity MaterialIdentity) error {
	if err := requireProtectedStore(store); err != nil {
		return err
	}
	key, err := AuditIdentityCredentialKey(workspace)
	if err != nil {
		return err
	}
	secret, err := identity.marshalSecret()
	if err != nil {
		return err
	}
	credential := auditCredential{APIVersion: auditCredentialAPIVersion, Kind: auditCredentialKind, Workspace: workspace, Identity: secret}
	encoded, err := MarshalCanonical(credential)
	if err != nil {
		return fmt.Errorf("encode audit identity credential: %w", err)
	}
	defer clearBytes(encoded)
	if len(encoded) > maxAuditCredentialBytes {
		return fmt.Errorf("%w: audit identity credential size", ErrInvalidDeviceCredential)
	}
	if err := store.Store(ctx, key, encoded); err != nil {
		return fmt.Errorf("store audit identity credential: %w", err)
	}
	return nil
}

func LoadAuditIdentity(ctx context.Context, store CredentialStore, workspace UUID) (MaterialIdentity, error) {
	if err := requireProtectedStore(store); err != nil {
		return MaterialIdentity{}, err
	}
	key, err := AuditIdentityCredentialKey(workspace)
	if err != nil {
		return MaterialIdentity{}, err
	}
	encoded, err := store.Load(ctx, key)
	if err != nil {
		return MaterialIdentity{}, fmt.Errorf("load audit identity credential: %w", err)
	}
	defer clearBytes(encoded)
	if len(encoded) == 0 || len(encoded) > maxAuditCredentialBytes {
		return MaterialIdentity{}, fmt.Errorf("%w: audit identity credential size", ErrInvalidDeviceCredential)
	}
	var credential auditCredential
	if err := UnmarshalStrict(encoded, &credential); err != nil {
		return MaterialIdentity{}, fmt.Errorf("%w: audit identity credential: %v", ErrInvalidDeviceCredential, err)
	}
	canonical, err := MarshalCanonical(credential)
	if err != nil || !bytes.Equal(encoded, canonical) {
		clearBytes(canonical)
		return MaterialIdentity{}, fmt.Errorf("%w: non-canonical audit identity credential", ErrInvalidDeviceCredential)
	}
	clearBytes(canonical)
	if credential.APIVersion != auditCredentialAPIVersion || credential.Kind != auditCredentialKind || credential.Workspace != workspace {
		return MaterialIdentity{}, fmt.Errorf("%w: audit identity binding", ErrInvalidDeviceCredential)
	}
	identity, err := parseMaterialIdentity(credential.Identity)
	if err != nil {
		return MaterialIdentity{}, fmt.Errorf("%w: audit identity", ErrInvalidDeviceCredential)
	}
	return identity, nil
}

package artifact

import (
	"context"
	"errors"
	"testing"
)

func TestAuditIdentityCredentialRoundTripAndWorkspaceBinding(t *testing.T) {
	t.Parallel()

	store := &keyedCredentialStore{values: map[string][]byte{}}
	workspace := auditTestUUID(t, "12121212-1212-4212-8212-121212121212")
	identity := mustMaterialIdentity(t)
	if err := SaveAuditIdentity(context.Background(), store, workspace, identity); err != nil {
		t.Fatalf("SaveAuditIdentity: %v", err)
	}
	loaded, err := LoadAuditIdentity(context.Background(), store, workspace)
	if err != nil {
		t.Fatalf("LoadAuditIdentity: %v", err)
	}
	if loaded.RecipientString() != identity.RecipientString() {
		t.Fatal("loaded a different audit identity")
	}
	other := auditTestUUID(t, "13131313-1313-4313-8313-131313131313")
	if _, err := LoadAuditIdentity(context.Background(), store, other); err == nil {
		t.Fatal("loaded an audit identity under a different workspace key")
	}
}

func TestAuditIdentityCredentialRequiresOSProtection(t *testing.T) {
	t.Parallel()

	workspace := auditTestUUID(t, "14141414-1414-4414-8414-141414141414")
	identity := mustMaterialIdentity(t)
	store := &keyedCredentialStore{protection: "plaintext", values: map[string][]byte{}}
	if err := SaveAuditIdentity(context.Background(), store, workspace, identity); !errors.Is(err, ErrInsecureCredentialStore) {
		t.Fatalf("SaveAuditIdentity = %v", err)
	}
}

type keyedCredentialStore struct {
	protection CredentialProtection
	values     map[string][]byte
}

func (store *keyedCredentialStore) Protection() CredentialProtection {
	if store.protection == "" {
		return CredentialProtectionOS
	}
	return store.protection
}
func (store *keyedCredentialStore) Store(_ context.Context, key string, value []byte) error {
	store.values[key] = append([]byte(nil), value...)
	return nil
}
func (store *keyedCredentialStore) Load(_ context.Context, key string) ([]byte, error) {
	value, ok := store.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}
func (store *keyedCredentialStore) Delete(_ context.Context, key string) error {
	delete(store.values, key)
	return nil
}

func auditTestUUID(t *testing.T, value string) UUID {
	t.Helper()
	parsed, err := ParseUUID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

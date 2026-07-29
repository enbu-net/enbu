//go:build scenario

package test

import (
	"context"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/oci"
)

const scenarioLifecycleRegistryRef = "localhost:5000/test/enbu-scenario-lifecycle"

func TestFullSecretLifecycle(t *testing.T) {
	ctx := context.Background()

	// Generate two key pairs (simulating two users)
	kp1, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair user1: %v", err)
	}
	kp2, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair user2: %v", err)
	}

	// Register recipient keys
	recipientRef1 := scenarioLifecycleRegistryRef + ":recipient-user1"
	recipientRef2 := scenarioLifecycleRegistryRef + ":recipient-user2"

	if err := oci.Push(ctx, recipientRef1, "application/vnd.enbu.recipient.age.v1", []byte(kp1.PublicKey), "", nil); err != nil {
		t.Fatalf("Push recipient1: %v", err)
	}
	if err := oci.Push(ctx, recipientRef2, "application/vnd.enbu.recipient.age.v1", []byte(kp2.PublicKey), "", nil); err != nil {
		t.Fatalf("Push recipient2: %v", err)
	}

	// Pull all recipient keys
	tags, err := oci.ListTags(ctx, scenarioLifecycleRegistryRef, "")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}

	var publicKeys []string
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "recipient-") {
			continue
		}
		data, err := oci.Pull(ctx, scenarioLifecycleRegistryRef+":"+tag, "")
		if err != nil {
			t.Fatalf("Pull recipient %s: %v", tag, err)
		}
		publicKeys = append(publicKeys, string(data))
	}

	if len(publicKeys) < 2 {
		t.Fatalf("expected at least 2 recipients, got %d", len(publicKeys))
	}

	// Encrypt and push secrets
	secrets := map[string]string{
		"DB_URL":  "postgres://localhost/prod",
		"API_KEY": "sk-secret-123",
	}
	plaintext := bundle.Marshal(secrets)
	ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	secretsRef := scenarioLifecycleRegistryRef + ":secrets-default"
	if err := oci.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, "", nil); err != nil {
		t.Fatalf("Push secrets: %v", err)
	}

	// User1 pulls and decrypts
	pulledCiphertext, err := oci.Pull(ctx, secretsRef, "")
	if err != nil {
		t.Fatalf("Pull secrets: %v", err)
	}

	decrypted1, err := age.Decrypt(pulledCiphertext, kp1.Identity)
	if err != nil {
		t.Fatalf("Decrypt as user1: %v", err)
	}

	got1, err := bundle.Unmarshal(decrypted1)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got1["DB_URL"] != "postgres://localhost/prod" {
		t.Fatalf("user1: got DB_URL=%q", got1["DB_URL"])
	}

	// User2 pulls and decrypts
	decrypted2, err := age.Decrypt(pulledCiphertext, kp2.Identity)
	if err != nil {
		t.Fatalf("Decrypt as user2: %v", err)
	}

	got2, err := bundle.Unmarshal(decrypted2)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got2["API_KEY"] != "sk-secret-123" {
		t.Fatalf("user2: got API_KEY=%q", got2["API_KEY"])
	}
}

func TestAddNewSecretToExistingBundle(t *testing.T) {
	ctx := context.Background()

	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Push initial recipient
	recipientRef := scenarioLifecycleRegistryRef + "-add:recipient-testuser"
	if err := oci.Push(ctx, recipientRef, "application/vnd.enbu.recipient.age.v1", []byte(kp.PublicKey), "", nil); err != nil {
		t.Fatalf("Push recipient: %v", err)
	}

	// Create initial secrets bundle
	secrets := map[string]string{"FIRST": "value1"}
	plaintext := bundle.Marshal(secrets)
	ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp.PublicKey})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	addRegistryRef := scenarioLifecycleRegistryRef + "-add"
	secretsRef := addRegistryRef + ":secrets-default"
	if err := oci.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, "", nil); err != nil {
		t.Fatalf("Push initial secrets: %v", err)
	}

	// Pull, decrypt, add new secret, re-encrypt, push
	pulled, err := oci.Pull(ctx, secretsRef, "")
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	decrypted, err := age.Decrypt(pulled, kp.Identity)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	existing, err := bundle.Unmarshal(decrypted)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	existing["SECOND"] = "value2"

	newPlaintext := bundle.Marshal(existing)
	newCiphertext, err := age.EncryptForPublicKeys(newPlaintext, []string{kp.PublicKey})
	if err != nil {
		t.Fatalf("Re-encrypt: %v", err)
	}

	if err := oci.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", newCiphertext, "", nil); err != nil {
		t.Fatalf("Push updated secrets: %v", err)
	}

	// Verify
	finalPulled, err := oci.Pull(ctx, secretsRef, "")
	if err != nil {
		t.Fatalf("Final pull: %v", err)
	}

	finalDecrypted, err := age.Decrypt(finalPulled, kp.Identity)
	if err != nil {
		t.Fatalf("Final decrypt: %v", err)
	}

	finalSecrets, err := bundle.Unmarshal(finalDecrypted)
	if err != nil {
		t.Fatalf("Final unmarshal: %v", err)
	}

	if finalSecrets["FIRST"] != "value1" || finalSecrets["SECOND"] != "value2" {
		t.Fatalf("expected {FIRST: value1, SECOND: value2}, got %v", finalSecrets)
	}
}

func TestSyncForNewRecipient(t *testing.T) {
	ctx := context.Background()

	// User1 sets up initially
	kp1, _ := age.GenerateKeyPair()
	syncRegistryRef := scenarioLifecycleRegistryRef + "-sync"

	recipientRef1 := syncRegistryRef + ":recipient-user1"
	if err := oci.Push(ctx, recipientRef1, "application/vnd.enbu.recipient.age.v1", []byte(kp1.PublicKey), "", nil); err != nil {
		t.Fatalf("Push recipient1: %v", err)
	}

	// Encrypt secrets only for user1
	secrets := map[string]string{"SECRET": "mysecret"}
	plaintext := bundle.Marshal(secrets)
	ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp1.PublicKey})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	secretsRef := syncRegistryRef + ":secrets-default"
	if err := oci.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, "", nil); err != nil {
		t.Fatalf("Push secrets: %v", err)
	}

	// User2 joins: register their key
	kp2, _ := age.GenerateKeyPair()
	recipientRef2 := syncRegistryRef + ":recipient-user2"
	if err := oci.Push(ctx, recipientRef2, "application/vnd.enbu.recipient.age.v1", []byte(kp2.PublicKey), "", nil); err != nil {
		t.Fatalf("Push recipient2: %v", err)
	}

	// User2 cannot decrypt yet
	pulled, _ := oci.Pull(ctx, secretsRef, "")
	_, err = age.Decrypt(pulled, kp2.Identity)
	if err == nil {
		t.Fatal("expected user2 to fail decryption before sync")
	}

	// User1 performs sync: decrypt, pull all recipients, re-encrypt
	decrypted, err := age.Decrypt(pulled, kp1.Identity)
	if err != nil {
		t.Fatalf("User1 decrypt for sync: %v", err)
	}

	tags, _ := oci.ListTags(ctx, syncRegistryRef, "")
	var allKeys []string
	for _, tag := range tags {
		if !strings.HasPrefix(tag, "recipient-") {
			continue
		}
		data, _ := oci.Pull(ctx, syncRegistryRef+":"+tag, "")
		allKeys = append(allKeys, string(data))
	}

	newCiphertext, err := age.EncryptForPublicKeys(decrypted, allKeys)
	if err != nil {
		t.Fatalf("Re-encrypt for all: %v", err)
	}

	if err := oci.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", newCiphertext, "", nil); err != nil {
		t.Fatalf("Push synced secrets: %v", err)
	}

	// User2 can now decrypt
	syncedPulled, _ := oci.Pull(ctx, secretsRef, "")
	decrypted2, err := age.Decrypt(syncedPulled, kp2.Identity)
	if err != nil {
		t.Fatalf("User2 decrypt after sync: %v", err)
	}

	got, _ := bundle.Unmarshal(decrypted2)
	if got["SECRET"] != "mysecret" {
		t.Fatalf("user2 got SECRET=%q, want mysecret", got["SECRET"])
	}
}

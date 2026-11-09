package keystore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// These tests talk to a real Secret Service on the session bus. CI runs them
// under dbus-run-session: ENBU_TEST_SECRET_SERVICE=unlocked with an unlocked
// gnome-keyring, and =absent with no Secret Service at all.

func TestSecretServiceUnlockedThenLocked(t *testing.T) {
	if os.Getenv("ENBU_TEST_SECRET_SERVICE") != "unlocked" {
		t.Skip("set ENBU_TEST_SECRET_SERVICE=unlocked inside a session with an unlocked gnome-keyring")
	}
	b := &KeyringBackend{}
	if err := b.Probe(context.Background()); err != nil {
		t.Fatalf("Probe of an unlocked keyring = %v", err)
	}
	if err := b.Store("enbu-test", "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Load("enbu-test", "k"); err != nil || string(got) != "v" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	if err := b.Delete("enbu-test", "k"); err != nil {
		t.Fatal(err)
	}

	lockAll(t)
	start := time.Now()
	if err := b.Probe(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("Probe of a locked keyring = %v, want ErrLocked", err)
	}
	// Without the check, go-keyring would show an unlock prompt here and
	// wait for it forever.
	if _, err := b.Load("enbu-test", "k"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Load from a locked keyring = %v, want ErrLocked", err)
	}
	if d := time.Since(start); d > probeTimeout {
		t.Fatalf("locked checks took %v", d)
	}
}

func TestSecretServiceAbsent(t *testing.T) {
	if os.Getenv("ENBU_TEST_SECRET_SERVICE") != "absent" {
		t.Skip("set ENBU_TEST_SECRET_SERVICE=absent inside a session without a Secret Service")
	}
	err := (&KeyringBackend{}).Probe(context.Background())
	if !errors.Is(err, ErrNoKeyring) || errors.Is(err, ErrLocked) {
		t.Fatalf("Probe without a Secret Service = %v, want ErrNoKeyring", err)
	}
}

// lockAll locks every collection, as a screen lock or a reboot would.
func lockAll(t *testing.T) {
	t.Helper()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	service := conn.Object(secretService, secretServicePath)
	var collections []dbus.ObjectPath
	if err := getProperty(context.Background(), service, secretServiceIface, "Collections", &collections); err != nil {
		t.Fatal(err)
	}
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := service.Call(secretServiceIface+".Lock", 0, collections).Store(&locked, &prompt); err != nil {
		t.Fatal(err)
	}
	if prompt != "/" {
		t.Fatalf("locking asked for a prompt: %s", prompt)
	}
}

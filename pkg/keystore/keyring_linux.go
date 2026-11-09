package keystore

import (
	"context"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// checkBeforeUse is true on Linux: go-keyring unlocks a locked Secret
// Service collection by showing a prompt and waiting for it without a
// timeout, which hangs forever without a desktop session (SSH, containers).
const checkBeforeUse = true

// probeKeyring is replaced in tests.
var probeKeyring = probeSecretService

const (
	secretService      = "org.freedesktop.secrets"
	secretServicePath  = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface = "org.freedesktop.Secret.Service"
	secretCollection   = "org.freedesktop.Secret.Collection"
	// loginCollection is the collection go-keyring uses when it exists; it
	// uses the "default" alias otherwise.
	loginCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	propertiesGet   = "org.freedesktop.DBus.Properties.Get"
)

// probeSecretService checks, with D-Bus calls bounded by ctx, the three
// things go-keyring needs: a Secret Service on the session bus, the
// collection it stores into, and that collection being unlocked.
func probeSecretService(ctx context.Context) error {
	conn, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("%w: no D-Bus session bus: %w", ErrNoKeyring, err)
	}
	defer func() { _ = conn.Close() }()

	service := conn.Object(secretService, secretServicePath)
	var collections []dbus.ObjectPath
	if err := getProperty(ctx, service, secretServiceIface, "Collections", &collections); err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == "org.freedesktop.DBus.Error.ServiceUnknown" {
			return fmt.Errorf("%w: no Secret Service (install GNOME Keyring or KWallet)", ErrNoKeyring)
		}
		return fmt.Errorf("%w: Secret Service: %w", ErrNoKeyring, err)
	}
	path := dbus.ObjectPath("")
	for _, c := range collections {
		if c == loginCollection {
			path = c
		}
	}
	if path == "" {
		if err := service.CallWithContext(ctx, secretServiceIface+".ReadAlias", 0, "default").Store(&path); err != nil {
			return fmt.Errorf("%w: Secret Service: %w", ErrNoKeyring, err)
		}
	}
	if path == "" || path == "/" {
		return fmt.Errorf("%w: the Secret Service has no default collection (create a keyring, for example with Seahorse)", ErrNoKeyring)
	}
	var locked bool
	if err := getProperty(ctx, conn.Object(secretService, path), secretCollection, "Locked", &locked); err != nil {
		return fmt.Errorf("%w: Secret Service collection %s: %w", ErrNoKeyring, path, err)
	}
	if locked {
		return fmt.Errorf("%w: unlock the %s collection (log in to the desktop, or run gnome-keyring-daemon --unlock) and retry", ErrLocked, path)
	}
	return nil
}

func getProperty(ctx context.Context, obj dbus.BusObject, iface, name string, out any) error {
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, propertiesGet, 0, iface, name).Store(&v); err != nil {
		return err
	}
	return dbus.Store([]any{v.Value()}, out)
}

package identity

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/jonboulle/clockwork"
)

func TestManagerPassesClockToKeyStores(t *testing.T) {
	c := clockwork.NewFakeClock()
	m := New(c)
	if m.Vault.(*keystore.KeyringBackend).Clock != c {
		t.Fatal("keyring received another clock")
	}
}

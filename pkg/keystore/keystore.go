package keystore

type Backend interface {
	Store(service, key string, secret []byte) error
	Load(service, key string) ([]byte, error)
	Delete(service, key string) error
}

// New returns the OS keyring backend.
func New() Backend { return &KeyringBackend{} }

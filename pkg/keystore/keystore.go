package keystore

type Backend interface {
	Store(service, key string, secret []byte) error
	Load(service, key string) ([]byte, error)
	Delete(service, key string) error
}

// New returns the backend for the GitHub token: the OS keyring. There is no
// plaintext file backend; a keyring that is missing or locked fails each
// operation instead.
func New() Backend { return &KeyringBackend{} }

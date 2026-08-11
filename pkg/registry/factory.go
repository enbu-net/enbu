package registry

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// RepositoryAuth is exactly one registry authentication mode. BearerToken is
// sent as an access token. Username and Password select registry basic auth.
type RepositoryAuth struct {
	BearerToken string
	Username    string
	Password    string
}

// NewRepositoryRemote constructs the production streaming OCI remote. The
// reference must be an ORAS repository reference without a URL scheme. Plain
// HTTP is enabled only for the literal localhost registry name.
func NewRepositoryRemote(reference string, credentials RepositoryAuth) (*OCIRemote, error) {
	if reference == "" || strings.TrimSpace(reference) != reference {
		return nil, errors.New("registry: invalid empty or padded repository reference")
	}
	credential, err := credentials.credential()
	if err != nil {
		return nil, err
	}
	repository, err := remote.NewRepository(reference)
	if err != nil {
		return nil, fmt.Errorf("registry: parse repository reference %q: %w", reference, err)
	}
	if repository.Reference.Reference != "" {
		return nil, errors.New("registry: repository reference must not contain a tag or digest")
	}
	registryHost := repository.Reference.Registry
	repository.PlainHTTP = isLiteralLocalhost(registryHost)

	client := *auth.DefaultClient
	client.Header = auth.DefaultClient.Header.Clone()
	client.Credential = auth.StaticCredential(registryHost, credential)
	repository.Client = &client

	return NewOCIRemote(repository)
}

func (credentials RepositoryAuth) credential() (auth.Credential, error) {
	hasBearer := credentials.BearerToken != ""
	hasBasic := credentials.Username != "" || credentials.Password != ""
	if hasBearer == hasBasic {
		return auth.Credential{}, errors.New("registry: select exactly one bearer or basic credential")
	}
	if hasBearer {
		if strings.IndexByte(credentials.BearerToken, 0) >= 0 {
			return auth.Credential{}, errors.New("registry: bearer token contains NUL")
		}
		return auth.Credential{AccessToken: credentials.BearerToken}, nil
	}
	if credentials.Username == "" || credentials.Password == "" {
		return auth.Credential{}, errors.New("registry: basic credentials require username and password")
	}
	if strings.IndexByte(credentials.Username, 0) >= 0 || strings.IndexByte(credentials.Password, 0) >= 0 {
		return auth.Credential{}, errors.New("registry: basic credentials contain NUL")
	}
	return auth.Credential{Username: credentials.Username, Password: credentials.Password}, nil
}

func isLiteralLocalhost(registryHost string) bool {
	host := registryHost
	if splitHost, _, err := net.SplitHostPort(registryHost); err == nil {
		host = splitHost
	}
	return strings.EqualFold(host, "localhost")
}

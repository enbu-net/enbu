package registry

import (
	"context"
	"strings"
	"testing"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestNewRepositoryRemoteConfiguresBearerAuthentication(t *testing.T) {
	remoteAdapter, err := NewRepositoryRemote("ghcr.io/enbu-net/example", RepositoryAuth{BearerToken: "bearer-secret"})
	if err != nil {
		t.Fatal(err)
	}
	repository := repositoryTarget(t, remoteAdapter)
	if repository.PlainHTTP {
		t.Fatal("ghcr.io unexpectedly uses plain HTTP")
	}
	credential := repositoryCredential(t, repository, "ghcr.io")
	if credential.AccessToken != "bearer-secret" || credential.Username != "" || credential.Password != "" {
		t.Fatal("bearer credential was not configured correctly")
	}
	other := repositoryCredential(t, repository, "registry.example")
	if other != auth.EmptyCredential {
		t.Fatal("credential leaked to another registry")
	}
}

func TestNewRepositoryRemoteConfiguresBasicAuthentication(t *testing.T) {
	remoteAdapter, err := NewRepositoryRemote("ghcr.io/enbu-net/example", RepositoryAuth{Username: "octocat", Password: "basic-secret"})
	if err != nil {
		t.Fatal(err)
	}
	credential := repositoryCredential(t, repositoryTarget(t, remoteAdapter), "ghcr.io")
	if credential.Username != "octocat" || credential.Password != "basic-secret" || credential.AccessToken != "" {
		t.Fatal("basic credential was not configured correctly")
	}
}

func TestNewRepositoryRemoteEnablesPlainHTTPOnlyForLiteralLocalhost(t *testing.T) {
	tests := []struct {
		reference string
		plain     bool
	}{
		{reference: "localhost/example", plain: true},
		{reference: "localhost:5000/example", plain: true},
		{reference: "LOCALHOST:5000/example", plain: true},
		{reference: "localhost.example/example", plain: false},
		{reference: "localhost.example:5000/example", plain: false},
		{reference: "127.0.0.1:5000/example", plain: false},
		{reference: "ghcr.io/enbu-net/example", plain: false},
	}
	for _, test := range tests {
		t.Run(test.reference, func(t *testing.T) {
			remoteAdapter, err := NewRepositoryRemote(test.reference, RepositoryAuth{BearerToken: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			if got := repositoryTarget(t, remoteAdapter).PlainHTTP; got != test.plain {
				t.Fatalf("PlainHTTP = %v, want %v", got, test.plain)
			}
		})
	}
}

func TestNewRepositoryRemoteRejectsInvalidAuthentication(t *testing.T) {
	tests := []RepositoryAuth{
		{},
		{BearerToken: "bearer", Username: "user", Password: "password"},
		{Username: "user"},
		{Password: "password"},
		{BearerToken: "bad\x00token"},
		{Username: "bad\x00user", Password: "password"},
	}
	for _, credentials := range tests {
		if _, err := NewRepositoryRemote("ghcr.io/enbu-net/example", credentials); err == nil {
			t.Fatal("NewRepositoryRemote() accepted invalid authentication")
		}
	}
}

func TestNewRepositoryRemoteRejectsInvalidReferenceWithoutExposingCredential(t *testing.T) {
	const token = "must-not-appear"
	for _, reference := range []string{"https://ghcr.io/enbu-net/example", "ghcr.io/enbu-net/example:latest", "ghcr.io/enbu-net/example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		_, err := NewRepositoryRemote(reference, RepositoryAuth{BearerToken: token})
		if err == nil {
			t.Fatalf("invalid reference %q succeeded", reference)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatal("credential appeared in the error")
		}
	}
}

func repositoryTarget(t *testing.T, adapter *OCIRemote) *remote.Repository {
	t.Helper()
	if adapter == nil {
		t.Fatal("nil OCI remote")
	}
	repository, ok := adapter.target.(*remote.Repository)
	if !ok {
		t.Fatalf("target type = %T", adapter.target)
	}
	return repository
}

func repositoryCredential(t *testing.T, repository *remote.Repository, host string) auth.Credential {
	t.Helper()
	client, ok := repository.Client.(*auth.Client)
	if !ok {
		t.Fatalf("client type = %T", repository.Client)
	}
	credential, err := client.Credential(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

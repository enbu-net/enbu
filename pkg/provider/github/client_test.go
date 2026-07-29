package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func newTestClient(t *testing.T, token string, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return newClient(token, server.Client(), server.URL+"/")
}

func TestGetUser(t *testing.T) {
	client := newTestClient(t, "test-token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("path = %q, want /user", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Errorf("API version = %q, want %q", got, "2022-11-28")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": int64(123), "login": "testuser", "type": "User"})
	})

	user, err := client.GetUser(context.Background())
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.ID != 123 || user.Login != "testuser" || user.Type != "User" {
		t.Fatalf("user = %#v", user)
	}
}

func TestIsOrganization(t *testing.T) {
	client := newTestClient(t, "test-token", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/my-org":
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "Organization", "login": "my-org"})
		case "/users/my-user":
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "User", "login": "my-user"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	if !client.IsOrganization(context.Background(), "my-org") {
		t.Error("expected my-org to be detected as Organization")
	}
	if client.IsOrganization(context.Background(), "my-user") {
		t.Error("expected my-user not to be detected as Organization")
	}
	if client.IsOrganization(context.Background(), "nonexistent") {
		t.Error("expected nonexistent not to be detected as Organization")
	}
}

func TestCreateRepository(t *testing.T) {
	client := newTestClient(t, "test-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/user/repos" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var request struct {
			Name    string `json:"name"`
			Private bool   `json:"private"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Name != "example" || !request.Private {
			t.Fatalf("request = %#v", request)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "example",
			"ssh_url":   "git@github.com:octo/example.git",
			"clone_url": "https://github.com/octo/example.git",
			"owner":     map[string]string{"login": "octo"},
		})
	})

	repository, err := client.CreateRepository(context.Background(), "", "example", true)
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	if repository.Owner != "octo" || repository.Name != "example" {
		t.Fatalf("repository = %#v", repository)
	}
}

func TestListRepositoryOwners(t *testing.T) {
	client := newTestClient(t, "test-token", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]string{"login": "octo", "type": "User"})
		case "/user/orgs":
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"login": "octo-org"},
				{"login": "another-org"},
			})
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
	})

	owners, err := client.ListRepositoryOwners(context.Background())
	if err != nil {
		t.Fatalf("ListRepositoryOwners: %v", err)
	}
	want := []RepositoryOwner{
		{Login: "octo"},
		{Login: "octo-org", Organization: true},
		{Login: "another-org", Organization: true},
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners = %#v, want %#v", owners, want)
	}
}

func TestCreateOrganizationRepository(t *testing.T) {
	client := newTestClient(t, "test-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/orgs/octo-org/repos" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "example",
			"ssh_url":   "git@github.com:octo-org/example.git",
			"clone_url": "https://github.com/octo-org/example.git",
			"owner":     map[string]string{"login": "octo-org"},
		})
	})

	repository, err := client.CreateRepository(context.Background(), "octo-org", "example", true)
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	if repository.Owner != "octo-org" {
		t.Fatalf("owner = %q, want octo-org", repository.Owner)
	}
}

func TestGetUserUnauthorized(t *testing.T) {
	client := newTestClient(t, "bad-token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
	})

	_, err := client.GetUser(context.Background())
	if err == nil {
		t.Fatal("expected error for unauthorized request")
	}
}

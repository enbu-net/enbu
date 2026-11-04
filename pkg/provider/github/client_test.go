package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, token string, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTestServer(t, handler)
	httpClient := server.Client()
	return newClient(token, httpClient, server.URL+"/")
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

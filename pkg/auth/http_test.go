package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newHTTPTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewTestServer(t, handler)
	// Client starts the in-memory network and initializes Server.URL.
	return server, server.Client()
}

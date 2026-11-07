package storage

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGHCRPackagesRejectsRedirectedAPICalls(t *testing.T) {
	for _, owner := range []string{"User", "Organization"} {
		for _, phase := range []string{"owner", "versions", "delete"} {
			for _, code := range []int{301, 302, 303, 307, 308} {
				for _, destination := range []string{"other-port", "other-host", "http-downgrade", "same-origin"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s", owner, phase, code, destination), func(t *testing.T) {
						var redirected, leaked, deleted atomic.Int32
						destinationHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							redirected.Add(1)
							if strings.Contains(r.Header.Get("Authorization"), "fixture-token-canary") {
								leaked.Add(1)
							}
							switch phase {
							case "owner":
								_, _ = fmt.Fprintf(w, `{"type":%q}`, owner)
							case "versions":
								_, _ = w.Write([]byte(`[{"id":7,"metadata":{"container":{"tags":["s-target"]}}}]`))
							default:
								w.WriteHeader(http.StatusNoContent)
							}
						})
						target := httptest.NewServer(destinationHandler)
						defer target.Close()
						location := target.URL + "/redirected"
						if destination == "other-host" {
							location = strings.Replace(location, "127.0.0.1", "localhost", 1)
						}
						var armed atomic.Bool
						armed.Store(true)
						api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/redirected" {
								destinationHandler.ServeHTTP(w, r)
								return
							}
							if r.Header.Get("Authorization") != "Bearer fixture-token-canary" {
								t.Error("canonical API did not receive its credential")
							}
							current := "versions"
							if r.URL.Path == "/users/acme" {
								current = "owner"
							} else if r.Method == http.MethodDelete {
								current = "delete"
							}
							if armed.Load() && current == phase {
								http.Redirect(w, r, location, code)
								return
							}
							switch current {
							case "owner":
								_, _ = fmt.Fprintf(w, `{"type":%q}`, owner)
							case "versions":
								_, _ = w.Write([]byte(`[{"id":7,"metadata":{"container":{"tags":["s-target"]}}},{"id":8,"metadata":{"container":{"tags":["s-neighbor"]}}}]`))
							default:
								if !strings.HasSuffix(r.URL.Path, "/versions/7") {
									t.Errorf("unexpected deletion path %q", r.URL.Path)
								}
								deleted.Add(1)
								w.WriteHeader(http.StatusNoContent)
							}
						})
						var source *httptest.Server
						if destination == "http-downgrade" {
							source = httptest.NewTLSServer(api)
						} else {
							source = httptest.NewServer(api)
						}
						defer source.Close()
						if destination == "same-origin" {
							location = source.URL + "/redirected"
						}
						g := &GHCRPackages{
							Owner: "acme", Package: "repo-enbu", BaseURL: source.URL, Client: source.Client(),
							Token: func() (string, error) { return "fixture-token-canary", nil },
						}
						if err := g.DeleteTag(t.Context(), "s-target"); err == nil {
							t.Error("redirected API call acknowledged deletion")
						}
						if redirected.Load() != 0 || leaked.Load() != 0 || deleted.Load() != 0 {
							t.Fatalf("redirect boundary violated: destination calls=%d credential disclosures=%d canonical deletes=%d", redirected.Load(), leaked.Load(), deleted.Load())
						}
						armed.Store(false)
						if err := g.DeleteTag(t.Context(), "s-target"); err != nil {
							t.Fatalf("same-client recovery: %v", err)
						}
						if deleted.Load() != 1 {
							t.Fatalf("expected exactly one authorized target deletion, got %d", deleted.Load())
						}
					})
				}
			}
		}
	}
}

func TestGHCRPackagesPreservesCallerRedirectPolicy(t *testing.T) {
	var policyCalls atomic.Int32
	policyError := errors.New("caller redirect policy")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path != "/api" {
			t.Errorf("unexpected destination %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		policyCalls.Add(1)
		return policyError
	}
	g := GHCRPackages{BaseURL: server.URL, Client: client, Token: func() (string, error) { return "fixture", nil }}
	if _, err := g.do(t.Context(), http.MethodGet, "/api", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(server.URL + "/redirect"); !errors.Is(err, policyError) {
		t.Fatalf("caller policy changed: %v", err)
	}
	if policyCalls.Load() != 1 {
		t.Fatalf("caller policy calls = %d", policyCalls.Load())
	}
}

package storage

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestGHCRDeletionAuthenticationChangesAfterListing(t *testing.T) {
	for _, ownerType := range []string{"User", "Organization"} {
		for _, change := range []string{"logout", "401", "403", "rotate"} {
			t.Run(ownerType+"/"+change, func(t *testing.T) {
				// Phase changes happen in the completed listing response, before the
				// deleter requests its next token. No wall-clock ordering is involved.
				var phase atomic.Int32 // listing, deletion boundary, reauthenticated
				var deleted atomic.Bool
				var denied atomic.Int32
				loggedOut := errors.New("fixture session logged out")
				pkg := "/users/acme/packages/container/repo-enbu"
				if ownerType == "Organization" {
					pkg = "/orgs/acme/packages/container/repo-enbu"
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					token := "initial"
					if phase.Load() == 2 {
						token = "restored"
					} else if r.Method == http.MethodDelete {
						token = "expired"
						if change == "rotate" {
							token = "rotated"
						}
					}
					if r.Header.Get("Authorization") != "Bearer "+token {
						t.Errorf("unexpected credential on %s %s", r.Method, r.URL.Path)
					}
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/users/acme":
						_, _ = fmt.Fprintf(w, `{"type":%q}`, ownerType)
					case r.Method == http.MethodGet && r.URL.Path == pkg+"/versions":
						if deleted.Load() {
							_, _ = fmt.Fprint(w, `[{"id":8,"metadata":{"container":{"tags":["neighbor-tag"]}}}]`)
							return
						}
						if phase.Load() == 0 {
							phase.Store(1)
						}
						_, _ = fmt.Fprint(w, `[{"id":7,"metadata":{"container":{"tags":["target-tag"]}}},{"id":8,"metadata":{"container":{"tags":["neighbor-tag"]}}}]`)
					case r.Method == http.MethodDelete && r.URL.Path == pkg+"/versions/7":
						if phase.Load() == 1 && change != "rotate" {
							if change == "logout" {
								t.Error("DELETE reached provider after token loading failed")
							}
							denied.Add(1)
							status, _ := strconv.Atoi(change)
							if status == 0 {
								status = http.StatusUnauthorized
							}
							w.WriteHeader(status)
							return
						}
						if deleted.Swap(true) {
							t.Error("duplicate successful deletion")
						}
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Errorf("unexpected provider request %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				g := &GHCRPackages{Owner: "acme", Package: "repo-enbu", BaseURL: server.URL, Token: func() (string, error) {
					switch phase.Load() {
					case 2:
						return "restored", nil
					case 1:
						if change == "logout" {
							return "", loggedOut
						}
						if change == "rotate" {
							return "rotated", nil
						}
						return "expired", nil
					default:
						return "initial", nil
					}
				}}
				err := g.DeleteTag(t.Context(), "target-tag")
				if change == "rotate" {
					if err != nil || !deleted.Load() {
						t.Fatalf("fresh token did not complete exact deletion: %v", err)
					}
				} else {
					if err == nil || errors.Is(err, ErrNotFound) || deleted.Load() {
						t.Fatalf("authentication failure was acknowledged or deleted a version: %v", err)
					}
					if change == "logout" {
						if !errors.Is(err, loggedOut) || denied.Load() != 0 {
							t.Fatalf("logout cause lost or DELETE attempted: %v", err)
						}
					} else if denied.Load() != 1 {
						t.Fatalf("permission failure did not reach exactly one DELETE: %d", denied.Load())
					}
					phase.Store(2)
					if err := g.DeleteTag(t.Context(), "target-tag"); err != nil || !deleted.Load() {
						t.Fatalf("same deleter did not recover after reauthentication: %v", err)
					}
				}
				phase.Store(2)
				// A repeat must report absence and never delete the neighboring version.
				if err := g.DeleteTag(t.Context(), "target-tag"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("repeat deletion was not absent: %v", err)
				}
			})
		}
	}
}

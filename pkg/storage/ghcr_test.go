package storage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeAPI struct {
	owner    string
	ownerTyp string
	versions []fakeVersion
	deleted  []int64
}

type fakeVersion struct {
	id   int64
	tags []string
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing token on %s %s", r.Method, r.URL.Path)
		}
		scope := "/users/" + f.owner + "/packages/container/repo-enbu"
		if f.ownerTyp == "Organization" {
			scope = "/orgs/" + f.owner + "/packages/container/repo-enbu"
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/users/"+f.owner:
			_, _ = fmt.Fprintf(w, `{"type":%q}`, f.ownerTyp)
		case r.Method == http.MethodGet && r.URL.Path == scope+"/versions":
			var parts []string
			for _, v := range f.versions {
				parts = append(parts, fmt.Sprintf(`{"id":%d,"metadata":{"container":{"tags":[%s]}}}`, v.id, quoted(v.tags)))
			}
			_, _ = w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, scope+"/versions/"):
			var id int64
			_, _ = fmt.Sscanf(strings.TrimPrefix(r.URL.Path, scope+"/versions/"), "%d", &id)
			f.deleted = append(f.deleted, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func quoted(tags []string) string {
	var out []string
	for _, tag := range tags {
		out = append(out, fmt.Sprintf("%q", tag))
	}
	return strings.Join(out, ",")
}

func newGHCR(t *testing.T, f *fakeAPI) *GHCRPackages {
	t.Helper()
	server := httptest.NewServer(f.handler(t))
	t.Cleanup(server.Close)
	g, ok := GHCRPackagesFor("ghcr.io/"+f.owner+"/repo-enbu", func() (string, error) { return "tok", nil })
	if !ok {
		t.Fatal("not a ghcr reference")
	}
	g.BaseURL = server.URL
	return g
}

func TestGHCRPackagesDeletesTheVersionOfATag(t *testing.T) {
	for _, owner := range []string{"User", "Organization"} {
		t.Run(owner, func(t *testing.T) {
			f := &fakeAPI{owner: "acme", ownerTyp: owner, versions: []fakeVersion{{1, []string{"s-a"}}, {2, []string{"s-b"}}, {3, nil}}}
			if err := newGHCR(t, f).DeleteTag(context.Background(), "s-b"); err != nil {
				t.Fatal(err)
			}
			if len(f.deleted) != 1 || f.deleted[0] != 2 {
				t.Fatalf("deleted = %v", f.deleted)
			}
		})
	}
}

// Deleting a version deletes every tag on it, so a shared version is protected.
func TestGHCRPackagesRefusesAVersionWithAnotherTag(t *testing.T) {
	f := &fakeAPI{owner: "acme", ownerTyp: "User", versions: []fakeVersion{{7, []string{"s-a", "latest"}}}}
	err := newGHCR(t, f).DeleteTag(context.Background(), "s-a")
	if err == nil || !strings.Contains(err.Error(), "latest") {
		t.Fatalf("error = %v", err)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("deleted = %v", f.deleted)
	}
}

func TestGHCRPackagesReportsAMissingTag(t *testing.T) {
	f := &fakeAPI{owner: "acme", ownerTyp: "User", versions: []fakeVersion{{1, []string{"s-a"}}}}
	if err := newGHCR(t, f).DeleteTag(context.Background(), "s-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestGHCRPackagesForOnlyAcceptsGHCR(t *testing.T) {
	for _, ref := range []string{"docker.io/acme/repo", "ghcr.io/acme", "ghcr.io", "localhost:5000/acme/repo"} {
		if _, ok := GHCRPackagesFor(ref, nil); ok {
			t.Fatalf("accepted %q", ref)
		}
	}
	g, ok := GHCRPackagesFor("ghcr.io/acme/team/repo-enbu", nil)
	if !ok || g.Owner != "acme" || g.Package != "team/repo-enbu" {
		t.Fatalf("%+v %v", g, ok)
	}
}

package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

type httpSession struct {
	mu          sync.Mutex
	token, user string
	err         error
}

func (s *httpSession) LoadToken() (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, s.user, s.err
}
func (s *httpSession) set(token, user string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token, s.user, s.err = token, user, err
}

type sessionRegistry struct {
	mu                          sync.Mutex
	blobs, manifests            map[string][]byte
	tokens                      map[string]string
	armed, committed, triggered bool
	readOnly                    bool
	publicationDenial           int
	entered, release            chan struct{}
}

func (r *sessionRegistry) stateCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for tag := range r.manifests {
		if strings.HasPrefix(tag, "s-") {
			n++
		}
	}
	return n
}
func (r *sessionRegistry) deny(w http.ResponseWriter, status int) {
	code := "DENIED"
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		code = "UNAUTHORIZED"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []errcode.Error{{Code: code, Message: "synthetic denial: fixture-token-1 private-own-canary"}}})
}
func (r *sessionRegistry) putManifest(path string, body []byte) error {
	var manifest ocispec.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return err
	}
	for _, desc := range append([]ocispec.Descriptor{manifest.Config}, manifest.Layers...) {
		if _, ok := r.blobs[desc.Digest.String()]; !ok {
			return fmt.Errorf("missing uploaded blob")
		}
	}
	tag := strings.TrimPrefix(path, "manifests/")
	if old, ok := r.manifests[tag]; ok && !bytes.Equal(old, body) {
		return fmt.Errorf("immutable tag overwritten")
	}
	r.manifests[tag] = bytes.Clone(body)
	r.manifests[digest.FromBytes(body).String()] = bytes.Clone(body)
	return nil
}
func (r *sessionRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, token, _ := req.BasicAuth()
	r.mu.Lock()
	valid := r.tokens[token] == user && user != ""
	readOnly := r.readOnly && user == "member-1"
	r.mu.Unlock()
	if !valid {
		r.deny(w, http.StatusUnauthorized)
		return
	}
	if readOnly && req.Method != http.MethodGet && req.Method != http.MethodHead {
		r.deny(w, http.StatusForbidden)
		return
	}
	path := strings.TrimPrefix(req.URL.Path, "/v2/team/secrets/")
	body, err := io.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	pause := r.armed && !r.triggered && user == "member-1" && req.Method == http.MethodPut && strings.HasPrefix(path, "manifests/s-")
	if pause {
		r.triggered = true
		if r.committed {
			if err := r.putManifest(path, body); err != nil {
				r.mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	}
	r.mu.Unlock()
	if pause {
		close(r.entered)
		select {
		case <-r.release:
		case <-req.Context().Done():
			return
		}
		// Deliberately lose authorization after the selected before/after
		// durability point. A cached HTTP credential must not imply success.
		r.deny(w, r.publicationDenial)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	serve := func(data []byte, ok bool, media, hash string) {
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Docker-Content-Digest", hash)
		if req.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	}
	switch {
	case path == "blobs/uploads/" && req.Method == http.MethodPost:
		w.Header().Set("Location", "/v2/team/secrets/blobs/uploads/session")
		w.WriteHeader(http.StatusAccepted)
	case strings.HasPrefix(path, "blobs/uploads/") && req.Method == http.MethodPut:
		if digest.FromBytes(body).String() != req.URL.Query().Get("digest") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.blobs[req.URL.Query().Get("digest")] = bytes.Clone(body)
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(path, "blobs/"):
		hash := strings.TrimPrefix(path, "blobs/")
		data, ok := r.blobs[hash]
		serve(data, ok, "application/octet-stream", hash)
	case strings.HasPrefix(path, "manifests/") && req.Method == http.MethodPut:
		if err := r.putManifest(path, body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(body).String())
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(path, "manifests/"):
		data, ok := r.manifests[strings.TrimPrefix(path, "manifests/")]
		serve(data, ok, ocispec.MediaTypeImageManifest, digest.FromBytes(data).String())
	case path == "tags/list":
		tags := []string{}
		for tag := range r.manifests {
			if !strings.HasPrefix(tag, "sha256:") {
				tags = append(tags, tag)
			}
		}
		slices.Sort(tags)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "team/secrets", "tags": tags})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type sessionRoute struct {
	transport   http.RoundTripper
	destination *url.URL
}

func (r sessionRoute) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "ghcr.io" {
		return nil, fmt.Errorf("unexpected logical test destination %q", req.URL.Host)
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	clone.URL = &u
	clone.URL.Scheme = r.destination.Scheme
	clone.URL.Host = r.destination.Host
	response, err := r.transport.RoundTrip(clone)
	if response != nil {
		response.Request = req
	} // Resolve relative OCI locations against the logical origin.
	return response, err
}

func TestNativeSessionTeamSmoke(t *testing.T) {
	shardCase(t)
	nativeSessionTeam(t, 3, "frozen", "logout", false)
}

func TestNativeReadOnlyTeamSmoke(t *testing.T) {
	shardCase(t)
	nativeSessionTeam(t, 3, "frozen", "pull-only", false)
}
func TestNativeSessionTeamClocks(t *testing.T) {
	exploration(t)
	for _, devices := range []int{2, 3, 8} {
		for _, clock := range []string{"", "frozen", "backward", "skewed"} {
			for _, mode := range []string{"logout", "revoked", "account-switch", "pull-only"} {
				for _, committed := range []bool{false, true} {
					t.Run(fmt.Sprintf("devices-%d/%s/%s/committed-%t", devices, clock, mode, committed), func(t *testing.T) { shardCase(t); nativeSessionTeam(t, devices, clock, mode, committed) })
				}
			}
		}
	}
}

func nativeSessionTeam(t *testing.T, devices int, profile, mode string, committed bool) {
	t.Helper()
	sampleCase(t)
	ctx, stop := context.WithTimeout(wsp.WithSerialHeadReads(t.Context()), 30*time.Second)
	defer stop()
	publicationDenial := http.StatusUnauthorized
	if mode == "pull-only" {
		publicationDenial = http.StatusForbidden
	}
	registry := &sessionRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, tokens: map[string]string{}, entered: make(chan struct{}), release: make(chan struct{}), committed: committed, publicationDenial: publicationDenial}
	server := httptest.NewServer(registry)
	defer server.Close()
	destination, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// This native test injects only the physical transport destination. The
	// App's real GHCR credential callback and actual OCI adapter remain active.
	// No other host can reach the network and no test runs in parallel here.
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	http.DefaultTransport = sessionRoute{transport, destination}
	defer func() { http.DefaultTransport = previous }()
	world, err := NewWorld(t.TempDir(), NewTape(373, "native-session-team"), devices)
	if err != nil {
		t.Fatal(err)
	}
	world.Clock = profile
	sessions := make([]*httpSession, devices)
	configure := func(i int) {
		world.Devices[i].App.Storage = nil
		world.Devices[i].App.StorageURL = "oci://ghcr.io/team/secrets"
		world.Devices[i].App.TokenProvider = sessions[i]
	}
	for i := range devices {
		token, user := fmt.Sprintf("fixture-token-%d", i), fmt.Sprintf("member-%d", i)
		sessions[i] = &httpSession{token: token, user: user}
		registry.tokens[token] = user
		configure(i)
	}
	if err := world.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := world.Devices[0].App.AddSecret(ctx, "default", "BASE", "private-initial-canary"); err != nil {
		t.Fatal(err)
	}
	world.Model["default"] = map[string]string{"BASE": "private-initial-canary"}
	if err := world.Check(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	before := registry.stateCount()
	writer := world.Devices[1]
	world.timeline.Advance(time.Second)
	registry.mu.Lock()
	registry.armed = true
	registry.mu.Unlock()
	result := make(chan error, 1)
	go func() { result <- writer.App.AddSecret(ctx, "default", "OWN", "private-own-canary") }()
	released := false
	joined := false
	defer func() {
		stop()
		if !released {
			close(registry.release)
		}
		if !joined {
			if err := <-result; err == nil {
				t.Log("writer completed before cleanup cancellation")
			}
		}
	}()
	select {
	case <-registry.entered:
	case <-ctx.Done():
		t.Fatal("writer did not reach authenticated HTTP publication")
	}
	world.timeline.Advance(time.Second)
	if err := world.Devices[0].App.AddSecret(ctx, "default", "PEER_ACK", "private-peer-canary"); err != nil {
		t.Fatal(err)
	}
	world.Model["default"]["PEER_ACK"] = "private-peer-canary"
	logoutCause := errors.New("synthetic logged-out session: fixture-token-1 private-own-canary")
	registry.mu.Lock()
	if mode == "pull-only" {
		registry.readOnly = true
	} else {
		delete(registry.tokens, "fixture-token-1")
	}
	registry.mu.Unlock()
	switch mode {
	case "logout":
		sessions[1].set("", "", logoutCause)
	case "account-switch":
		sessions[1].set("fixture-switched-token", "repository-owner", nil)
		registry.mu.Lock()
		registry.tokens["fixture-switched-token"] = "repository-owner"
		registry.mu.Unlock()
	}
	close(registry.release)
	released = true
	var outcome error
	select {
	case outcome = <-result:
		joined = true
	case <-ctx.Done():
		t.Fatal("session change did not finish the writer")
	}
	if mode == "account-switch" {
		if outcome != nil {
			t.Fatalf("fresh account credentials did not complete the same write: %v", outcome)
		}
	} else if outcome == nil {
		t.Fatal("denied publication was acknowledged")
	}
	if mode == "logout" && (!apperr.Is(outcome, apperr.CodeNotAuthenticated) || !errors.Is(outcome, logoutCause)) {
		t.Fatalf("logout cause was not preserved: %v", outcome)
	}
	if mode == "revoked" || mode == "pull-only" {
		var denied *errcode.ErrorResponse
		if !errors.As(outcome, &denied) || denied.StatusCode != publicationDenial {
			t.Fatalf("storage permission cause was not preserved: %v", outcome)
		}
		var remote errcode.Error
		if !errors.As(outcome, &remote) || !strings.Contains(remote.Message, "private-own-canary") {
			t.Fatal("hostile provider error did not reach the internal cause")
		}
	}
	if committed || mode == "account-switch" {
		world.Model["default"]["OWN"] = "private-own-canary"
	}
	wantCount := before + 1
	if committed || mode == "account-switch" {
		wantCount++
	}
	if registry.stateCount() != wantCount {
		t.Fatalf("unexpected durable State count: got %d want %d", registry.stateCount(), wantCount)
	}
	if mode == "pull-only" {
		// Storage write access and workspace membership are independent. The
		// denied member can still read peers' new acknowledged publications.
		if err := world.Devices[0].App.AddSecret(ctx, "default", "PEER_DURING_READ_ONLY", "acknowledged-without-writer-access"); err != nil {
			t.Fatal(err)
		}
		world.Model["default"]["PEER_DURING_READ_ONLY"] = "acknowledged-without-writer-access"
		got, err := writer.App.ListSecrets(ctx, "default")
		if err != nil || !maps.Equal(got, world.Model["default"]) {
			t.Fatalf("read-only storage access lost the exact peer snapshot: %v", err)
		}
		beforeBlocked := registry.stateCount()
		for _, call := range []func() error{
			func() error { return writer.App.AddSecret(ctx, "default", "MUST_NOT_ACK_READ_ONLY", "blocked") },
			func() error { return writer.App.SyncSecrets(ctx, "default") },
		} {
			var denied *errcode.ErrorResponse
			if err := call(); !errors.As(err, &denied) || denied.StatusCode != http.StatusForbidden {
				t.Fatalf("read-only member falsely acknowledged a write: %v", err)
			}
		}
		if registry.stateCount() != beforeBlocked {
			t.Fatal("read-only member published an unauthorized State")
		}
	} else if mode != "account-switch" {
		got, err := writer.App.ListSecrets(ctx, "default")
		if err == nil || got != nil {
			t.Fatalf("denied reader exposed a snapshot: %v", err)
		}
	}
	if outcome != nil {
		payload, _ := json.Marshal(apperr.PayloadOf(outcome))
		for _, canary := range []string{"private-own-canary", "private-peer-canary", "fixture-token-1"} {
			if bytes.Contains(payload, []byte(canary)) {
				t.Fatal("session error disclosed a synthetic secret")
			}
		}
	}
	// Restoring storage access retains the same device identity. A different
	// GitHub account must not become a workspace administrator either.
	restoredUser := "repository-owner"
	if mode == "pull-only" {
		restoredUser = "member-1"
	}
	sessions[1].set("fixture-restored-token", restoredUser, nil)
	registry.mu.Lock()
	registry.tokens["fixture-restored-token"] = restoredUser
	registry.readOnly = false
	registry.mu.Unlock()
	world.timeline.Advance(time.Second)
	if err := world.Check(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if err := requireCode(writer.App.SetAdmin(ctx, writer.ID, true), apperr.CodeAccessDenied); err != nil {
		t.Fatal(err)
	}
	if err := writer.App.SyncSecrets(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if _, exists := world.Model["default"]["OWN"]; exists {
		if err := requireCode(writer.App.AddSecret(ctx, "default", "OWN", "private-own-canary"), apperr.CodeSecretExists); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := writer.App.AddSecret(ctx, "default", "OWN", "private-own-canary"); err != nil {
			t.Fatal(err)
		}
		world.Model["default"]["OWN"] = "private-own-canary"
	}
	if err := world.Devices[0].App.RemoveMember(ctx, writer.ID); err != nil {
		t.Fatal(err)
	}
	if err := world.Devices[0].App.AddSecret(ctx, "default", "AFTER_REMOVE_ACK", "private-after-remove-canary"); err != nil {
		t.Fatal(err)
	}
	world.Model["default"]["AFTER_REMOVE_ACK"] = "private-after-remove-canary"
	got, err := writer.App.ListSecrets(ctx, "default")
	if requireCode(err, apperr.CodeNotMember) != nil || got != nil {
		t.Fatalf("valid storage account bypassed removal: %v", err)
	}
	if err := requireCode(writer.App.AddSecret(ctx, "default", "MUST_NOT_WRITE", "removed-canary"), apperr.CodeNotMember); err != nil {
		t.Fatal(err)
	}
	init, err := writer.App.InitializeRepository(ctx)
	if err != nil || init == nil || !init.Pending || init.DeviceID != writer.ID {
		t.Fatalf("readmission after reauthentication: %v", err)
	}
	if err := world.Devices[0].App.ApproveMember(ctx, writer.ID); err != nil {
		t.Fatal(err)
	}
	want := maps.Clone(world.Model["default"])
	for i := range devices {
		world.Restart(i)
		configure(i)
		got, err := world.Devices[i].App.ListSecrets(ctx, "default")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("restarted device %d lost acknowledged team writes: %v", i, err)
		}
		key := fmt.Sprintf("AFTER_SESSION_%d", i)
		if err := world.Devices[i].App.AddSecret(ctx, "default", key, "acknowledged"); err != nil {
			t.Fatal(err)
		}
		world.Model["default"][key] = "acknowledged"
		want[key] = "acknowledged"
	}
	if err := world.Check(ctx, "default"); err != nil {
		t.Fatal(err)
	}
}

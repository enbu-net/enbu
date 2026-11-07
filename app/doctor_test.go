package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/jonboulle/clockwork"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

func doctorCheck(t *testing.T, r DoctorReport, name, env, status string) DiagnosticCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name && c.Environment == env {
			if c.Status != status {
				t.Fatalf("%s [%s]: %+v; report %+v", name, env, c, r)
			}
			return c
		}
	}
	t.Fatalf("missing %s [%s] in %+v", name, env, r)
	return DiagnosticCheck{}
}

func doctorFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = string(b)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func TestDoctorHealthyWorkspaceIsReadOnlyAndRedactsSecrets(t *testing.T) {
	a := newAlice(t)
	if err := a.AddSecret(bg, "default", "DOCTOR_PRIVATE_KEY_NAME", "DOCTOR_PRIVATE_VALUE"); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddEnvironment("empty"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveProject(cfg); err != nil {
		t.Fatal(err)
	}
	// A new local checkpoint directory proves diagnosis does not TOFU-pin.
	a.CheckpointDir = t.TempDir()
	before := doctorFiles(t, a.CheckpointDir)
	revisions := revisionsOf(t, a, "default")
	r := a.Diagnose(bg)
	if !r.Healthy {
		t.Fatalf("report: %+v", r)
	}
	for _, name := range []string{"config", "storage", "control", "membership", "encryption_key"} {
		doctorCheck(t, r, name, "", "ok")
	}
	for _, name := range []string{"history", "decrypt", "conflicts"} {
		doctorCheck(t, r, name, "default", "ok")
	}
	doctorCheck(t, r, "history", "empty", "skip")
	if after := doctorFiles(t, a.CheckpointDir); !reflect.DeepEqual(before, after) {
		t.Fatal("diagnosis modified checkpoints or trust pins")
	}
	if !reflect.DeepEqual(revisions, revisionsOf(t, a, "default")) {
		t.Fatal("diagnosis published a revision")
	}
	encoded, _ := json.Marshal(r)
	for _, secret := range []string{"DOCTOR_PRIVATE_KEY_NAME", "DOCTOR_PRIVATE_VALUE"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("diagnosis exposed a secret")
		}
	}
}

func TestDoctorDetectsChangedTrustRoot(t *testing.T) {
	a := newAlice(t)
	setGenesis(t, a, foundRival(t, a))
	r := a.Diagnose(bg)
	c := doctorCheck(t, r, "control", "", "fail")
	if r.Healthy || c.Code != apperr.CodeTrustRootChanged {
		t.Fatalf("%+v", r)
	}
}

func TestDoctorDetectsMissingAcceptedHistory(t *testing.T) {
	a := newAlice(t)
	cfg, _ := a.loadProject()
	for _, rev := range revisionsOf(t, a, "default") {
		if err := a.Storage.Delete(bg, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")), rev); err != nil {
			t.Fatal(err)
		}
	}
	r := a.Diagnose(bg)
	c := doctorCheck(t, r, "history", "default", "fail")
	if c.Code != apperr.CodeRollback {
		t.Fatalf("%+v", r)
	}
}

type doctorCorruptStore struct{ storage.Store }

func (s doctorCorruptStore) OpenBlob(context.Context, storage.Kind, string, digest.Digest, int) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("corrupt ciphertext")), nil
}

func TestDoctorDetectsCorruptCiphertext(t *testing.T) {
	a := newAlice(t)
	a.Storage = doctorCorruptStore{a.Storage}
	r := a.Diagnose(bg)
	c := doctorCheck(t, r, "history", "default", "fail")
	if c.Code != apperr.CodeUntrusted {
		t.Fatalf("%+v", r)
	}
}

func TestDoctorFindsConflictsWithoutAcceptingHeads(t *testing.T) {
	a := newAlice(t)
	cfg, _ := a.loadProject()
	parents := revisionsOf(t, a, "default")
	control := digest.Digest(genesisOf(t, a))
	s, err := a.openControl(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, value := range []string{"left", "right"} {
		ciphertext, err := age.EncryptForPublicKeys([]byte("{\"KEY\":\""+value+"\"}"), s.head.Recipients())
		if err != nil {
			t.Fatal(err)
		}
		publishRevision(t, a.Storage, a, cfg.WorkspaceID, cfg.Resource("default"), control, ciphertext, parents...)
	}
	before := doctorFiles(t, a.CheckpointDir)
	r := a.Diagnose(bg)
	doctorCheck(t, r, "conflicts", "default", "fail")
	if !reflect.DeepEqual(before, doctorFiles(t, a.CheckpointDir)) {
		t.Fatal("diagnosis accepted conflicting heads")
	}
}

func TestDoctorUnapprovedDeviceStillVerifiesHistory(t *testing.T) {
	a := newAlice(t)
	other := newDevice(t, a)
	requestJoin(t, other)
	r := other.Diagnose(bg)
	doctorCheck(t, r, "membership", "", "fail")
	doctorCheck(t, r, "history", "default", "ok")
	doctorCheck(t, r, "decrypt", "default", "skip")
}

func TestDoctorReportsMissingAndMalformedConfig(t *testing.T) {
	a := &App{RepositoryDir: t.TempDir()}
	doctorCheck(t, a.Diagnose(bg), "config", "", "skip")
	if err := os.WriteFile(filepath.Join(a.RepositoryDir, "enbu.toml"), []byte("broken = ["), 0600); err != nil {
		t.Fatal(err)
	}
	r := a.Diagnose(bg)
	doctorCheck(t, r, "config", "", "fail")
	if r.Healthy {
		t.Fatal("malformed config is healthy")
	}
}

func TestDoctorChecksGitHubTokenAndRedactsProviderErrors(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "invalid"}[valid], func(t *testing.T) {
			a := newAlice(t)
			a.StorageURL = "oci://ghcr.io/owner/repo"
			calls := 0
			r := a.diagnose(bg, func(ctx context.Context, token string) error {
				calls++
				if token != "tok" {
					t.Fatal("wrong token")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("no timeout")
				}
				if !valid {
					return errors.New("PROVIDER_PRIVATE_RESPONSE")
				}
				return nil
			})
			status := "ok"
			if !valid {
				status = "fail"
			}
			doctorCheck(t, r, "github_auth", "", status)
			// The independent storage/control checks continue after an API failure.
			doctorCheck(t, r, "control", "", "ok")
			encoded, _ := json.Marshal(r)
			if calls != 1 || strings.Contains(string(encoded), "PROVIDER_PRIVATE_RESPONSE") {
				t.Fatalf("%s", encoded)
			}
		})
	}
}

func TestDoctorHonorsCancelledContext(t *testing.T) {
	a := newAlice(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	r := a.Diagnose(ctx)
	if r.Healthy {
		t.Fatalf("cancelled report: %+v", r)
	}
}

func TestDoctorDetectsMissingAncestorEvenOnANewDevice(t *testing.T) {
	a := newAlice(t)
	old := revisionsOf(t, a, "default")
	if err := a.AddSecret(bg, "default", "NEXT", "value"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := a.loadProject()
	for _, rev := range old {
		if err := a.Storage.Delete(bg, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")), rev); err != nil {
			t.Fatal(err)
		}
	}
	a.CheckpointDir = t.TempDir()
	r := a.Diagnose(bg)
	c := doctorCheck(t, r, "history", "default", "fail")
	if c.Code != apperr.CodeRollback {
		t.Fatalf("%+v", r)
	}
}

type doctorOfflineStore struct{ storage.Store }

func (s doctorOfflineStore) Discover(context.Context, storage.Kind, string) ([]digest.Digest, error) {
	return nil, errors.New("PRIVATE_STORAGE_RESPONSE")
}
func TestDoctorStorageFailureDoesNotExposeResponse(t *testing.T) {
	a := newAlice(t)
	a.Storage = doctorOfflineStore{a.Storage}
	r := a.Diagnose(bg)
	doctorCheck(t, r, "storage", "", "fail")
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "PRIVATE_STORAGE_RESPONSE") {
		t.Fatal("storage response exposed")
	}
}

func TestDoctorGHCRWithoutTokenProviderDoesNotPanic(t *testing.T) {
	a := newAlice(t)
	a.TokenProvider = nil
	a.StorageURL = "oci://ghcr.io/owner/repo"
	r := a.Diagnose(bg)
	doctorCheck(t, r, "github_auth", "", "fail")
	credential := a.ociCredential("ghcr.io")
	if _, err := credential(bg, "ghcr.io"); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("%v", err)
	}
}

func TestDoctorWithoutIdentityStoreDoesNotInventBackendFailure(t *testing.T) {
	a := &App{RepositoryDir: t.TempDir()}
	r := a.Diagnose(bg)
	doctorCheck(t, r, "config", "", "skip")
	for _, c := range r.Checks {
		if c.Name == "identity_backend" {
			t.Fatal("unconfigured identity store reported as an unavailable backend")
		}
	}
}

func TestDoctorUsesCallerBudgetAndReportsHistoryDeadline(t *testing.T) {
	for _, limited := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlimited", true: "caller-deadline"}[limited], func(t *testing.T) {
			a := newAlice(t)
			fake := clockwork.NewFakeClock()
			ctx := bg
			var cancel context.CancelFunc
			if limited {
				ctx, cancel = clock.WithTimeout(bg, fake, 2*time.Hour)
				defer cancel()
			}
			checks := 0
			a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{OpenBlob: func(got context.Context, store storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
				checks++
				deadline, ok := got.Deadline()
				want, wantOK := ctx.Deadline()
				if ok != wantOK || !deadline.Equal(want) {
					t.Fatalf("diagnosis replaced caller budget: got %v/%t want %v/%t", deadline, ok, want, wantOK)
				}
				if limited {
					fake.Advance(2 * time.Hour)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return store.OpenBlob(got, kind, scope, rev, index)
			}})
			r := a.Diagnose(ctx)
			if checks == 0 {
				t.Fatal("no ciphertext checked")
			}
			if limited {
				doctorCheck(t, r, "history", "default", "fail")
				if r.Healthy {
					t.Fatal("incomplete diagnosis reported healthy")
				}
			} else if !r.Healthy {
				t.Fatalf("%+v", r)
			}
		})
	}
}

type doctorKeys struct {
	IdentityStore
	active, retained identity.Identity
}

func (s doctorKeys) Load(string) (identity.Identity, error) { return s.active, nil }
func (s doctorKeys) LoadRetained(string) ([]identity.Identity, error) {
	if s.retained == nil {
		return nil, nil
	}
	return []identity.Identity{s.retained}, nil
}

func TestDoctorChecksApprovedEncryptionRecipientWithoutHistory(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "mismatch", true: "approved-retained-key"}[retained], func(t *testing.T) {
			a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
			cfg, err := a.loadProject()
			if err != nil {
				t.Fatal(err)
			}
			approved, err := a.Identities.Load(cfg.WorkspaceID)
			if err != nil {
				t.Fatal(err)
			}
			other := identity.FromX25519(mustKeyPair(t).Identity)
			keys := doctorKeys{IdentityStore: a.Identities, active: other}
			if retained {
				keys.retained = approved
			} else {
				defer func() { _ = approved.Close() }()
			}
			a.Identities = keys
			r := a.Diagnose(bg)
			doctorCheck(t, r, "membership", "", "ok")
			doctorCheck(t, r, "history", "default", "skip")
			status := "fail"
			if retained {
				status = "ok"
			}
			doctorCheck(t, r, "encryption_key", "", status)
			if r.Healthy != retained {
				t.Fatalf("mismatched recipient health: %+v", r)
			}
		})
	}
}

type doctorContextKeys struct {
	IdentityStore
	got context.Context
}

func (s *doctorContextKeys) Doctor(ctx context.Context) identity.Diagnosis {
	s.got = ctx
	return identity.Diagnosis{FallbackAvailable: true}
}
func TestDoctorPassesContextToIdentityProbe(t *testing.T) {
	a := newAlice(t)
	keys := &doctorContextKeys{IdentityStore: a.Identities}
	a.Identities = keys
	ctx, cancel := context.WithCancel(bg)
	cancel()
	a.Diagnose(ctx)
	if keys.got != ctx || !errors.Is(keys.got.Err(), context.Canceled) {
		t.Fatal("identity probe lost caller cancellation")
	}
}

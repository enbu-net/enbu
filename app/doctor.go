package app

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	githubprovider "github.com/enbu-net/enbu/pkg/provider/github"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
	"uuid"
)

// DiagnosticCheck contains only safe descriptions and error codes, never
// provider response bodies, credentials, or decrypted secret names and values.
type DiagnosticCheck struct {
	Name        string      `json:"name"`
	Environment string      `json:"environment,omitempty"`
	Status      string      `json:"status"`
	Message     string      `json:"message"`
	Code        apperr.Code `json:"code,omitempty"`
}

type DoctorReport struct {
	identity.Diagnosis
	Healthy bool              `json:"healthy"`
	Checks  []DiagnosticCheck `json:"checks"`
}

func (r *DoctorReport) add(name, env, status, message string, err error) {
	c := DiagnosticCheck{Name: name, Environment: env, Status: status, Message: message}
	if err != nil {
		c.Code = apperr.CodeOf(apperr.Normalize(err))
	}
	if status == "fail" {
		r.Healthy = false
	}
	r.Checks = append(r.Checks, c)
}

// addIdentityBackend says where a new identity would go, or what the person
// must fix first: hardware they may not use, a locked keyring, or none. It
// follows ENBU_IDENTITY_BACKEND: hardware never falls back, keyring never uses
// the hardware.
func (r *DoctorReport) addIdentityBackend() {
	hardware := r.Mode != "keyring" && r.Available
	keyring := r.Mode != "hardware" && (r.Mode == "keyring" || !r.Denied) && r.FallbackAvailable
	switch {
	case r.WSL != nil && r.WSL.Error != "":
		r.add("identity_backend", "", "warn", "Inside WSL, enbu keeps its keys in Windows, and the Windows enbu.exe cannot be used: "+r.WSL.Error,
			apperr.New(apperr.CodeIdentityUnavailable, r.WSL.Error, nil))
	case hardware:
		r.add("identity_backend", "", "ok", "New identities use the hardware ("+r.Backend+")"+inWindows(r)+".", nil)
	case keyring:
		r.add("identity_backend", "", "ok", "New identities use a software key in the OS keyring"+inWindows(r)+".", nil)
	case r.Mode == "hardware":
		r.add("identity_backend", "", "warn", "ENBU_IDENTITY_BACKEND=hardware, but the hardware ("+r.Backend+") is unavailable: "+r.Reason+".",
			apperr.New(apperr.CodeIdentityUnavailable, r.Reason, nil))
	case r.Mode != "keyring" && r.Denied:
		r.add("identity_backend", "", "warn", "The hardware ("+r.Backend+") exists but this user may not use it, and enbu does not fall back to a software key: "+r.Reason+". Or set ENBU_IDENTITY_BACKEND=keyring to use the OS keyring.",
			apperr.New(apperr.CodeIdentityUnavailable, r.Reason, nil))
	case r.WSL != nil:
		r.add("identity_backend", "", "warn", "Windows has no usable hardware and no Credential Manager for a software key: "+r.KeyringReason+". Run enbu.exe doctor in Windows.",
			apperr.New(apperr.CodeIdentityUnavailable, r.KeyringReason, nil))
	case r.KeyringLocked:
		r.add("identity_backend", "", "warn", "The OS keyring is locked. Unlock it (log in to the desktop, or run gnome-keyring-daemon --unlock) and retry.",
			apperr.New(apperr.CodeKeyringLocked, r.KeyringReason, nil))
	default:
		r.add("identity_backend", "", "warn", "No usable hardware and no OS keyring. Install and unlock a Secret Service (GNOME Keyring or KWallet) to keep a software key.",
			apperr.New(apperr.CodeIdentityUnavailable, r.KeyringReason, nil))
	}
}

// inWindows names the Windows side when WSL hands its keys to enbu.exe.
func inWindows(r *DoctorReport) string {
	if r.WSL == nil {
		return ""
	}
	return " of Windows, through " + r.WSL.Exe
}

// Diagnose checks all configured environments without publishing data,
// creating keys, promoting keys, or advancing trust pins and checkpoints.
// Successful execution produces a report even when individual checks fail.
// The caller controls the overall budget: retained histories have no fixed size.
func (a *App) Diagnose(ctx context.Context) DoctorReport {
	return a.diagnose(ctx, func(ctx context.Context, token string) error {
		_, err := githubprovider.NewClient(token).GetUser(ctx)
		return err
	})
}

func (a *App) diagnose(ctx context.Context, validateToken func(context.Context, string) error) DoctorReport {
	r := DoctorReport{Healthy: true, Checks: []DiagnosticCheck{}}
	if a.Identities != nil {
		r.Diagnosis = a.DiagnoseIdentity(ctx)
		r.addIdentityBackend()
	}
	cfg, err := a.loadProject()
	if err != nil {
		status := "fail"
		if apperr.Is(err, apperr.CodeConfigNotFound) {
			status = "skip"
		}
		r.add("config", "", status, "No readable workspace configuration; workspace checks were skipped.", err)
		return r
	}
	if err := validateDoctorConfig(cfg); err != nil {
		r.add("config", "", "fail", "Workspace configuration is invalid.", err)
		return r
	}
	r.add("config", "", "ok", "Configuration and environment outputs are valid.", nil)
	a.diagnoseAuth(ctx, cfg, &r, validateToken)
	store, err := a.openStorage(ctx, cfg)
	if err == nil {
		_, err = store.Discover(ctx, storage.KindControl, "")
	}
	if err != nil {
		r.add("storage", "", "fail", "Cannot read the configured storage; control and environment checks were skipped.", err)
		return r
	}
	r.add("storage", "", "ok", "Storage listing is accessible (write access is not tested).", nil)
	s := &session{app: a, store: store, cfg: cfg, workspace: cfg.WorkspaceID, diagnostic: true}
	defer s.Close()
	if err := a.verifyControl(ctx, s); err != nil {
		r.add("control", "", "fail", "Control signatures, trust root or rollback protection failed; environment checks were skipped.", err)
		return r
	}
	if s.head == nil {
		r.add("control", "", "fail", "Control has competing heads; an admin of every head joins them on their next enbu operation.", wspError(&wsp.ForkError{Heads: s.view.Heads}))
		return r
	}
	r.add("control", "", "ok", "Control signatures, trust pins and checkpoint are valid.", nil)
	a.diagnoseDevice(s, &r)
	names := cfg.EnvironmentNames()
	for _, name := range names {
		if ctx.Err() != nil {
			r.add("history", name, "fail", "Diagnosis was cancelled or timed out.", ctx.Err())
			continue
		}
		s.diagnoseEnvironment(ctx, name, &r)
	}
	return r
}

func validateDoctorConfig(cfg *config.ProjectConfig) error {
	invalid := func() error { return apperr.New(apperr.CodeInvalidArgument, "invalid workspace configuration", nil) }
	if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
		return invalid()
	}
	if digest.Digest(cfg.ControlGenesis).Validate() != nil {
		return invalid()
	}
	if err := config.ValidateProjectOutputs(cfg); err != nil {
		return err
	}
	if _, err := cfg.Environment(cfg.CurrentEnvironment()); err != nil {
		return err
	}
	for name := range cfg.Environments {
		if !config.ValidEnvironmentName(name) {
			return invalid()
		}
	}
	if cfg.DefaultEnv != "" {
		if _, err := cfg.Environment(cfg.DefaultEnv); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) diagnoseAuth(ctx context.Context, cfg *config.ProjectConfig, r *DoctorReport, validate func(context.Context, string) error) {
	location := cfg.Storage.URL
	if a.StorageURL != "" {
		location = a.StorageURL
	}
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "oci" || u.Host != "ghcr.io" {
		r.add("github_auth", "", "skip", "GitHub login is only required for GHCR; storage checks validate the configured backend's read access.", nil)
		return
	}
	var token string
	if a.TokenProvider != nil {
		token, _, err = a.TokenProvider.LoadToken()
	}
	if err != nil || token == "" {
		r.add("github_auth", "", "fail", "GitHub credentials are unavailable; run enbu auth login.", apperr.New(apperr.CodeNotAuthenticated, "GitHub credentials unavailable", nil))
		return
	}
	authCtx, cancel := clock.WithTimeout(ctx, a.clock(), 10*time.Second)
	defer cancel()
	if err := validate(authCtx, token); err != nil {
		r.add("github_auth", "", "fail", "GitHub could not validate the saved token; check connectivity or sign in again.", err)
		return
	}
	r.add("github_auth", "", "ok", "GitHub accepted the saved token.", nil)
}

func (a *App) diagnoseDevice(s *session, r *DoctorReport) {
	if a.Identities == nil {
		r.add("membership", "", "fail", "No identity store is configured.", apperr.New(apperr.CodeNotInitialized, "no identity store", nil))
		return
	}
	signer, err := a.Identities.LoadSigner(s.workspace)
	if err != nil {
		r.add("membership", "", "fail", "The saved signing key cannot be loaded; run enbu init if this device has not joined.", identityError(err))
		return
	}
	s.signer = signer
	principal, ok := s.head.Principal(s.self())
	if !ok {
		r.add("membership", "", "fail", "This device is not an approved member.", apperr.New(apperr.CodeNotMember, "device is not approved", nil))
		return
	}
	r.add("membership", "", "ok", "The signing key belongs to an approved member.", nil)
	s.ids, err = LoadIdentities(a.Identities, s.workspace)
	if err != nil {
		r.add("encryption_key", "", "fail", "The saved encryption identity cannot be loaded.", err)
		return
	}
	for _, id := range s.ids {
		if key, ok := id.(identity.Identity); ok && key.Recipient().String() == principal.Recipient {
			r.add("encryption_key", "", "ok", "A saved encryption identity matches this device's approved recipient.", nil)
			return
		}
	}
	CloseIdentities(s.ids)
	s.ids = nil
	r.add("encryption_key", "", "fail", "No saved encryption identity matches this device's approved recipient.", apperr.New(apperr.CodeNotInitialized, "approved encryption identity is unavailable", nil))
}

func (s *session) diagnoseEnvironment(ctx context.Context, name string, r *DoctorReport) {
	resource := s.resource(name)
	sv, err := s.loadResource(ctx, resource)
	if apperr.Is(err, apperr.CodeArtifactNotFound) || errors.Is(err, storage.ErrNotFound) {
		accepted, cpErr := s.cps.State(resource)
		if cpErr != nil {
			r.add("history", name, "fail", "Cannot read the local history checkpoint.", cpErr)
		} else if len(accepted) > 0 {
			r.add("history", name, "fail", "Previously accepted history is missing from storage.", wspError(wsp.ErrRollback))
		} else {
			r.add("history", name, "skip", "This environment has no revisions yet.", nil)
		}
		return
	}
	if err != nil {
		r.add("history", name, "fail", "History signature, ancestry or checkpoint verification failed.", err)
		return
	}
	if len(sv.MissingParents()) > 0 {
		r.add("history", name, "fail", "History has missing ancestors without a signed compaction record.", wspError(wsp.ErrRollback))
		return
	}
	// Read every retained ciphertext to detect missing or corrupted old blobs too.
	revs := make([]digest.Digest, 0, len(sv.States))
	for rev := range sv.States {
		revs = append(revs, rev)
	}
	slices.Sort(revs)
	for _, rev := range revs {
		if _, err := wsp.ReadCiphertext(ctx, s.store, sv.States[rev]); err != nil {
			r.add("history", name, "fail", "A retained ciphertext is missing or corrupt.", wspError(err))
			return
		}
	}
	r.add("history", name, "ok", "Retained signatures, ciphertext digests and rollback checkpoints are valid.", nil)
	if len(s.ids) == 0 {
		r.add("decrypt", name, "skip", "Decryption and conflict checks require this device's approved identity.", nil)
		return
	}
	read, err := s.mergeResource(ctx, resource, sv, nil)
	if err != nil {
		r.add("decrypt", name, "fail", "Current revisions cannot be decrypted or merged with this device's identity.", err)
		return
	}
	r.add("decrypt", name, "ok", "Current revisions decrypt successfully.", nil)
	if len(read.conflicts) > 0 {
		r.add("conflicts", name, "fail", "Concurrent edits conflict; run enbu resolve.", apperr.New(apperr.CodeSecretConflict, "secret conflict", nil))
	} else {
		r.add("conflicts", name, "ok", "No unresolved secret conflicts.", nil)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
)

// DesktopService is everything the frontend can call. The binding generator
// writes a typed TypeScript client for it into web/src/bindings.
type DesktopService struct {
	core *desktop.Service
}

// bindingError carries the payload of a normalized AppError to the frontend.
// Its message is the payload's, so the cause of an internal error never
// leaves the process; it is logged here instead.
type bindingError struct {
	payload apperr.Payload
}

func (e *bindingError) Error() string { return e.payload.Message }

func publicError(err error) error {
	if err == nil {
		return nil
	}
	return toBindingError(err)
}

func toBindingError(err error) *bindingError {
	normalized := apperr.Normalize(err)
	payload := apperr.PayloadOf(normalized)
	if payload.Code == apperr.CodeInternal || payload.Code == apperr.CodeUnavailable {
		slog.Error("desktop operation failed", "err", normalized)
	}
	return &bindingError{payload: payload}
}

func result[T any](value T, err error) (T, error) {
	return value, publicError(err)
}

// marshalError is the cause the frontend receives with a failed call: the
// AppError payload of errors from DesktopService, and an internal one for
// anything else.
func marshalError(err error) []byte {
	var be *bindingError
	if !errors.As(err, &be) {
		be = toBindingError(err)
	}
	data, err := json.Marshal(be.payload)
	if err != nil {
		return nil
	}
	return data
}

func (s *DesktopService) GetAuthStatus() (desktop.AuthStatus, error) {
	return result(s.core.GetAuthStatus())
}

func (s *DesktopService) StartOAuthLogin() (desktop.OAuthStart, error) {
	return result(s.core.StartOAuthLogin())
}

func (s *DesktopService) GetOAuthLoginStatus(sessionID string) (desktop.OAuthStatus, error) {
	return result(s.core.GetOAuthLoginStatus(sessionID))
}

func (s *DesktopService) CancelOAuthLogin(sessionID string) error {
	return publicError(s.core.CancelOAuthLogin(sessionID))
}

func (s *DesktopService) Logout() error {
	return publicError(s.core.Logout())
}

func (s *DesktopService) BrowseRepository() (desktop.RepoInfo, error) {
	return result(s.core.BrowseRepository())
}

func (s *DesktopService) SelectRepository(path string) (desktop.RepoInfo, error) {
	return result(s.core.SelectRepository(path))
}

func (s *DesktopService) GetRepoStatus() (desktop.RepoInfo, error) {
	return result(s.core.GetRepoStatus())
}

func (s *DesktopService) SuggestStorage() (string, error) {
	return result(s.core.SuggestStorage())
}

func (s *DesktopService) Initialize(storage desktop.StorageSettings, acceptNewGenesis bool) (desktop.InitResult, error) {
	return result(s.core.Initialize(storage, acceptNewGenesis))
}

func (s *DesktopService) ListEnvironments() ([]desktop.Environment, error) {
	return result(s.core.ListEnvironments())
}

func (s *DesktopService) CreateEnvironment(name string) error {
	return publicError(s.core.CreateEnvironment(name))
}

func (s *DesktopService) SwitchEnvironment(name string) error {
	return publicError(s.core.SwitchEnvironment(name))
}

func (s *DesktopService) RenameEnvironment(name, newName string) error {
	return publicError(s.core.RenameEnvironment(name, newName))
}

func (s *DesktopService) DeleteEnvironment(name string, purge bool) (desktop.EnvironmentDeletion, error) {
	return result(s.core.DeleteEnvironment(name, purge))
}

func (s *DesktopService) PurgeIncarnation(incarnation string) (int, error) {
	return result(s.core.PurgeIncarnation(incarnation))
}

func (s *DesktopService) ListSecrets(env string) (desktop.SecretsResponse, error) {
	return result(s.core.ListSecrets(env))
}

func (s *DesktopService) AddSecret(env, key, value string) error {
	return publicError(s.core.AddSecret(env, key, value))
}

func (s *DesktopService) EditSecret(env, key, value string) error {
	return publicError(s.core.EditSecret(env, key, value))
}

func (s *DesktopService) DeleteSecret(env, key string) error {
	return publicError(s.core.DeleteSecret(env, key))
}

func (s *DesktopService) PullSecrets(env string, replace bool) (desktop.PullResult, error) {
	return result(s.core.PullSecrets(env, replace))
}

func (s *DesktopService) SyncSecrets(env string) error {
	return publicError(s.core.SyncSecrets(env))
}

func (s *DesktopService) ListConflicts(env string) (desktop.ConflictSet, error) {
	return result(s.core.ListConflicts(env))
}

func (s *DesktopService) ResolveConflicts(env string, heads []string, choices []desktop.ConflictChoice) error {
	return publicError(s.core.ResolveConflicts(env, heads, choices))
}

func (s *DesktopService) ImportSecrets(env, dotenv string, overwrite bool) (app.ImportResult, error) {
	return result(s.core.ImportSecrets(env, dotenv, overwrite))
}

func (s *DesktopService) ListHistory(env string) ([]desktop.HistoryEntry, error) {
	return result(s.core.ListHistory(env))
}

func (s *DesktopService) DiffHistory(env string, from, to int) (*app.Diff, error) {
	return result(s.core.DiffHistory(env, from, to))
}

func (s *DesktopService) RestoreHistory(env string, index int) error {
	return publicError(s.core.RestoreHistory(env, index))
}

func (s *DesktopService) ListRepositories() ([]desktop.RepoInfo, error) {
	return result(s.core.ListRepositories())
}

func (s *DesktopService) RemoveRepository(path string) error {
	return publicError(s.core.RemoveRepository(path))
}

func (s *DesktopService) ListMembers() ([]desktop.Member, error) {
	return result(s.core.ListMembers())
}

func (s *DesktopService) ListJoinRequests() ([]desktop.JoinRequest, error) {
	return result(s.core.ListJoinRequests())
}

func (s *DesktopService) ApproveMember(deviceID string) error {
	return publicError(s.core.ApproveMember(deviceID))
}

func (s *DesktopService) RemoveMember(deviceID string) error {
	return publicError(s.core.RemoveMember(deviceID))
}

func (s *DesktopService) SetAdmin(deviceID string, admin bool) error {
	return publicError(s.core.SetAdmin(deviceID, admin))
}

func (s *DesktopService) ResolveMemberFork() error {
	return publicError(s.core.ResolveMemberFork())
}

func (s *DesktopService) GetIdentity() (identity.PublicInfo, error) {
	return result(s.core.GetIdentity())
}

func (s *DesktopService) DiagnoseIdentity() desktop.IdentityDiagnosis {
	return s.core.DiagnoseIdentity()
}

func (s *DesktopService) UpgradeIdentity() (app.KeyUpdateResult, error) {
	return result(s.core.UpgradeIdentity())
}

func (s *DesktopService) ReadConfig() (string, error) {
	return result(s.core.ReadConfig())
}

func (s *DesktopService) WriteConfig(content string) error {
	return publicError(s.core.WriteConfig(content))
}

func (s *DesktopService) GetAppVersion() string {
	return s.core.GetAppVersion()
}

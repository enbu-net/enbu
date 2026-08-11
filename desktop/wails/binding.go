package main

import (
	"log/slog"

	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/apperr"
)

type BindingResponse struct {
	Data  any             `json:"data"`
	Error *apperr.Payload `json:"error,omitempty"`
}

type DesktopService struct {
	service *desktop.Service
}

func bindingResult[T any](data T, err error) BindingResponse {
	if err == nil {
		return BindingResponse{Data: data}
	}
	normalized := apperr.Normalize(err)
	payload := apperr.PayloadOf(normalized)
	if payload.Code == apperr.CodeInternal || payload.Code == apperr.CodeUnavailable {
		slog.Error("desktop operation failed", "err", normalized)
	}
	return BindingResponse{Error: &payload}
}

func bindingError(err error) BindingResponse {
	return bindingResult[any](nil, err)
}

func (s *DesktopService) GetAuthStatus() BindingResponse {
	value, err := s.service.GetAuthStatus()
	return bindingResult(value, err)
}

func (s *DesktopService) StartOAuthLogin() BindingResponse {
	value, err := s.service.StartOAuthLogin()
	return bindingResult(value, err)
}

func (s *DesktopService) GetOAuthLoginStatus(sessionID string) BindingResponse {
	value, err := s.service.GetOAuthLoginStatus(sessionID)
	return bindingResult(value, err)
}

func (s *DesktopService) CancelOAuthLogin(sessionID string) BindingResponse {
	return bindingError(s.service.CancelOAuthLogin(sessionID))
}

func (s *DesktopService) Logout() BindingResponse {
	return bindingError(s.service.Logout())
}

func (s *DesktopService) BrowseRepository() BindingResponse {
	value, err := s.service.BrowseRepository()
	return bindingResult(value, err)
}

func (s *DesktopService) SelectRepository(path string) BindingResponse {
	value, err := s.service.SelectRepository(path)
	return bindingResult(value, err)
}

func (s *DesktopService) GetRepoStatus() BindingResponse {
	value, err := s.service.GetRepoStatus()
	return bindingResult(value, err)
}

func (s *DesktopService) Initialize() BindingResponse {
	value, err := s.service.Initialize()
	return bindingResult(value, err)
}

func (s *DesktopService) ListEnvironments() BindingResponse {
	value, err := s.service.ListEnvironments()
	return bindingResult(value, err)
}

func (s *DesktopService) CreateEnvironment(name string) BindingResponse {
	return bindingError(s.service.CreateEnvironment(name))
}

func (s *DesktopService) SwitchEnvironment(name string) BindingResponse {
	return bindingError(s.service.SwitchEnvironment(name))
}

func (s *DesktopService) RenameEnvironment(name, newName string) BindingResponse {
	return bindingError(s.service.RenameEnvironment(name, newName))
}

func (s *DesktopService) DeleteEnvironment(name string) BindingResponse {
	return bindingError(s.service.DeleteEnvironment(name))
}

func (s *DesktopService) ListSecrets(env string) BindingResponse {
	value, err := s.service.ListSecrets(env)
	return bindingResult(value, err)
}

func (s *DesktopService) AddSecret(env, key, value string) BindingResponse {
	return bindingError(s.service.AddSecret(env, key, value))
}

func (s *DesktopService) EditSecret(env, key, value string) BindingResponse {
	return bindingError(s.service.EditSecret(env, key, value))
}

func (s *DesktopService) DeleteSecret(env, key string) BindingResponse {
	return bindingError(s.service.DeleteSecret(env, key))
}

func (s *DesktopService) PullSecrets(env string) BindingResponse {
	return bindingError(s.service.PullSecrets(env))
}

func (s *DesktopService) SyncSecrets(env string) BindingResponse {
	return bindingError(s.service.SyncSecrets(env))
}

func (s *DesktopService) ListHistory(env string) BindingResponse {
	value, err := s.service.ListHistory(env)
	return bindingResult(value, err)
}

func (s *DesktopService) DiffHistory(env string, from, to int) BindingResponse {
	value, err := s.service.DiffHistory(env, from, to)
	return bindingResult(value, err)
}

func (s *DesktopService) RestoreHistory(env string, index int) BindingResponse {
	return bindingError(s.service.RestoreHistory(env, index))
}

func (s *DesktopService) ListRepositories() BindingResponse {
	value, err := s.service.ListRepositories()
	return bindingResult(value, err)
}

func (s *DesktopService) RemoveRepository(path string) BindingResponse {
	return bindingError(s.service.RemoveRepository(path))
}

func (s *DesktopService) ListRecipients() BindingResponse {
	value, err := s.service.ListRecipients()
	return bindingResult(value, err)
}

func (s *DesktopService) ReadConfig() BindingResponse {
	value, err := s.service.ReadConfig()
	return bindingResult(value, err)
}

func (s *DesktopService) WriteConfig(content string) BindingResponse {
	return bindingError(s.service.WriteConfig(content))
}

func (s *DesktopService) GetAppVersion() BindingResponse {
	return bindingResult(s.service.GetAppVersion(), nil)
}

func (s *DesktopService) StartHostOperation(action string) BindingResponse {
	value, err := s.service.StartHostOperation(action)
	return bindingResult(value, err)
}

func (s *DesktopService) PollHostOperation(operationID string) BindingResponse {
	value, err := s.service.PollHostOperation(operationID)
	return bindingResult(value, err)
}

func (s *DesktopService) CancelHostOperation(operationID string) BindingResponse {
	return bindingError(s.service.CancelHostOperation(operationID))
}

func (s *DesktopService) GitInit(path string) BindingResponse {
	value, err := s.service.GitInit(path)
	return bindingResult(value, err)
}

func (s *DesktopService) ListRepositoryOwners() BindingResponse {
	value, err := s.service.ListRepositoryOwners()
	return bindingResult(value, err)
}

func (s *DesktopService) GitCreateRemote(path, owner, repoName string, private bool) BindingResponse {
	value, err := s.service.GitCreateRemote(path, owner, repoName, private)
	return bindingResult(value, err)
}

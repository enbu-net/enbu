package main

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	gh "github.com/enbu-net/enbu/provider/github"
)

type DesktopService struct {
	service *desktop.Service
}

func (s *DesktopService) GetAuthStatus() (desktop.AuthStatus, error) {
	return s.service.GetAuthStatus()
}

func (s *DesktopService) StartOAuthLogin() (desktop.OAuthStart, error) {
	return s.service.StartOAuthLogin()
}

func (s *DesktopService) GetOAuthLoginStatus(sessionID string) (desktop.OAuthStatus, error) {
	return s.service.GetOAuthLoginStatus(sessionID)
}

func (s *DesktopService) CancelOAuthLogin(sessionID string) error {
	return s.service.CancelOAuthLogin(sessionID)
}

func (s *DesktopService) Logout() error {
	return s.service.Logout()
}

func (s *DesktopService) BrowseRepository() (desktop.RepoInfo, error) {
	return s.service.BrowseRepository()
}

func (s *DesktopService) SelectRepository(path string) (desktop.RepoInfo, error) {
	return s.service.SelectRepository(path)
}

func (s *DesktopService) GetRepoStatus() (desktop.RepoInfo, error) {
	return s.service.GetRepoStatus()
}

func (s *DesktopService) Initialize() (map[string]any, error) {
	return s.service.Initialize()
}

func (s *DesktopService) ListEnvironments() ([]desktop.Environment, error) {
	return s.service.ListEnvironments()
}

func (s *DesktopService) CreateEnvironment(name string) error {
	return s.service.CreateEnvironment(name)
}

func (s *DesktopService) SwitchEnvironment(name string) error {
	return s.service.SwitchEnvironment(name)
}

func (s *DesktopService) RenameEnvironment(name, newName string) error {
	return s.service.RenameEnvironment(name, newName)
}

func (s *DesktopService) DeleteEnvironment(name string) error {
	return s.service.DeleteEnvironment(name)
}

func (s *DesktopService) ListSecrets(env string) (desktop.SecretsResponse, error) {
	return s.service.ListSecrets(env)
}

func (s *DesktopService) AddSecret(env, key, value string) error {
	return s.service.AddSecret(env, key, value)
}

func (s *DesktopService) EditSecret(env, key, value string) error {
	return s.service.EditSecret(env, key, value)
}

func (s *DesktopService) DeleteSecret(env, key string) error {
	return s.service.DeleteSecret(env, key)
}

func (s *DesktopService) PullSecrets(env string) error {
	return s.service.PullSecrets(env)
}

func (s *DesktopService) ExportSecrets(env string) error {
	return s.service.ExportSecrets(env)
}

func (s *DesktopService) SyncSecrets(env string) error {
	return s.service.SyncSecrets(env)
}

func (s *DesktopService) ListHistory(env string) ([]desktop.HistoryEntry, error) {
	return s.service.ListHistory(env)
}

func (s *DesktopService) DiffHistory(env string, from, to int) (*app.Diff, error) {
	return s.service.DiffHistory(env, from, to)
}

func (s *DesktopService) RestoreHistory(env string, index int) error {
	return s.service.RestoreHistory(env, index)
}

func (s *DesktopService) ListRepositories() ([]desktop.RepoInfo, error) {
	return s.service.ListRepositories()
}

func (s *DesktopService) RemoveRepository(path string) error {
	return s.service.RemoveRepository(path)
}

func (s *DesktopService) ListRecipients() ([]desktop.Recipient, error) {
	return s.service.ListRecipients()
}

func (s *DesktopService) ReadConfig() (string, error) {
	return s.service.ReadConfig()
}

func (s *DesktopService) WriteConfig(content string) error {
	return s.service.WriteConfig(content)
}

func (s *DesktopService) GetAppVersion() string {
	return s.service.GetAppVersion()
}

func (s *DesktopService) GitInit(path string) (desktop.RepoInfo, error) {
	return s.service.GitInit(path)
}

func (s *DesktopService) ListRepositoryOwners() ([]gh.RepositoryOwner, error) {
	return s.service.ListRepositoryOwners()
}

func (s *DesktopService) GitCreateRemote(path, owner, repoName string, private bool) (desktop.RepoInfo, error) {
	return s.service.GitCreateRemote(path, owner, repoName, private)
}

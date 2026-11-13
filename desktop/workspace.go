package desktop

import (
	"log/slog"
	"sort"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

type SecretsResponse struct {
	Environment string       `json:"environment"`
	Secrets     []SecretItem `json:"secrets"`
}

type SecretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *Service) ListMembers() ([]app.MemberInfo, error) {
	return withRepoResult(s, func() ([]app.MemberInfo, error) { return s.app.ListMembers(s.context()) })
}

func (s *Service) ListJoinRequests() ([]app.JoinRequestInfo, error) {
	return withRepoResult(s, func() ([]app.JoinRequestInfo, error) { return s.app.ListJoinRequests(s.context()) })
}

// ApproveMember is called after the admin has compared the device's
// fingerprint with the person who owns it.
func (s *Service) ApproveMember(deviceID string) error {
	return s.withRepo(func() error { return s.app.ApproveMember(s.context(), deviceID) })
}

func (s *Service) RemoveMember(deviceID string) error {
	return s.withRepo(func() error { return s.app.RemoveMember(s.context(), deviceID) })
}

// SetAdmin grants or revokes the right to manage members. Granting it is as
// sensitive as approving a device, so the frontend confirms the fingerprint.
func (s *Service) SetAdmin(deviceID string, admin bool) error {
	return s.withRepo(func() error { return s.app.SetAdmin(s.context(), deviceID, admin) })
}

func (s *Service) ReadConfig() (string, error) {
	return withRepoResult(s, func() (string, error) {
		return s.app.ReadConfig()
	})
}

func (s *Service) WriteConfig(content string) error {
	return s.withRepo(func() error { return s.app.WriteConfig(content) })
}

// ChangeStorage migrates verified history before updating the shared configuration.
func (s *Service) ChangeStorage(settings config.StorageConfig) error {
	return s.withRepo(func() error { return s.app.ChangeStorage(s.context(), settings) })
}

// SuggestStorage is the storage Initialize founds a workspace in when given
// none: GHCR beside the GitHub origin, or under the signed-in account.
func (s *Service) SuggestStorage() (string, error) {
	return withRepoResult(s, func() (string, error) { return s.app.DefaultStorageURL() })
}

// Initialize sets this device up in the selected repository, as `enbu init`
// does. It founds a workspace in storage, or in SuggestStorage's when
// storage.URL is empty; with an enbu.toml that names a storage it joins that
// workspace, and storage.URL must be empty. acceptNewGenesis is
// `--accept-new-genesis`.
func (s *Service) Initialize(storage config.StorageConfig, acceptNewGenesis bool) (app.InitResult, error) {
	return withRepoResult(s, func() (app.InitResult, error) {
		opts := app.InitOptions{AcceptNewGenesis: acceptNewGenesis}
		if storage.URL != "" {
			if cfg, err := config.LoadProjectFrom(s.app.RepositoryDir); err == nil && cfg.Storage.URL != "" {
				return app.InitResult{}, apperr.New(apperr.CodeInvalidArgument, "enbu.toml already names the storage", nil)
			}
			opts.Storage = &storage
		}
		result, err := s.app.InitializeRepository(s.context(), opts)
		if err != nil {
			return app.InitResult{}, err
		}
		for _, warning := range result.Warnings {
			slog.Warn("initialize", "warning", warning)
		}
		return *result, nil
	})
}

func (s *Service) ListEnvironments() ([]app.EnvInfo, error) {
	return withRepoResult(s, s.app.ListEnvironments)
}

func (s *Service) CreateEnvironment(name string) error {
	return s.withRepo(func() error { return s.app.CreateEnvironment(name) })
}

func (s *Service) SwitchEnvironment(name string) error {
	return s.withRepo(func() error { return s.app.SwitchEnvironment(name) })
}

func (s *Service) RenameEnvironment(name, newName string) error {
	return s.withRepo(func() error { return s.app.RenameEnvironment(name, newName) })
}

// DeleteEnvironment removes an environment from enbu.toml. With purge its
// stored revisions are deleted too (admin only); without, they stay and the
// result names the incarnation PurgeIncarnation deletes them by later.
func (s *Service) DeleteEnvironment(name string, purge bool) (app.EnvironmentDeletion, error) {
	return withRepoResult(s, func() (app.EnvironmentDeletion, error) {
		return s.app.DeleteEnvironment(s.context(), name, purge)
	})
}

// PurgeIncarnation deletes the stored revisions of an environment deleted
// without purging them (admin only), and returns how many it deleted.
func (s *Service) PurgeIncarnation(incarnation string) (int, error) {
	return withRepoResult(s, func() (int, error) {
		return s.app.PurgeIncarnation(s.context(), incarnation)
	})
}

func (s *Service) ListSecrets(env string) (SecretsResponse, error) {
	return withRepoResult(s, func() (SecretsResponse, error) {
		secrets, err := s.app.ListSecrets(s.context(), env)
		if err != nil {
			return SecretsResponse{}, err
		}
		currentEnv, _ := s.app.CurrentEnvironment()
		if env == "" {
			env = currentEnv
		}
		keys := make([]string, 0, len(secrets))
		for key := range secrets {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		items := make([]SecretItem, 0, len(keys))
		for _, key := range keys {
			items = append(items, SecretItem{Key: key, Value: secrets[key]})
		}
		return SecretsResponse{Environment: env, Secrets: items}, nil
	})
}

func (s *Service) AddSecret(env, key, value string) error {
	return s.withRepo(func() error { return s.app.AddSecret(s.context(), env, key, value) })
}

func (s *Service) EditSecret(env, key, value string) error {
	return s.withRepo(func() error { return s.app.EditSecret(s.context(), env, key, value) })
}

func (s *Service) DeleteSecret(env, key string) error {
	return s.withRepo(func() error { return s.app.DeleteSecret(s.context(), env, key) })
}

// PullSecrets writes the environment's secrets to its output file. With replace
// the file's current content is dropped, including a file enbu cannot read
// (output_unreadable), which a pull otherwise refuses to overwrite.
func (s *Service) PullSecrets(env string, replace bool) (app.WrittenFile, error) {
	return withRepoResult(s, func() (app.WrittenFile, error) {
		written, err := s.app.PullSecretsToFileWith(s.context(), env, replace)
		if err != nil {
			return app.WrittenFile{}, err
		}
		return *written, nil
	})
}

func (s *Service) SyncSecrets(env string) error {
	return s.withRepo(func() error { return s.app.SyncSecrets(s.context(), env) })
}

func (s *Service) ListConflicts(env string) (app.ConflictSet, error) {
	return withRepoResult(s, func() (app.ConflictSet, error) {
		set, err := s.app.ListConflicts(s.context(), env)
		if err != nil {
			return app.ConflictSet{}, err
		}
		return *set, nil
	})
}

// ResolveConflicts publishes a decision for every conflicted key. heads are the
// ConflictSet.Heads the person decided from; if anyone wrote since, nothing is
// published and the call fails with CodeConflict.
func (s *Service) ResolveConflicts(env string, heads []string, choices []app.SecretChoice) error {
	return s.withRepo(func() error { return s.app.ResolveSecrets(s.context(), env, heads, choices) })
}

func (s *Service) ListHistory(env string) ([]app.HistoryEntry, error) {
	return withRepoResult(s, func() ([]app.HistoryEntry, error) { return s.app.ListHistory(s.context(), env) })
}

func (s *Service) DiffHistory(env string, from, to int) (app.Diff, error) {
	return withRepoResult(s, func() (app.Diff, error) {
		diff, err := s.app.DiffHistory(s.context(), env, from, to)
		if err != nil {
			return app.Diff{}, err
		}
		return *diff, nil
	})
}

func (s *Service) RestoreHistory(env string, index int) error {
	return s.withRepo(func() error { return s.app.RestoreHistory(s.context(), env, index) })
}

package desktop

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

type RepoInfo struct {
	Path              string `json:"path,omitempty"`
	Owner             string `json:"owner,omitempty"`
	Repo              string `json:"repo,omitempty"`
	Initialized       bool   `json:"initialized"`
	HasGit            bool   `json:"has_git"`
	HasRemote         bool   `json:"has_remote"`
	StorageConfigured bool   `json:"storage_configured"`
}

func (s *Service) BrowseRepository() (_ RepoInfo, err error) {
	defer publicInto(&err)
	if s.pickDir == nil {
		return RepoInfo{}, fmt.Errorf("directory picker is not available")
	}
	path, err := s.pickDir(s.context())
	if err != nil {
		return RepoInfo{}, err
	}
	if path == "" {
		return RepoInfo{}, nil
	}
	return s.SelectRepository(path)
}

func (s *Service) SelectRepository(path string) (_ RepoInfo, err error) {
	defer publicInto(&err)
	repo, err := validateRepoPath(s.context(), s.git, path)
	if err != nil {
		return RepoInfo{}, apperr.Wrap(
			apperr.CodeInvalidArgument,
			"invalid repository path",
			err,
			nil,
		)
	}
	s.repoMu.Lock()
	if err := s.context().Err(); err != nil {
		s.repoMu.Unlock()
		return RepoInfo{}, err
	}
	cfg, err := config.LoadGUI()
	if err != nil {
		cfg = &config.GUIConfig{}
	}
	cfg.SelectedRepo = repo.Path
	cfg.RepoHistory = appendUnique(cfg.RepoHistory, repo.Path)
	saveErr := config.SaveGUI(cfg)
	if saveErr == nil {
		s.repoPath = repo.Path
		s.app.SetRepositoryDir(repo.Path)
	}
	s.repoMu.Unlock()
	if saveErr != nil {
		return RepoInfo{}, saveErr
	}
	return s.repoInfo(repo)
}

func (s *Service) ListRepositories() (_ []RepoInfo, err error) {
	defer publicInto(&err)
	cfg, err := config.LoadGUI()
	if err != nil {
		return nil, err
	}
	var repos []RepoInfo
	seen := make(map[string]struct{}, len(cfg.RepoHistory))
	for _, path := range cfg.RepoHistory {
		key := repoPathKey(path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		repo, err := validateRepoPath(s.context(), s.git, path)
		if err != nil {
			continue
		}
		info, err := s.repoInfo(repo)
		if err != nil {
			continue
		}
		repos = append(repos, info)
	}
	return repos, nil
}

func (s *Service) RemoveRepository(path string) (err error) {
	defer publicInto(&err)
	s.repoMu.Lock()
	defer s.repoMu.Unlock()
	if err := s.context().Err(); err != nil {
		return err
	}
	cfg, err := config.LoadGUI()
	if err != nil {
		return err
	}
	targetKey := repoPathKey(path)
	filtered := cfg.RepoHistory[:0]
	for _, p := range cfg.RepoHistory {
		if repoPathKey(p) != targetKey {
			filtered = append(filtered, p)
		}
	}
	cfg.RepoHistory = filtered
	if cfg.SelectedRepo != "" && repoPathKey(cfg.SelectedRepo) == targetKey {
		cfg.SelectedRepo = ""
		s.repoPath = ""
	}
	return config.SaveGUI(cfg)
}

func appendUnique(slice []string, val string) []string {
	seen := make(map[string]struct{}, len(slice)+1)
	result := slice[:0]
	for _, existing := range slice {
		key := repoPathKey(existing)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, existing)
	}
	key := repoPathKey(val)
	if _, exists := seen[key]; exists {
		return result
	}
	return append(result, val)
}

// repoPathKey compares two spellings of a repository path. Windows matches
// names in any letter case, also for a folder that no longer exists.
func repoPathKey(path string) string {
	key := fsutil.Canonical(path)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func (s *Service) GetRepoStatus() (_ RepoInfo, err error) {
	defer publicInto(&err)
	s.repoMu.Lock()
	path := s.repoPath
	s.repoMu.Unlock()
	if path == "" {
		return RepoInfo{}, nil
	}
	repo, err := validateRepoPath(s.context(), s.git, path)
	if err != nil {
		return RepoInfo{}, err
	}
	return s.repoInfo(repo)
}

func (s *Service) loadSelectedRepo() {
	cfg, err := config.LoadGUI()
	if err != nil || cfg.SelectedRepo == "" {
		return
	}
	repo, err := validateRepoPath(s.context(), s.git, cfg.SelectedRepo)
	if err != nil {
		return
	}
	s.repoPath = repo.Path
	s.app.SetRepositoryDir(repo.Path)
}

func (s *Service) repoInfo(repo *SelectedRepo) (RepoInfo, error) {
	info := RepoInfo{
		Path:      repo.Path,
		Owner:     repo.Owner,
		Repo:      repo.Repo,
		HasGit:    repo.HasGit,
		HasRemote: repo.HasRemote,
	}
	return withRepoPathResult(s, repo.Path, func() (RepoInfo, error) {
		if cfg, err := config.LoadProjectFrom(repo.Path); err == nil {
			info.StorageConfigured = cfg.Storage.URL != ""
			_, identityErr := s.app.IdentityInfo()
			info.Initialized = identityErr == nil
		}
		return info, nil
	})
}

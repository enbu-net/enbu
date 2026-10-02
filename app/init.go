package app

import (
	"context"
	"fmt"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/oci"
	gh "github.com/enbu-net/enbu/pkg/provider/github"
)

type InitResult struct {
	PublicKey   string `json:"public_key"`
	Username    string `json:"username"`
	Environment string `json:"environment"`
}

func (a *App) InitializeRepository(ctx context.Context) (result *InitResult, err error) {
	defer apperr.NormalizeInto(&err)

	accessToken, username, err := a.TokenProvider.LoadToken()
	if err != nil {
		return nil, err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, err
	}

	id, _, warning, err := a.Identities.Create(owner, repo)
	if err != nil {
		return nil, err
	}
	defer func() { _ = id.Close() }()
	if warning != "" {
		a.emit(warning)
	}
	publicKey := id.Recipient().String()

	ghClient := a.Platform
	if ghClient == nil {
		ghClient = gh.NewClient(accessToken)
	}

	fingerprint := age.Fingerprint(publicKey)
	tag := oci.CleanTag(username + "-" + fingerprint)
	ref := a.registryRef(owner, repo) + ":" + RecipientTagPrefix() + tag
	if err := a.Registry.Push(ctx, ref, "application/vnd.enbu.recipient.age.v1", []byte(publicKey), accessToken, &oci.PushOptions{
		SourceRepo: ghClient.SourceRepoURL(owner, repo),
	}); err != nil {
		return nil, fmt.Errorf("pushing public key to GHCR: %w", err)
	}

	projectCfg, err := a.loadProject()
	if err != nil {
		if !apperr.Is(err, apperr.CodeConfigNotFound) {
			return nil, fmt.Errorf("loading enbu.toml: %w", err)
		}
		projectCfg = config.NewProjectWithEnvironment(DefaultEnvironment)
		if err := a.saveProject(projectCfg); err != nil {
			return nil, fmt.Errorf("creating enbu.toml: %w", err)
		}
	}

	return &InitResult{
		PublicKey:   publicKey,
		Username:    username,
		Environment: projectCfg.CurrentEnvironment(),
	}, nil
}

package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	agecrypto "filippo.io/age"
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

	repoKey := RepoKeystoreKey(owner, repo)
	var publicKey string

	existingPriv, err := a.KeyStore.Load(KeystoreService, repoKey)
	if err == nil && len(existingPriv) > 0 {
		id, err := agecrypto.ParseX25519Identity(string(existingPriv))
		if err != nil {
			return nil, fmt.Errorf("parsing existing private key: %w", err)
		}
		publicKey = id.Recipient().String()
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("loading private key from keystore: %w", err)
	} else {
		kp, err := age.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating age key pair: %w", err)
		}
		publicKey = kp.PublicKey

		if err := a.KeyStore.Store(KeystoreService, repoKey, []byte(kp.Identity.String())); err != nil {
			return nil, fmt.Errorf("storing private key: %w", err)
		}
	}

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

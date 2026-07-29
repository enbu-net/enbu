package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/oci"
)

const (
	KeystoreService    = "enbu"
	DefaultEnvironment = "default"
)

func RepoKeystoreKey(owner, repo string) string {
	return fmt.Sprintf("%s/%s", strings.ToLower(owner), strings.ToLower(repo))
}

func LoadIdentitiesForRepo(ks KeyStore, owner, repo string) ([]*agecrypto.X25519Identity, error) {
	if ks == nil {
		return nil, fmt.Errorf("keystore is not initialized")
	}
	key := RepoKeystoreKey(owner, repo)
	privKeyBytes, err := ks.Load(KeystoreService, key)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, apperr.New(apperr.CodeNotInitialized, "no private key found (run 'enbu init' first)", nil)
		}
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	id, err := agecrypto.ParseX25519Identity(string(privKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return []*agecrypto.X25519Identity{id}, nil
}

func PullAllRecipients(ctx context.Context, reg Registry, ref string, token string) ([]string, error) {
	tags, err := reg.ListTags(ctx, ref, token)
	if err != nil {
		return nil, err
	}

	var publicKeys []string
	for _, tag := range tags {
		if !IsUserRecipientTag(tag) {
			continue
		}
		tagRef := fmt.Sprintf("%s:%s", ref, tag)
		data, err := reg.Pull(ctx, tagRef, token)
		if err != nil {
			return nil, fmt.Errorf("pulling recipient %s: %w", tag, err)
		}
		publicKeys = append(publicKeys, string(data))
	}
	return publicKeys, nil
}

func PullSecretsWithDigest(ctx context.Context, reg Registry, ref, token string, identities ...*agecrypto.X25519Identity) (map[string]string, string, error) {
	digest, err := reg.GetDigest(ctx, ref, token)
	if err != nil {
		return nil, "", err
	}

	ciphertext, err := reg.Pull(ctx, ref, token)
	if err != nil {
		return nil, "", err
	}

	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, "", err
	}

	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		return nil, "", err
	}

	return secrets, digest, nil
}

func SecretsExists(ctx context.Context, reg Registry, ref, token string) bool {
	_, err := reg.GetDigest(ctx, ref, token)
	return err == nil
}

func secretsTag(env string) string {
	if env == "" {
		env = DefaultEnvironment
	}
	return "secrets-" + oci.CleanTag(env)
}

func RecipientTagPrefix() string {
	return "recipient-"
}

func IsUserRecipientTag(tag string) bool {
	if tag == "recipient-github-actions" {
		return false
	}
	return strings.HasPrefix(tag, "recipient-")
}

func IsNotFoundError(err error) bool {
	return apperr.Is(err, apperr.CodeArtifactNotFound)
}

type ResolvedEnvironment struct {
	Name   string
	Output string
}

func ResolveEnvironment(name string) (*ResolvedEnvironment, error) {
	return resolveEnvironment(config.LoadProject, name)
}

func (a *App) resolveEnvironment(name string) (*ResolvedEnvironment, error) {
	return resolveEnvironment(a.loadProject, name)
}

func resolveEnvironment(load func() (*config.ProjectConfig, error), name string) (*ResolvedEnvironment, error) {
	cfg, err := load()
	if err != nil {
		if apperr.Is(err, apperr.CodeConfigNotFound) {
			if name == "" {
				name = DefaultEnvironment
			}
			return &ResolvedEnvironment{
				Name:   name,
				Output: config.DefaultOutput(name),
			}, nil
		}
		return nil, err
	}

	if name == "" {
		name = cfg.CurrentEnvironment()
	}

	if !config.ValidEnvironmentName(name) {
		return nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment %q", name), apperr.Params{"name": name})
	}

	env, err := cfg.Environment(name)
	if err != nil {
		return nil, err
	}
	return &ResolvedEnvironment{
		Name:   name,
		Output: env.Output,
	}, nil
}

func IsNotInitializedError(err error) bool {
	return apperr.Is(err, apperr.CodeConfigNotFound) ||
		apperr.Is(err, apperr.CodeNotInitialized)
}

func snapshotTag(env string) string {
	if env == "" {
		env = DefaultEnvironment
	}
	return fmt.Sprintf("secrets-%s-%d", oci.CleanTag(env), time.Now().UnixMilli())
}

func IsSnapshotTag(env, tag string) bool {
	prefix := "secrets-" + oci.CleanTag(env) + "-"
	if !strings.HasPrefix(tag, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(tag, prefix)
	_, err := strconv.ParseInt(suffix, 10, 64)
	return err == nil
}

func snapshotTimestamp(env, tag string) (time.Time, bool) {
	prefix := "secrets-" + oci.CleanTag(env) + "-"
	suffix := strings.TrimPrefix(tag, prefix)
	ts, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(ts), true
}

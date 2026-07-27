package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/config"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/keystore"
	"github.com/enbu-net/enbu/utils/oci"
)

const (
	KeystoreService    = "enbu"
	DefaultEnvironment = "default"
)

func RepoKeystoreKey(owner, repo string) string {
	return fmt.Sprintf("%s/%s", strings.ToLower(owner), strings.ToLower(repo))
}

func LoadIdentitiesForRepo(ks KeyStore, owner, repo string) ([]agecrypto.Identity, error) {
	if ks == nil {
		return nil, fmt.Errorf("keystore is not initialized")
	}
	key := RepoKeystoreKey(owner, repo)
	privKeyBytes, err := ks.Load(KeystoreService, key)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, fmt.Errorf("no private key found (run 'enbu init' first)")
		}
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	id, err := agecrypto.ParseX25519Identity(string(privKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return []agecrypto.Identity{id}, nil
}

func PullAllRecipients(ctx context.Context, reg Registry, ref string, token string) ([]string, error) {
	tags, err := reg.ListTags(ctx, ref, token)
	if err != nil {
		if IsNotFoundError(err) {
			return []string{}, nil
		}
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
			if IsNotFoundError(err) {
				continue
			}
			return nil, fmt.Errorf("pulling recipient %s: %w", tag, err)
		}
		publicKeys = append(publicKeys, string(data))
	}
	return publicKeys, nil
}

func PullSecretsWithDigest(ctx context.Context, reg Registry, ref, token string, identities ...agecrypto.Identity) (map[string]string, string, error) {
	secrets, digest, _, err := pullSecretsWithDigestAndCiphertext(ctx, reg, ref, token, identities...)
	return secrets, digest, err
}

func pullSecretsWithDigestAndCiphertext(ctx context.Context, reg Registry, ref, token string, identities ...agecrypto.Identity) (map[string]string, string, []byte, error) {
	digest, err := reg.GetDigest(ctx, ref, token)
	if err != nil {
		return nil, "", nil, err
	}

	ciphertext, err := reg.Pull(ctx, ref, token)
	if err != nil {
		return nil, "", nil, err
	}

	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, "", nil, err
	}

	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		return nil, "", nil, err
	}

	return secrets, digest, ciphertext, nil
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
	return oci.IsNotFound(err)
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
		if strings.Contains(err.Error(), "enbu.toml not found") {
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
		return nil, fmt.Errorf("invalid environment %q", name)
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
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "enbu.toml not found") ||
		strings.Contains(s, "no private key found")
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

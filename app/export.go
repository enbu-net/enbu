package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
)

type ExportInput struct {
	Owner       string
	Repository  string
	Environment string
	Output      string
	Secrets     map[string]string
}

type Exporter interface {
	Export(ctx context.Context, input ExportInput) (destination string, err error)
}

type ExportResult struct {
	Destination string
	Count       int
}

type DotenvExporter struct {
	RepositoryDir string
	Writer        io.Writer
}

func (e DotenvExporter) Export(ctx context.Context, input ExportInput) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	dotenv := bundle.ToDotEnv(input.Secrets)
	if e.Writer != nil {
		if _, err := io.Copy(e.Writer, bytes.NewReader(dotenv)); err != nil {
			return "", fmt.Errorf("writing dotenv output: %w", err)
		}
		return "stdout", nil
	}

	outputPath := input.Output
	if e.RepositoryDir != "" && !filepath.IsAbs(outputPath) {
		outputPath = filepath.Join(e.RepositoryDir, outputPath)
	}
	if err := atomicWriteFile(outputPath, dotenv, 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", input.Output, err)
	}
	return input.Output, nil
}

func (a *App) ExportSecrets(ctx context.Context, env string, exporter Exporter) (*ExportResult, error) {
	if exporter == nil {
		return nil, fmt.Errorf("exporter is required")
	}

	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, err
	}

	ref := a.secretsRef(owner, repo, resolved.Name)
	a.emitStepProgress("export", "load", "start")
	ciphertext, err := a.secretCache().Load(ref)
	if err != nil {
		if errors.Is(err, ErrSecretCacheMiss) {
			return nil, fmt.Errorf("no cached secrets for environment %q (run 'enbu pull' first)", resolved.Name)
		}
		return nil, err
	}
	a.emitStepProgress("export", "load", "done")

	secrets := map[string]string{}
	if len(ciphertext) > 0 {
		identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
		if err != nil {
			return nil, err
		}

		a.emitStepProgress("export", "decrypt", "start")
		secrets, err = decryptSecretBundle(ciphertext, identities...)
		if err != nil {
			return nil, fmt.Errorf("decrypting cached secrets: %w", err)
		}
		a.emitStepProgress("export", "decrypt", "done")
	}

	a.emitStepProgress("export", "export", "start")
	destination, err := exporter.Export(ctx, ExportInput{
		Owner:       owner,
		Repository:  repo,
		Environment: resolved.Name,
		Output:      resolved.Output,
		Secrets:     secrets,
	})
	if err != nil {
		return nil, err
	}
	a.emitStepProgress("export", "export", "done")
	a.emit(fmt.Sprintf("Exported %d secrets to %s", len(secrets), destination))
	return &ExportResult{Destination: destination, Count: len(secrets)}, nil
}

func (a *App) ExportSecretsToFile(ctx context.Context, env string) (*ExportResult, error) {
	return a.ExportSecrets(ctx, env, DotenvExporter{RepositoryDir: a.RepositoryDir})
}

func decryptSecretBundle(ciphertext []byte, identities ...agecrypto.Identity) (map[string]string, error) {
	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting secrets: %w", err)
	}
	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parsing secrets: %w", err)
	}
	return secrets, nil
}

func (a *App) cacheAfterRemoteUpdate(ref string, ciphertext []byte) {
	if err := a.secretCache().Store(ref, ciphertext); err != nil {
		a.emit(fmt.Sprintf("Warning: remote secrets were updated, but the local cache could not be updated: %v. Run 'enbu pull' to refresh it.", err))
	}
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".enbu-export-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmpPath, path)
}

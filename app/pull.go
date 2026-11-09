package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/dotenv"
)

type PulledSecrets struct {
	Environment string
	Output      string
	Secrets     map[string]string
}

func (a *App) PullSecretsData(ctx context.Context, env string) (result *PulledSecrets, err error) {
	defer apperr.NormalizeInto(&err)

	return a.pullSecretsData(ctx, env, true)
}

func (a *App) PullSecrets(ctx context.Context, env string) (data []byte, output string, count int, err error) {
	defer apperr.NormalizeInto(&err)

	result, err := a.pullSecretsData(ctx, env, true)
	if err != nil {
		return nil, "", 0, err
	}
	data, err = dotenv.Format(result.Secrets)
	if err != nil {
		return nil, "", 0, err
	}
	return data, result.Output, len(result.Secrets), nil
}

func (a *App) pullSecretsData(ctx context.Context, env string, emitDone bool) (*PulledSecrets, error) {
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	a.emitStepProgress("pull", "pull_secrets", "start")
	a.emitStepProgress("pull", "decrypt", "start")
	read, err := s.readResource(ctx, s.resource(resolved.Name), nil, true)
	if err != nil {
		return nil, fmt.Errorf("pulling secrets: %w", err)
	}
	if err := conflictError(read.conflicts); err != nil {
		return nil, err
	}
	secrets := read.secrets
	if emitDone {
		a.emitStepProgress("pull", "decrypt", "done")
	}
	return &PulledSecrets{Environment: resolved.Name, Output: resolved.Output, Secrets: secrets}, nil
}

func (a *App) PullSecretsToFile(ctx context.Context, env string) (err error) {
	defer apperr.NormalizeInto(&err)
	written, err := a.PullSecretsToFileWith(ctx, env, false)
	if err != nil {
		return err
	}
	for _, message := range written.Messages() {
		a.emit(message)
	}
	return nil
}

// WrittenFile describes what a pull wrote.
type WrittenFile struct {
	Output string   `json:"output"` // the file, as configured for the environment
	Count  int      `json:"count"`  // secrets written
	Kept   []string `json:"kept"`   // variables of the previous file that enbu does not store
	// Removed are variables an earlier pull wrote that the environment no
	// longer has; they are not kept, so a deleted secret leaves the file.
	Removed []string `json:"removed"`
}

// Messages tells the user what the pull kept and removed besides the secrets.
func (w *WrittenFile) Messages() []string {
	var out []string
	if len(w.Kept) > 0 {
		out = append(out, fmt.Sprintf("Kept %d local variable(s) enbu does not store: %s (pull --replace drops them)", len(w.Kept), strings.Join(w.Kept, ", ")))
	}
	if len(w.Removed) > 0 {
		out = append(out, fmt.Sprintf("Removed %d variable(s) no longer in the environment: %s", len(w.Removed), strings.Join(w.Removed, ", ")))
	}
	return out
}

// PullSecretsToFileWith writes the environment's secrets to its output file,
// followed by a marker. Variables below the marker that enbu does not store are
// kept there and reported, unless replace is set; variables above it were
// written by an earlier pull and leave the file once the environment no longer
// has them. A file without a marker was written before enbu wrote one, or by
// hand: its variables that some retained revision of the environment held are
// enbu's own and leave the file too, and the rest are kept. A file that cannot
// be read as dotenv is not overwritten without replace.
func (a *App) PullSecretsToFileWith(ctx context.Context, env string, replace bool) (written *WrittenFile, err error) {
	defer apperr.NormalizeInto(&err)

	result, err := a.pullSecretsData(ctx, env, false)
	if err != nil {
		return nil, err
	}

	outputPath := result.Output
	if a.RepositoryDir != "" && !filepath.IsAbs(result.Output) {
		outputPath = filepath.Join(a.RepositoryDir, result.Output)
	}
	a.emitStepProgress("pull", "write", "start")
	stored := func() (map[string]bool, error) { return a.storedKeys(ctx, result.Environment) }
	data, kept, removed, err := dotenvWithLocal(outputPath, result.Secrets, replace, stored)
	if err != nil {
		return nil, err
	}
	// Optional history failures may preserve local variables, but cancellation
	// ends this request before any local output is replaced (including --replace).
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := writePrivateOutput(ctx, outputPath, data); err != nil {
		return nil, fmt.Errorf("writing %s: %w", result.Output, err)
	}

	a.emitStepProgress("pull", "write", "done")
	a.emit(fmt.Sprintf("Written %s (%d secrets)", result.Output, len(result.Secrets)))
	return &WrittenFile{Output: result.Output, Count: len(result.Secrets), Kept: kept, Removed: removed}, nil
}

// storedKeys returns every key that a retained revision of env held, as far as
// this device can decrypt. It tells enbu's own variables in a file without a
// marker apart from a person's: a key the environment once stored and no
// longer does was deleted from enbu.
func (a *App) storedKeys(ctx context.Context, env string) (map[string]bool, error) {
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	resource := s.resource(resolved.Name)
	sv, err := s.loadResource(ctx, resource)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	history := historyStates(sv, s.trustedHeads(sv))
	// Decryption can fetch a blob: map order must not decide external effects.
	for _, revision := range slices.Sorted(maps.Keys(history)) {
		st := history[revision]
		secrets, err := s.decrypt(ctx, st)
		var noMatch *agecrypto.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for k := range secrets {
			keys[k] = true
		}
	}
	return keys, nil
}

// keptMarker separates the secrets a pull writes from the local variables it
// keeps. Every pull writes it, so the next one can tell the two apart.
const keptMarker = "# Local variables below are kept by enbu pull; enbu does not store them (pull --replace drops them):"

// dotenvWithLocal renders secrets as dotenv, then the marker and the local
// variables of the file at path that are not in secrets, so a pull does not
// throw away what a person put there by hand. Variables above the marker of
// an earlier pull are enbu's own: those not in secrets are removed. In a file
// without a marker, everStored names the keys enbu ever held; those are
// removed too. It is called only when the file has variables enbu does not
// hold now, and if it fails those variables are kept.
// With replace the file's content is ignored.
func dotenvWithLocal(path string, secrets map[string]string, replace bool, everStored func() (map[string]bool, error)) (data []byte, kept, removed []string, err error) {
	data, err = dotenv.Format(secrets)
	if err != nil {
		return nil, nil, nil, err
	}
	data = append(data, '\n')
	data = append(data, keptMarker...)
	data = append(data, '\n')
	if replace {
		return data, nil, nil, nil
	}
	existing, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return data, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}
	pulled, local, marked := splitAtMarker(existing)
	unreadable := func(err error) error {
		name := filepath.Base(path)
		return apperr.Wrap(apperr.CodeOutputUnreadable,
			fmt.Sprintf("%s exists but is not a dotenv file enbu can read; pass --replace to overwrite it", name), err, apperr.Params{"file": name})
	}
	previous, err := dotenv.Parse(pulled)
	if err != nil {
		return nil, nil, nil, unreadable(err)
	}
	vars, err := dotenv.Parse(local)
	if err != nil {
		return nil, nil, nil, unreadable(err)
	}
	if !marked {
		var unknown bool
		for key := range vars {
			if _, ok := secrets[key]; !ok {
				unknown = true
				break
			}
		}
		if unknown {
			// Without the history nothing can be told apart, and keeping a
			// variable is the safe side: it is reported as kept, not lost.
			ever, err := everStored()
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, nil, nil, err
				}
				ever = nil
			}
			if previous == nil {
				previous = map[string]string{}
			}
			for key, value := range vars {
				if _, now := secrets[key]; !now && ever[key] {
					previous[key] = value
					delete(vars, key)
				}
			}
		}
	}
	for key := range previous {
		if _, stored := secrets[key]; !stored {
			removed = append(removed, key)
		}
	}
	sort.Strings(removed)
	keep := map[string]string{}
	for key, value := range vars {
		if _, stored := secrets[key]; !stored {
			keep[key] = value
			kept = append(kept, key)
		}
	}
	if len(kept) == 0 {
		return data, nil, removed, nil
	}
	sort.Strings(kept)
	extra, err := dotenv.Format(keep)
	if err != nil {
		return nil, nil, nil, err
	}
	return append(data, extra...), kept, removed, nil
}

// splitAtMarker returns what an earlier pull wrote above its marker and the
// local part below it. A file without a marker is all local.
func splitAtMarker(file []byte) (pulled, local []byte, marked bool) {
	lines := strings.SplitAfter(string(file), "\n")
	for i, line := range lines {
		if strings.TrimRight(line, "\r\n") == keptMarker {
			return []byte(strings.Join(lines[:i], "")), []byte(strings.Join(lines[i+1:], "")), true
		}
	}
	return nil, file, false
}

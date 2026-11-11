package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/merge"
	"github.com/opencontainers/go-digest"
)

// SecretConflict is a key that concurrent edits changed differently. Nothing
// is chosen for the user: they pick one candidate, or give a new value.
type SecretConflict struct {
	Key        string              `json:"key"`
	Candidates []ConflictCandidate `json:"candidates"`
}

type ConflictCandidate struct {
	Value   string `json:"value"`
	Deleted bool   `json:"deleted"`
}

// ConflictSet is what a person looked at when deciding: the conflicted keys and
// the heads they were computed from. ResolveSecrets must be given the same
// Heads, so a value that appeared since is shown to the person rather than
// swept away by a choice made without seeing it.
type ConflictSet struct {
	Environment string `json:"environment"`
	// ID is a short name for Heads, for a person to repeat back when deciding.
	ID        string           `json:"id"`
	Heads     []string         `json:"heads"`
	Conflicts []SecretConflict `json:"conflicts"`
}

// ListConflicts returns the keys of env that are waiting for a decision.
func (a *App) ListConflicts(ctx context.Context, env string) (set *ConflictSet, err error) {
	defer apperr.NormalizeInto(&err)
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	read, err := s.readResource(ctx, s.resource(resolved.Name), nil, true)
	if IsNotFoundError(err) {
		return &ConflictSet{Environment: resolved.Name, Heads: []string{}, Conflicts: []SecretConflict{}}, nil
	}
	if err != nil {
		return nil, err
	}
	heads := headNames(read.parents())
	return &ConflictSet{Environment: resolved.Name, ID: conflictID(heads), Heads: heads, Conflicts: toSecretConflicts(read.conflicts)}, nil
}

func conflictID(heads []string) string {
	sum := sha256.Sum256([]byte(strings.Join(heads, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}

func headNames(heads []digest.Digest) []string {
	out := make([]string, len(heads))
	for i, h := range heads {
		out[i] = h.Encoded()
	}
	slices.Sort(out)
	return out
}

// SecretChoice settles one conflicted key with a value, or by deleting it.
type SecretChoice struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Delete bool   `json:"delete"`
}

// ResolveSecrets settles every conflicted key of env and publishes the result
// as a revision that merges all heads. Every conflict must be settled at once:
// a merge revision holds one value per key. seen is ConflictSet.Heads from the
// listing the choices were made from; if the heads are different now, nothing
// is published and the person looks again.
func (a *App) ResolveSecrets(ctx context.Context, env string, seen []string, choices []SecretChoice) (err error) {
	defer apperr.NormalizeInto(&err)
	picked := make(map[string]merge.Choice, len(choices))
	for _, c := range choices {
		if _, dup := picked[c.Key]; dup {
			return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("%s was decided twice", c.Key), apperr.Params{"key": c.Key})
		}
		picked[c.Key] = merge.Choice{Value: c.Value, Delete: c.Delete}
	}
	if len(seen) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "resolving needs the heads of the conflicts that were listed", nil)
	}
	slices.Sort(seen)
	return a.changeSecretWith(ctx, env, "resolve", picked, seen, func(map[string]string) error { return nil })
}

func toSecretConflicts(cs []merge.Conflict) []SecretConflict {
	out := make([]SecretConflict, len(cs))
	for i, c := range cs {
		out[i] = SecretConflict{Key: c.Key}
		for _, v := range c.Candidates {
			out[i].Candidates = append(out[i].Candidates, ConflictCandidate{Value: v.Text, Deleted: v.Deleted})
		}
	}
	return out
}

func conflictError(cs []merge.Conflict) error {
	if len(cs) == 0 {
		return nil
	}
	keys := make([]string, len(cs))
	for i, c := range cs {
		keys[i] = c.Key
	}
	return apperr.New(apperr.CodeSecretConflict, fmt.Sprintf("concurrent edits changed %s differently; choose a value with 'enbu resolve'", strings.Join(keys, ", ")),
		apperr.Params{"keys": strings.Join(keys, ", ")})
}

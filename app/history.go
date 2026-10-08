package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

type HistoryEntry struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Tag       string    `json:"tag"`
}

type Diff struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
}

// ListHistory lists the retained revisions of env that changed its secrets,
// oldest first. It is a change log bounded by what storage still holds, not an
// audit log. Revisions that only re-encrypted the same content are left out, as
// are revisions this device cannot decrypt (written before it was a member).
func (a *App) ListHistory(ctx context.Context, env string) (history []HistoryEntry, err error) {
	defer apperr.NormalizeInto(&err)
	entries, _, err := a.history(ctx, env)
	return entries, err
}

type historyRevision struct {
	state   *wsp.VerifiedState
	secrets map[string]string
}

func (a *App) history(ctx context.Context, env string) ([]HistoryEntry, map[digest.Digest]historyRevision, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, nil, err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	sv, err := s.loadResource(ctx, resolved.Name)
	if IsNotFoundError(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	revisions := map[digest.Digest]historyRevision{}
	for d, st := range sv.States {
		secrets, err := s.decrypt(ctx, st)
		var noMatch *agecrypto.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		revisions[d] = historyRevision{state: st, secrets: secrets}
	}
	byDigest := map[digest.Digest]HistoryEntry{}
	for d, r := range revisions {
		if repeatsAParent(r, revisions) {
			continue
		}
		byDigest[d] = HistoryEntry{Timestamp: time.Unix(r.state.CreatedAt, 0).UTC(), Tag: d.Encoded()}
	}
	var history []HistoryEntry
	for _, d := range chronological(revisions) {
		if e, ok := byDigest[d]; ok {
			history = append(history, e)
		}
	}
	for i := range history {
		history[i].Index = i + 1
	}
	return history, revisions, nil
}

// chronological orders revisions so that every revision comes after its
// parents. Between revisions that do not depend on each other it follows the
// recorded time, then the digest, so the order is the same on every device.
// The clock only breaks ties; it can never put a child before its parent.
func chronological(revisions map[digest.Digest]historyRevision) []digest.Digest {
	waiting := map[digest.Digest]int{}
	children := map[digest.Digest][]digest.Digest{}
	var ready []digest.Digest
	for d, r := range revisions {
		for _, p := range r.state.Parents {
			if _, ok := revisions[p]; ok {
				waiting[d]++
				children[p] = append(children[p], d)
			}
		}
		if waiting[d] == 0 {
			ready = append(ready, d)
		}
	}
	less := func(a, b digest.Digest) bool {
		ta, tb := revisions[a].state.CreatedAt, revisions[b].state.CreatedAt
		if ta != tb {
			return ta < tb
		}
		return a < b
	}
	var order []digest.Digest
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
		d := ready[0]
		ready = ready[1:]
		order = append(order, d)
		for _, c := range children[d] {
			if waiting[c]--; waiting[c] == 0 {
				ready = append(ready, c)
			}
		}
	}
	return order
}

func repeatsAParent(r historyRevision, all map[digest.Digest]historyRevision) bool {
	for _, p := range r.state.Parents {
		if parent, ok := all[p]; ok && maps.Equal(parent.secrets, r.secrets) {
			return true
		}
	}
	return false
}

func (a *App) historyEntry(ctx context.Context, env string, idx int) (map[string]string, error) {
	entries, revisions, err := a.history(ctx, env)
	if err != nil {
		return nil, err
	}
	if idx < 1 || idx > len(entries) {
		return nil, invalidHistoryIndexError(idx, len(entries))
	}
	return revisions[digest.NewDigestFromEncoded(digest.SHA256, entries[idx-1].Tag)].secrets, nil
}

func (a *App) DiffHistory(ctx context.Context, env string, fromIdx, toIdx int) (diff *Diff, err error) {
	defer apperr.NormalizeInto(&err)
	entries, revisions, err := a.history(ctx, env)
	if err != nil {
		return nil, err
	}
	for _, idx := range []int{fromIdx, toIdx} {
		if idx < 1 || idx > len(entries) {
			return nil, invalidHistoryIndexError(idx, len(entries))
		}
	}
	at := func(idx int) map[string]string {
		return revisions[digest.NewDigestFromEncoded(digest.SHA256, entries[idx-1].Tag)].secrets
	}
	return diffSecrets(at(fromIdx), at(toIdx)), nil
}

// RestoreHistory publishes the content of a retained revision as a new revision.
func (a *App) RestoreHistory(ctx context.Context, env string, idx int) (err error) {
	defer apperr.NormalizeInto(&err)
	snapshot, err := a.historyEntry(ctx, env, idx)
	if err != nil {
		return err
	}
	return a.changeSecret(ctx, env, "restore", func(current map[string]string) error {
		clear(current)
		for k, v := range snapshot {
			current[k] = v
		}
		return nil
	})
}

func invalidHistoryIndexError(index, count int) error {
	return apperr.New(
		apperr.CodeInvalidArgument,
		fmt.Sprintf("version %d not found (history has %d entries)", index, count),
		apperr.Params{"index": fmt.Sprint(index)},
	)
}

func diffSecrets(from, to map[string]string) *Diff {
	d := &Diff{}
	for k := range to {
		if _, ok := from[k]; !ok {
			d.Added = append(d.Added, k)
		} else if from[k] != to[k] {
			d.Modified = append(d.Modified, k)
		}
	}
	for k := range from {
		if _, ok := to[k]; !ok {
			d.Removed = append(d.Removed, k)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	return d
}

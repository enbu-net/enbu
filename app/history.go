package app

import (
	"context"
	"fmt"
	"github.com/enbu-net/enbu/pkg/apperr"
	"sort"
	"time"
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

func (a *App) ListHistory(ctx context.Context, env string) (history []HistoryEntry, err error) {
	defer apperr.NormalizeInto(&err)
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	store, err := a.workspaceStorage(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := store.Refs.List(ctx, snapshotPrefix(resolved.Name))
	if err != nil {
		return nil, storageError(err)
	}
	for _, key := range keys {
		ts, ok := snapshotTimestamp(resolved.Name, key)
		if ok {
			history = append(history, HistoryEntry{Timestamp: ts, Tag: key})
		}
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Timestamp.Equal(history[j].Timestamp) {
			return history[i].Tag < history[j].Tag
		}
		return history[i].Timestamp.Before(history[j].Timestamp)
	})
	for i := range history {
		history[i].Index = i + 1
	}
	return history, nil
}
func (a *App) DiffHistory(ctx context.Context, env string, fromIdx, toIdx int) (diff *Diff, err error) {
	defer apperr.NormalizeInto(&err)
	entries, err := a.ListHistory(ctx, env)
	if err != nil {
		return nil, err
	}
	if fromIdx < 1 || fromIdx > len(entries) {
		return nil, invalidHistoryIndexError(fromIdx, len(entries))
	}
	if toIdx < 1 || toIdx > len(entries) {
		return nil, invalidHistoryIndexError(toIdx, len(entries))
	}
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	from, err := s.readState(ctx, entries[fromIdx-1].Tag, resolved.Name, false)
	if err != nil {
		return nil, err
	}
	to, err := s.readState(ctx, entries[toIdx-1].Tag, resolved.Name, false)
	if err != nil {
		return nil, err
	}
	return diffSecrets(from.secrets, to.secrets), nil
}
func (a *App) RestoreHistory(ctx context.Context, env string, idx int) (err error) {
	defer apperr.NormalizeInto(&err)
	entries, err := a.ListHistory(ctx, env)
	if err != nil {
		return err
	}
	if idx < 1 || idx > len(entries) {
		return invalidHistoryIndexError(idx, len(entries))
	}
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	snapshot, err := s.readState(ctx, entries[idx-1].Tag, resolved.Name, false)
	if err != nil {
		return err
	}
	return a.changeSecret(ctx, env, "restore", func(current map[string]string) error {
		clear(current)
		for k, v := range snapshot.secrets {
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

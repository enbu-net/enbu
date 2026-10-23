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
//
// Telling those apart needs each revision decrypted once. What was learned is
// kept in a local index (two flags per revision, never content), so later
// listings decrypt only revisions that are new since.
func (a *App) ListHistory(ctx context.Context, env string) (history []HistoryEntry, err error) {
	defer apperr.NormalizeInto(&err)
	h, err := a.openHistory(ctx, env)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return h.entries, nil
}

// historyView is the history of one environment with its session still open,
// so the content of an entry is decrypted only when it is asked for.
type historyView struct {
	s       *session
	entries []HistoryEntry
	states  map[digest.Digest]*wsp.VerifiedState
	plain   map[digest.Digest]map[string]string // decrypted during this call only
}

func (h *historyView) Close() {
	if h.s != nil {
		h.s.Close()
	}
}

// at returns the secrets of a listed entry, counting from 1.
func (h *historyView) at(ctx context.Context, idx int) (map[string]string, error) {
	if idx < 1 || idx > len(h.entries) {
		return nil, invalidHistoryIndexError(idx, len(h.entries))
	}
	d := digest.NewDigestFromEncoded(digest.SHA256, h.entries[idx-1].Tag)
	return h.secrets(ctx, d)
}

func (h *historyView) secrets(ctx context.Context, d digest.Digest) (map[string]string, error) {
	if m, ok := h.plain[d]; ok {
		return m, nil
	}
	m, err := h.s.decrypt(ctx, h.states[d])
	if err != nil {
		return nil, err
	}
	h.plain[d] = m
	return m, nil
}

func (a *App) openHistory(ctx context.Context, env string) (*historyView, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	h := &historyView{s: s, plain: map[digest.Digest]map[string]string{}}
	if err := h.load(ctx, s.resource(resolved.Name)); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *historyView) load(ctx context.Context, resource string) error {
	s := h.s
	sv, err := s.loadResource(ctx, resource)
	if IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return err
	}
	accepted, err := s.cps.State(resource)
	if err != nil {
		return err
	}
	h.states = historyStates(sv, s.trustedHeads(sv, accepted))
	index := s.app.openHistoryIndex(s, resource)
	known := index.load()
	// unreadable notes revisions found unreadable in this call before their
	// flags are complete; known holds only complete flags.
	unreadable := map[digest.Digest]bool{}
	readable := func(d digest.Digest) (bool, error) {
		if f, ok := known[d]; ok {
			return f.Readable, nil
		}
		if unreadable[d] {
			return false, nil
		}
		_, err := h.secrets(ctx, d)
		var noMatch *agecrypto.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			unreadable[d] = true
			return false, nil
		}
		return err == nil, err
	}
	revisions := map[digest.Digest]*wsp.VerifiedState{}
	var listed []digest.Digest
	for d := range h.states {
		f, ok := known[d]
		if !ok {
			r, err := readable(d)
			if err != nil {
				return err
			}
			f = historyFlags{}
			if r {
				if f, err = h.flags(ctx, d, readable); err != nil {
					return err
				}
			}
			known[d] = f
		}
		if !f.Readable {
			continue
		}
		revisions[d] = h.states[d]
		if !f.Repeats {
			listed = append(listed, d)
		}
	}
	index.save(known, h.states)
	keep := map[digest.Digest]bool{}
	for _, d := range listed {
		keep[d] = true
	}
	for _, d := range chronological(revisions) {
		if keep[d] {
			st := h.states[d]
			h.entries = append(h.entries, HistoryEntry{Index: len(h.entries) + 1, Timestamp: time.Unix(st.CreatedAt, 0).UTC(), Tag: d.Encoded()})
		}
	}
	return nil
}

// flags works out whether a readable revision only repeats the content of one
// of its parents, as a re-encryption does.
func (h *historyView) flags(ctx context.Context, d digest.Digest, readable func(digest.Digest) (bool, error)) (historyFlags, error) {
	f := historyFlags{Readable: true}
	mine, err := h.secrets(ctx, d)
	if err != nil {
		return f, err
	}
	for _, p := range h.states[d].Parents {
		if _, ok := h.states[p]; !ok {
			continue
		}
		ok, err := readable(p)
		if err != nil {
			return f, err
		}
		if !ok {
			continue
		}
		parent, err := h.secrets(ctx, p)
		if err != nil {
			return f, err
		}
		if maps.Equal(parent, mine) {
			f.Repeats = true
			break
		}
	}
	return f, nil
}

// historyStates keeps the revisions that lead to the current content: the heads
// a read trusts and their ancestors. Any member can sign a revision that names
// an older Control, so a removed member who can still write to storage can
// publish one; reading sets it aside as a head, and history must too, or
// restoring it would publish its content under the restorer's signature.
func historyStates(sv *wsp.StateView, heads []*wsp.VerifiedState) map[digest.Digest]*wsp.VerifiedState {
	out := map[digest.Digest]*wsp.VerifiedState{}
	for _, h := range heads {
		for d := range sv.Graph.Ancestors(h.Digest) {
			if st, ok := sv.States[d]; ok {
				out[d] = st
			}
		}
	}
	return out
}

// chronological orders revisions so that every revision comes after its
// parents. Between revisions that do not depend on each other it follows the
// recorded time, then the digest, so the order is the same on every device.
// The clock only breaks ties; it can never put a child before its parent.
func chronological(revisions map[digest.Digest]*wsp.VerifiedState) []digest.Digest {
	waiting := map[digest.Digest]int{}
	children := map[digest.Digest][]digest.Digest{}
	var ready []digest.Digest
	for d, r := range revisions {
		for _, p := range r.Parents {
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
		ta, tb := revisions[a].CreatedAt, revisions[b].CreatedAt
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

func (a *App) DiffHistory(ctx context.Context, env string, fromIdx, toIdx int) (diff *Diff, err error) {
	defer apperr.NormalizeInto(&err)
	h, err := a.openHistory(ctx, env)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	for _, idx := range []int{fromIdx, toIdx} {
		if idx < 1 || idx > len(h.entries) {
			return nil, invalidHistoryIndexError(idx, len(h.entries))
		}
	}
	from, err := h.at(ctx, fromIdx)
	if err != nil {
		return nil, err
	}
	to, err := h.at(ctx, toIdx)
	if err != nil {
		return nil, err
	}
	return diffSecrets(from, to), nil
}

// RestoreHistory publishes the content of a retained revision as a new revision.
func (a *App) RestoreHistory(ctx context.Context, env string, idx int) (err error) {
	defer apperr.NormalizeInto(&err)
	h, err := a.openHistory(ctx, env)
	if err != nil {
		return err
	}
	snapshot, err := h.at(ctx, idx)
	h.Close()
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

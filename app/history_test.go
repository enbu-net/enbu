package app

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/opencontainers/go-digest"
)

func TestListHistory_Empty(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)

	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty history, got %d entries", len(entries))
	}
}

func TestListHistory_AfterAddSecret(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(entries))
	}
	if entries[0].Index != 1 {
		t.Fatalf("expected Index=1, got %d", entries[0].Index)
	}
	if entries[0].Timestamp.IsZero() {
		t.Fatal("expected non-zero timestamp")
	}
}

// Fixed revisions exercise ordering and all diff categories without waiting for
// the wall clock or repeating the add/edit/delete command tests.
func TestDiffHistory(t *testing.T) {
	a, revs := newHistoryTestApp(t)
	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	wantEntries := []HistoryEntry{
		{Index: 1, Timestamp: time.Unix(1000, 0).UTC(), Tag: revs[0].Encoded()},
		{Index: 2, Timestamp: time.Unix(2000, 0).UTC(), Tag: revs[1].Encoded()},
	}
	if !reflect.DeepEqual(entries, wantEntries) {
		t.Fatalf("history = %#v, want %#v", entries, wantEntries)
	}
	for _, tc := range []struct {
		name     string
		from, to int
		want     *Diff
	}{
		{"forward", 1, 2, &Diff{Added: []string{"A_NEW", "Z_NEW"}, Removed: []string{"A_OLD", "Z_OLD"}, Modified: []string{"A_CHANGED", "Z_CHANGED"}}},
		{"reverse", 2, 1, &Diff{Added: []string{"A_OLD", "Z_OLD"}, Removed: []string{"A_NEW", "Z_NEW"}, Modified: []string{"A_CHANGED", "Z_CHANGED"}}},
		{"same version", 1, 1, &Diff{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.DiffHistory(context.Background(), "default", tc.from, tc.to)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("diff = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// newHistoryTestApp publishes two chained revisions with fixed times, and some
// revisions that must not show up: another environment's, and a re-encryption
// of the same content.
func newHistoryTestApp(t *testing.T) (*App, []digest.Digest) {
	t.Helper()
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ws := mustWorkspace(t, a)
	publish := func(env string, at int64, secrets map[string]string, parents ...digest.Digest) digest.Digest {
		ciphertext, err := age.EncryptForPublicKeys(encodeSecrets(secrets), []string{kp.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		return publishRevisionAt(t, a.Storage, a, ws, s.resource(env), s.head.Digest, ciphertext, at, parents...)
	}
	old := publish("default", 1000, map[string]string{"UNCHANGED": "same", "A_CHANGED": "old", "Z_CHANGED": "old", "A_OLD": "removed", "Z_OLD": "removed"})
	next := publish("default", 2000, map[string]string{"UNCHANGED": "same", "A_CHANGED": "new", "Z_CHANGED": "new", "A_NEW": "added", "Z_NEW": "added"}, old)
	publish("default", 3000, map[string]string{"UNCHANGED": "same", "A_CHANGED": "new", "Z_CHANGED": "new", "A_NEW": "added", "Z_NEW": "added"}, next) // re-encryption only
	publish("production", 4000, map[string]string{"OTHER_ENV": "value"})
	return a, []digest.Digest{old, next}
}

func TestRestoreHistoryRevisionUsesDisplayedDigestAfterCompaction(t *testing.T) {
	a := newAlice(t)
	for _, value := range []string{"v2", "v3"} {
		if err := a.EditSecret(bg, "default", "KEY", value); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	target := EnvironmentTarget{WorkspaceID: cfg.WorkspaceID, Environment: "default",
		Incarnation: cfg.Environments["default"].Incarnation}
	before, err := a.ListHistory(bg, "default")
	if err != nil || len(before) != 3 {
		t.Fatalf("original history: %v %v", before, err)
	}
	if _, err := a.CompactHistory(bg, "default", 2); err != nil {
		t.Fatal(err)
	}
	after, err := a.ListHistory(bg, "default")
	if err != nil || len(after) != 2 || after[0].Tag != before[1].Tag {
		t.Fatalf("history after compaction: %v %v", after, err)
	}
	if err := a.RestoreHistoryRevision(bg, target, before[0].Tag); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("removed revision: %v", err)
	}
	wrong := target
	wrong.Incarnation = "replaced"
	if err := a.RestoreHistoryRevision(bg, wrong, before[1].Tag); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("replacement environment: %v", err)
	}
	if err := a.RestoreHistoryRevision(bg, target, before[1].Tag); err != nil {
		t.Fatal(err)
	}
	if got := mustSecrets(t, a, "default")["KEY"]; got != "v2" {
		t.Fatalf("restored value = %q", got)
	}
}

func TestRestoreHistory(t *testing.T) {
	a, _ := newHistoryTestApp(t)
	if err := a.RestoreHistory(context.Background(), "default", 1); err != nil {
		t.Fatal(err)
	}
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"UNCHANGED": "same", "A_CHANGED": "old", "Z_CHANGED": "old", "A_OLD": "removed", "Z_OLD": "removed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restored = %#v, want %#v", got, want)
	}
	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil || len(entries) != 3 {
		t.Fatalf("history after restore = %#v, %v", entries, err)
	}
}

func TestHistoryRejectsInvalidIndices(t *testing.T) {
	a, _ := newHistoryTestApp(t)
	for _, index := range []int{-1, 0, 3} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"diff from", func() error { _, err := a.DiffHistory(context.Background(), "default", index, 1); return err }},
				{"diff to", func() error { _, err := a.DiffHistory(context.Background(), "default", 1, index); return err }},
				{"restore", func() error { return a.RestoreHistory(context.Background(), "default", index) }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); !apperr.Is(err, apperr.CodeInvalidArgument) {
						t.Fatalf("error = %v, want invalid_argument", err)
					}
				})
			}
		})
	}
}

package app

import (
	"context"
	"testing"
	"time"

	"github.com/enbu-net/enbu/apperr"
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

func TestListHistory_OrderedByTimestamp(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	// sleep 1 second to ensure different timestamps
	time.Sleep(1100 * time.Millisecond)

	if err := a.EditSecret(context.Background(), "default", "FOO", "baz"); err != nil {
		t.Fatalf("EditSecret: %v", err)
	}

	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(entries))
	}
	if !entries[0].Timestamp.Before(entries[1].Timestamp) {
		t.Fatal("expected entries ordered oldest-first")
	}
	if entries[0].Index != 1 || entries[1].Index != 2 {
		t.Fatalf("unexpected indices: %d, %d", entries[0].Index, entries[1].Index)
	}
}

func TestDiffHistory_ModifiedKey(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	time.Sleep(1100 * time.Millisecond)

	if err := a.EditSecret(context.Background(), "default", "FOO", "baz"); err != nil {
		t.Fatalf("EditSecret: %v", err)
	}

	diff, err := a.DiffHistory(context.Background(), "default", 1, 2)
	if err != nil {
		t.Fatalf("DiffHistory: %v", err)
	}
	if len(diff.Modified) != 1 || diff.Modified[0] != "FOO" {
		t.Fatalf("expected Modified=[FOO], got Modified=%v Added=%v Removed=%v", diff.Modified, diff.Added, diff.Removed)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 {
		t.Fatalf("unexpected Added=%v Removed=%v", diff.Added, diff.Removed)
	}
}

func TestDiffHistory_AddedAndRemovedKeys(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	time.Sleep(1100 * time.Millisecond)

	if err := a.AddSecret(context.Background(), "default", "NEW_KEY", "val"); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	if err := a.DeleteSecret(context.Background(), "default", "FOO"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListHistory: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(entries))
	}

	diff, err := a.DiffHistory(context.Background(), "default", 1, 3)
	if err != nil {
		t.Fatalf("DiffHistory: %v", err)
	}
	if len(diff.Added) != 1 || diff.Added[0] != "NEW_KEY" {
		t.Fatalf("expected Added=[NEW_KEY], got %v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0] != "FOO" {
		t.Fatalf("expected Removed=[FOO], got %v", diff.Removed)
	}
}

func TestRestoreHistory(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "original"})

	time.Sleep(1100 * time.Millisecond)

	if err := a.EditSecret(context.Background(), "default", "FOO", "updated"); err != nil {
		t.Fatalf("EditSecret: %v", err)
	}

	// verify current value is "updated"
	secrets, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if secrets["FOO"] != "updated" {
		t.Fatalf("expected FOO=updated, got %q", secrets["FOO"])
	}

	// restore to version 1
	if err := a.RestoreHistory(context.Background(), "default", 1); err != nil {
		t.Fatalf("RestoreHistory: %v", err)
	}

	// verify restored value
	secrets, err = a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecrets after restore: %v", err)
	}
	if secrets["FOO"] != "original" {
		t.Fatalf("expected FOO=original after restore, got %q", secrets["FOO"])
	}
}

func TestDiffHistory_InvalidIndex(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	_, err := a.DiffHistory(context.Background(), "default", 1, 99)
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("DiffHistory error = %v, want %q", err, apperr.CodeInvalidArgument)
	}
}

func TestRestoreHistory_InvalidIndex(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar"})

	err := a.RestoreHistory(context.Background(), "default", 99)
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("RestoreHistory error = %v, want %q", err, apperr.CodeInvalidArgument)
	}
}

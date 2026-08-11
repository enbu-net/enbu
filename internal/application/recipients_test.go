package app

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestListRecipients(t *testing.T) {
	reg := newMemRegistry()
	a := &App{
		Registry:      reg,
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: "alice", repo: "myrepo"},
	}

	ref := "ghcr.io/alice/myrepo-enbu"
	pubKey1 := "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysqqp"
	pubKey2 := "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysqqa"
	tag1 := "recipient-alice-aabbccdd"
	tag2 := "recipient-bob-11223344"
	if err := reg.Push(context.Background(), ref+":"+tag1, "application/vnd.enbu.recipient.age.v1", []byte(pubKey1), "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := reg.Push(context.Background(), ref+":"+tag2, "application/vnd.enbu.recipient.age.v1", []byte(pubKey2), "tok", nil); err != nil {
		t.Fatal(err)
	}

	recipients, err := a.ListRecipients(context.Background())
	if err != nil {
		t.Fatalf("ListRecipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("got %d recipients, want 2", len(recipients))
	}

	var aliceFound bool
	for _, r := range recipients {
		if r.Username == "alice" {
			aliceFound = true
			if r.Fingerprint != "aabbccdd" {
				t.Fatalf("alice fingerprint = %q, want aabbccdd", r.Fingerprint)
			}
			if !strings.Contains(r.PublicKey, "age1") {
				t.Fatalf("alice public key looks wrong: %q", r.PublicKey)
			}
		}
	}
	if !aliceFound {
		t.Fatal("alice not found in recipients")
	}
}

type concurrentRegistry struct {
	*memRegistry
	active int32
	max    int32
}

func (r *concurrentRegistry) Pull(ctx context.Context, ref, token string) ([]byte, error) {
	active := atomic.AddInt32(&r.active, 1)
	defer atomic.AddInt32(&r.active, -1)
	for {
		max := atomic.LoadInt32(&r.max)
		if active <= max || atomic.CompareAndSwapInt32(&r.max, max, active) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	return r.memRegistry.Pull(ctx, ref, token)
}

func TestListRecipientsPullsWithBoundedConcurrency(t *testing.T) {
	base := newMemRegistry()
	reg := &concurrentRegistry{memRegistry: base}
	a := &App{
		Registry:      reg,
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: "alice", repo: "myrepo"},
	}

	ref := "ghcr.io/alice/myrepo-enbu"
	for i := range 12 {
		tag := fmt.Sprintf("recipient-user-%02d-fingerprint", i)
		if err := reg.Push(context.Background(), ref+":"+tag, "application/vnd.enbu.recipient.age.v1", []byte("age1key"), "tok", nil); err != nil {
			t.Fatal(err)
		}
	}

	recipients, err := a.ListRecipients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 12 {
		t.Fatalf("got %d recipients, want 12", len(recipients))
	}
	if reg.max <= 1 || reg.max > 8 {
		t.Fatalf("max concurrent pulls = %d, want 2..8", reg.max)
	}
}

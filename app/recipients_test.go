package app

import (
	"context"
	"github.com/enbu-net/enbu/pkg/storage"
	"sync/atomic"
	"testing"
	"time"
)

func TestListRecipients(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	second := mustKeyPair(t)
	if err := a.Storage.Put(context.Background(), RecipientKey(second.PublicKey), storage.Object{MediaType: recipientMediaType, Data: []byte(second.PublicKey)}, ""); err != nil {
		t.Fatal(err)
	}
	recipients, err := a.ListRecipients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 {
		t.Fatalf("recipients=%v", recipients)
	}
	for _, r := range recipients {
		if RecipientTagPrefix()+r.Fingerprint != RecipientKey(r.PublicKey) {
			t.Fatal("fingerprint mismatch")
		}
	}
}

type concurrentRegistry struct {
	storage.Storage
	active atomic.Int32
	max    atomic.Int32
}

func (r *concurrentRegistry) Get(ctx context.Context, key string) (storage.Object, storage.Version, error) {
	active := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		max := r.max.Load()
		if active <= max || r.max.CompareAndSwap(max, active) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	return r.Storage.Get(ctx, key)
}
func TestListRecipientsPullsWithBoundedConcurrency(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	for range 11 {
		kp := mustKeyPair(t)
		if err := a.Storage.Put(context.Background(), RecipientKey(kp.PublicKey), storage.Object{MediaType: recipientMediaType, Data: []byte(kp.PublicKey)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	reg := &concurrentRegistry{Storage: a.Storage}
	a.Storage = reg
	recipients, err := a.ListRecipients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 12 || reg.max.Load() <= 1 || reg.max.Load() > 8 {
		t.Fatalf("recipients=%d max=%d", len(recipients), reg.max.Load())
	}
}
func TestListRecipientsRejectsCorruptRegistration(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	if err := a.Storage.Put(context.Background(), "recipient-corrupt", storage.Object{MediaType: recipientMediaType, Data: []byte("bad")}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListRecipients(context.Background()); err == nil {
		t.Fatal("corrupt recipient accepted")
	}
}

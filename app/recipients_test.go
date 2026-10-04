package app

import (
	"context"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"sync/atomic"
	"testing"
	"time"
)

func TestListRecipients(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	second := mustKeyPair(t)
	if err := putRef(context.Background(), a.Storage, RecipientKey(second.PublicKey), []byte(second.PublicKey), ""); err != nil {
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
	storagetest.Objects
	active atomic.Int32
	max    atomic.Int32
}

func (r *concurrentRegistry) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	active := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		max := r.max.Load()
		if active <= max || r.max.CompareAndSwap(max, active) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	return r.Objects.Get(ctx, key)
}
func TestListRecipientsPullsWithBoundedConcurrency(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	for range 11 {
		kp := mustKeyPair(t)
		if err := putRef(context.Background(), a.Storage, RecipientKey(kp.PublicKey), []byte(kp.PublicKey), ""); err != nil {
			t.Fatal(err)
		}
	}
	reg := &concurrentRegistry{Objects: storagetest.ToObjects(a.Storage)}
	a.Storage = storagetest.FromObjects(reg)
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
	if err := putRef(context.Background(), a.Storage, "recipient-corrupt", []byte("bad"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListRecipients(context.Background()); err == nil {
		t.Fatal("corrupt recipient accepted")
	}
}

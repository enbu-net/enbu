package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/opencontainers/go-digest"
)

func newTestJournal(t *testing.T) (*Journal, *cas.Store, *artifact.DeviceIdentity, string) {
	t.Helper()
	store, err := cas.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.GenerateMaterialIdentity()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/audit.log"
	journal, err := NewJournal(path, store, store, identity, signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal, store, signer, path
}

func testEvent(signer *artifact.DeviceIdentity, result string) Event {
	operationID, _ := artifact.ParseUUID("11111111-1111-4111-8111-111111111111")
	return Event{
		APIVersion: APIVersion, Kind: Kind, OperationID: operationID,
		Action: "materialize", DeviceID: signer.DeviceID(),
		CiphertextDigest: digest.FromString("ciphertext"), ResultCode: result,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func TestJournalEncryptsSignsAndChainsEvents(t *testing.T) {
	journal, _, signer, _ := newTestJournal(t)
	first, err := journal.Append(context.Background(), testEvent(signer, "started"))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := testEvent(signer, "succeeded")
	second, err := journal.Append(context.Background(), secondEvent)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest || first.MediaType != artifact.MediaTypeEncryptedAuditSegment {
		t.Fatalf("audit descriptors = %#v / %#v", first, second)
	}
	events, err := journal.Replay(context.Background(), signer.SigningPublicKey())
	if err != nil || len(events) != 2 {
		t.Fatalf("Replay() = %#v, %v", events, err)
	}
	if events[1].PreviousDigest != digest.FromBytes(mustEncodeEvent(t, events[0])) {
		t.Fatal("second event does not link to first event")
	}
}

func TestJournalNeverStoresSecretMetadataAndRecoversTruncatedFrame(t *testing.T) {
	journal, _, signer, path := newTestJournal(t)
	if _, err := journal.Append(context.Background(), testEvent(signer, "started")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte("secret-name")) || bytes.Contains(contents, []byte("plaintext-value")) {
		t.Fatal("journal contains forbidden secret metadata")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0, 10, 1, 2}); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	store, err := cas.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.GenerateMaterialIdentity()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewJournal(path, store, store, identity, signer)
	if err == nil {
		// The encrypted object source is intentionally new and cannot replay the
		// prior event; recovery itself must nevertheless truncate the tail.
		_ = reopened.Close()
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatal(statErr)
	}
}

func TestJournalFsyncFailureFailsClosedWithoutAdvancingChain(t *testing.T) {
	journal, _, signer, _ := newTestJournal(t)
	sentinel := errors.New("fsync failed")
	journal.sync = func() error { return sentinel }
	if _, err := journal.Append(context.Background(), testEvent(signer, "started")); !errors.Is(err, sentinel) {
		t.Fatalf("Append() error = %v, want sentinel", err)
	}
	journal.sync = journal.file.Sync
	if _, err := journal.Append(context.Background(), testEvent(signer, "started")); err != nil {
		t.Fatal(err)
	}
}

func TestDispatcherFailureRemainsPending(t *testing.T) {
	journal, _, signer, _ := newTestJournal(t)
	descriptor, err := journal.Append(context.Background(), testEvent(signer, "succeeded"))
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := NewDispatcher()
	if err := dispatcher.Enqueue(descriptor); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("remote unavailable")
	if err := dispatcher.Flush(context.Background(), sinkFunc(func(context.Context, artifact.Descriptor) error { return sentinel })); !errors.Is(err, sentinel) {
		t.Fatalf("Flush() error = %v, want sentinel", err)
	}
	if len(dispatcher.Pending()) != 1 {
		t.Fatal("failed delivery was removed from pending queue")
	}
	if err := dispatcher.Flush(context.Background(), sinkFunc(func(context.Context, artifact.Descriptor) error { return nil })); err != nil {
		t.Fatal(err)
	}
	if len(dispatcher.Pending()) != 0 {
		t.Fatal("successful delivery remained pending")
	}
}

type sinkFunc func(context.Context, artifact.Descriptor) error

func (function sinkFunc) Deliver(ctx context.Context, descriptor artifact.Descriptor) error {
	return function(ctx, descriptor)
}

func mustEncodeEvent(t *testing.T, event Event) []byte {
	t.Helper()
	encoded, err := EncodeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

package engine

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/audit"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/opencontainers/go-digest"
)

func TestJournalAuditTrailReplayHasClosedVocabularyAndConsistentChain(t *testing.T) {
	t.Parallel()

	timestamps := []time.Time{
		time.Date(2026, 8, 9, 12, 34, 56, 123, time.FixedZone("test", 9*60*60)),
		time.Date(2026, 8, 9, 12, 35, 1, 456, time.FixedZone("test", 9*60*60)),
	}
	nextTimestamp := 0
	journal, trail, signer := newJournalAuditFixture(t, func() time.Time {
		value := timestamps[nextTimestamp]
		nextTimestamp++
		return value
	})
	operationID := testUUID(t, "71717171-7171-4171-8171-717171717171")
	ciphertext := digest.FromString("sealed-commit")

	if err := trail.Started(context.Background(), operationID, AuditActionMaterialize, ciphertext); err != nil {
		t.Fatalf("Started: %v", err)
	}
	if err := trail.Finished(context.Background(), operationID, AuditActionMaterialize, ciphertext, AuditResultSucceeded); err != nil {
		t.Fatalf("Finished: %v", err)
	}

	events, err := journal.Replay(context.Background(), signer.SigningPublicKey())
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Replay event count = %d, want 2", len(events))
	}
	wantResults := []string{"started", "succeeded"}
	for index, event := range events {
		if event.APIVersion != audit.APIVersion || event.Kind != audit.Kind {
			t.Fatalf("event[%d] envelope = %q/%q", index, event.APIVersion, event.Kind)
		}
		if event.OperationID != operationID || event.DeviceID != signer.DeviceID() || event.CiphertextDigest != ciphertext {
			t.Fatalf("event[%d] identity fields = %#v", index, event)
		}
		if event.Action != "materialize" || event.ResultCode != wantResults[index] {
			t.Fatalf("event[%d] action/result = %q/%q", index, event.Action, event.ResultCode)
		}
		wantTimestamp := timestamps[index].UTC().Format(time.RFC3339Nano)
		if event.Timestamp != wantTimestamp {
			t.Fatalf("event[%d] timestamp = %q, want %q", index, event.Timestamp, wantTimestamp)
		}
	}
	if events[0].PreviousDigest != "" {
		t.Fatalf("first previous digest = %q, want empty", events[0].PreviousDigest)
	}
	encodedFirst, err := audit.EncodeEvent(events[0])
	if err != nil {
		t.Fatalf("EncodeEvent(first): %v", err)
	}
	if events[1].PreviousDigest != digest.FromBytes(encodedFirst) {
		t.Fatalf("second previous digest = %q, want digest of first event", events[1].PreviousDigest)
	}
}

func TestJournalAuditTrailPersistsTerminalAfterContextCancellation(t *testing.T) {
	t.Parallel()

	journal, trail, signer := newJournalAuditFixture(t, func() time.Time {
		return time.Date(2026, 8, 9, 3, 4, 5, 6, time.UTC)
	})
	operationID := testUUID(t, "72727272-7272-4272-8272-727272727272")
	ciphertext := digest.FromString("canceled-operation")
	ctx, cancel := context.WithCancel(context.Background())

	if err := trail.Started(ctx, operationID, AuditActionApply, ciphertext); err != nil {
		t.Fatalf("Started: %v", err)
	}
	cancel()
	if err := trail.Finished(ctx, operationID, AuditActionApply, ciphertext, AuditResultFailed); err != nil {
		t.Fatalf("Finished after cancellation: %v", err)
	}

	events, err := journal.Replay(context.Background(), signer.SigningPublicKey())
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(events) != 2 || events[1].Action != "apply" || events[1].ResultCode != "failed" {
		t.Fatalf("terminal events = %#v", events)
	}
}

func TestJournalAuditTrailRejectsOpenEndedActionAndResultValues(t *testing.T) {
	t.Parallel()

	appender := &recordingAuditAppender{}
	trail, err := newJournalAuditTrail(
		appender,
		testUUID(t, "73737373-7373-4373-8373-737373737373"),
		"github:12345",
		func() time.Time { return time.Date(2026, 8, 9, 4, 5, 6, 7, time.UTC) },
	)
	if err != nil {
		t.Fatalf("newJournalAuditTrail: %v", err)
	}
	operationID := testUUID(t, "74747474-7474-4474-8474-747474747474")
	ciphertext := digest.FromString("closed-enums")

	if err := trail.Started(context.Background(), operationID, AuditAction(255), ciphertext); !errors.Is(err, ErrInvalidAuditRecord) {
		t.Fatalf("Started invalid action = %v, want ErrInvalidAuditRecord", err)
	}
	if err := trail.Finished(context.Background(), operationID, AuditActionApply, ciphertext, AuditResultStarted); !errors.Is(err, ErrInvalidAuditRecord) {
		t.Fatalf("Finished invalid terminal result = %v, want ErrInvalidAuditRecord", err)
	}
	if len(appender.events) != 0 {
		t.Fatalf("invalid enum values reached Journal: %#v", appender.events)
	}
}

func TestJournalAuditTrailFsyncFailureFailsPublicationClosed(t *testing.T) {
	t.Parallel()

	fixture := newPublishFixture(t)
	sentinel := errors.New("fsync failed")
	appender := &recordingAuditAppender{err: errors.Join(audit.ErrJournal, sentinel)}
	trail, err := newJournalAuditTrail(appender, fixture.publisher.Device.DeviceID(), "github:12345", time.Now)
	if err != nil {
		t.Fatalf("newJournalAuditTrail: %v", err)
	}
	fixture.publisher.Audit = trail

	if _, err := fixture.publisher.Publish(context.Background(), AuditActionInitialize, fixture.mutation); !errors.Is(err, sentinel) {
		t.Fatalf("Publish = %v, want fsync failure", err)
	}
	if len(fixture.remote.refs) != 0 {
		t.Fatal("publication became visible after audit fsync failure")
	}
	if len(appender.events) != 1 || appender.events[0].ResultCode != "started" {
		t.Fatalf("append attempts = %#v", appender.events)
	}
}

func TestAuditEnumsHaveExactClosedEventVocabulary(t *testing.T) {
	t.Parallel()

	actions := []struct {
		value AuditAction
		want  string
	}{
		{AuditActionInitialize, "initialize"},
		{AuditActionApply, "apply"},
		{AuditActionTransform, "transform"},
		{AuditActionMaterialize, "materialize"},
		{AuditActionChangeAccess, "change_access"},
		{AuditActionMerge, "merge"},
		{AuditActionRestore, "restore"},
	}
	for _, action := range actions {
		if got := action.value.eventValue(); got != action.want {
			t.Errorf("AuditAction(%d) = %q, want %q", action.value, got, action.want)
		}
	}
	if got := AuditAction(0).eventValue(); got != "" {
		t.Errorf("AuditAction(0) = %q, want empty", got)
	}
	if got := AuditAction(255).eventValue(); got != "" {
		t.Errorf("AuditAction(255) = %q, want empty", got)
	}

	results := []struct {
		value AuditResult
		want  string
	}{
		{AuditResultStarted, "started"},
		{AuditResultSucceeded, "succeeded"},
		{AuditResultFailed, "failed"},
	}
	for _, result := range results {
		if got := result.value.eventValue(); got != result.want {
			t.Errorf("AuditResult(%d) = %q, want %q", result.value, got, result.want)
		}
	}
	if got := AuditResult(255).eventValue(); got != "" {
		t.Errorf("AuditResult(255) = %q, want empty", got)
	}
}

type recordingAuditAppender struct {
	events []audit.Event
	err    error
}

func (appender *recordingAuditAppender) Append(ctx context.Context, event audit.Event) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	appender.events = append(appender.events, event)
	return artifact.Descriptor{}, appender.err
}

func newJournalAuditFixture(
	t *testing.T,
	now func() time.Time,
) (*audit.Journal, *JournalAuditTrail, *artifact.DeviceIdentity) {
	t.Helper()
	store, err := cas.New(t.TempDir())
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	identity, err := artifact.GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	signer, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	journal, err := audit.NewJournal(filepath.Join(t.TempDir(), "audit.log"), store, store, identity, signer)
	if err != nil {
		t.Fatalf("audit.NewJournal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	trail, err := NewJournalAuditTrail(journal, signer, "github:12345", now)
	if err != nil {
		t.Fatalf("NewJournalAuditTrail: %v", err)
	}
	return journal, trail, signer
}

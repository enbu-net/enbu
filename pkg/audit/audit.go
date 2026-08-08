// Package audit implements the host-owned encrypted operation journal.
// Plugins never receive a Journal or its signing/encryption identities.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	APIVersion         = "artifacts.enbu.net/v1alpha1"
	Kind               = "AuditEvent"
	MaxActionBytes     = 128
	MaxResultCodeBytes = 128
	MaxFrameBytes      = 256 * 1024
	auditDomain        = "enbu.net/audit-event/v1\x00"
)

var (
	ErrInvalidEvent = errors.New("audit: invalid event")
	ErrChainBroken  = errors.New("audit: hash chain broken")
	ErrJournal      = errors.New("audit: journal failure")
	ErrDelivery     = errors.New("audit: delivery failed")
)

// Event intentionally has no fields for names, labels, paths, payload values,
// or arbitrary provider/plugin errors.
type Event struct {
	APIVersion       string        `cbor:"apiVersion" json:"apiVersion"`
	Kind             string        `cbor:"kind" json:"kind"`
	OperationID      artifact.UUID `cbor:"operationID" json:"operationID"`
	Action           string        `cbor:"action" json:"action"`
	DeviceID         artifact.UUID `cbor:"deviceID" json:"deviceID"`
	CiphertextDigest digest.Digest `cbor:"ciphertextDigest" json:"ciphertextDigest"`
	ResultCode       string        `cbor:"resultCode" json:"resultCode"`
	Timestamp        string        `cbor:"timestamp" json:"timestamp"`
	PreviousDigest   digest.Digest `cbor:"previousDigest,omitempty" json:"previousDigest,omitempty"`
	Signature        []byte        `cbor:"signature" json:"signature"`
}

type eventBody struct {
	APIVersion       string        `cbor:"apiVersion"`
	Kind             string        `cbor:"kind"`
	OperationID      artifact.UUID `cbor:"operationID"`
	Action           string        `cbor:"action"`
	DeviceID         artifact.UUID `cbor:"deviceID"`
	CiphertextDigest digest.Digest `cbor:"ciphertextDigest"`
	ResultCode       string        `cbor:"resultCode"`
	Timestamp        string        `cbor:"timestamp"`
	PreviousDigest   digest.Digest `cbor:"previousDigest,omitempty"`
}

type frame struct {
	Descriptor     artifact.Descriptor `cbor:"descriptor"`
	EventDigest    digest.Digest       `cbor:"eventDigest"`
	PreviousDigest digest.Digest       `cbor:"previousDigest,omitempty"`
}

func (event Event) body() eventBody {
	return eventBody{APIVersion: event.APIVersion, Kind: event.Kind, OperationID: event.OperationID,
		Action: event.Action, DeviceID: event.DeviceID, CiphertextDigest: event.CiphertextDigest,
		ResultCode: event.ResultCode, Timestamp: event.Timestamp, PreviousDigest: event.PreviousDigest}
}

func (event Event) Validate() error {
	if event.APIVersion != APIVersion || event.Kind != Kind {
		return fmt.Errorf("%w: envelope type", ErrInvalidEvent)
	}
	if err := event.OperationID.Validate(); err != nil {
		return fmt.Errorf("%w: operation ID: %v", ErrInvalidEvent, err)
	}
	if err := event.DeviceID.Validate(); err != nil {
		return fmt.Errorf("%w: device ID: %v", ErrInvalidEvent, err)
	}
	if err := validateText(event.Action, MaxActionBytes, "action"); err != nil {
		return err
	}
	if err := validateText(event.ResultCode, MaxResultCodeBytes, "result code"); err != nil {
		return err
	}
	if err := validateDigest(event.CiphertextDigest); err != nil {
		return fmt.Errorf("%w: ciphertext digest: %v", ErrInvalidEvent, err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != event.Timestamp {
		return fmt.Errorf("%w: timestamp is not canonical UTC RFC3339Nano", ErrInvalidEvent)
	}
	if event.PreviousDigest != "" {
		if err := validateDigest(event.PreviousDigest); err != nil {
			return fmt.Errorf("%w: previous digest: %v", ErrInvalidEvent, err)
		}
	}
	if len(event.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature size", ErrInvalidEvent)
	}
	return nil
}

func SignEvent(event Event, signer *artifact.DeviceIdentity) (Event, error) {
	if signer == nil || event.DeviceID != signer.DeviceID() {
		return Event{}, fmt.Errorf("%w: signer/device mismatch", ErrInvalidEvent)
	}
	event.Signature = nil
	if err := validateUnsigned(event); err != nil {
		return Event{}, err
	}
	body, err := artifact.MarshalCanonical(event.body())
	if err != nil {
		return Event{}, fmt.Errorf("%w: encode event: %v", ErrInvalidEvent, err)
	}
	signature, err := signer.Sign(append([]byte(auditDomain), body...))
	if err != nil {
		return Event{}, err
	}
	event.Signature = signature
	return event, event.Validate()
}

func VerifyEvent(event Event, publicKey ed25519.PublicKey) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key size", ErrInvalidEvent)
	}
	signature := append([]byte(nil), event.Signature...)
	event.Signature = nil
	body, err := artifact.MarshalCanonical(event.body())
	if err != nil || !ed25519.Verify(publicKey, append([]byte(auditDomain), body...), signature) {
		return fmt.Errorf("%w: signature", ErrInvalidEvent)
	}
	return nil
}

func EncodeEvent(event Event) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	encoded, err := artifact.MarshalCanonical(event)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidEvent, err)
	}
	return encoded, nil
}

func DecodeEvent(encoded []byte) (Event, error) {
	if len(encoded) == 0 || len(encoded) > MaxFrameBytes {
		return Event{}, fmt.Errorf("%w: encoded size", ErrInvalidEvent)
	}
	var event Event
	if err := artifact.UnmarshalStrict(encoded, &event); err != nil {
		return Event{}, fmt.Errorf("%w: decode: %v", ErrInvalidEvent, err)
	}
	canonical, err := EncodeEvent(event)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Event{}, fmt.Errorf("%w: non-canonical event", ErrInvalidEvent)
	}
	return event, nil
}

// Journal stores only encrypted audit objects and a descriptor index. The
// index is append-only; a descriptor becomes visible only after the frame and
// file metadata have been fsynced.
type Journal struct {
	mu       sync.Mutex
	file     *os.File
	sink     artifact.ObjectSink
	source   artifact.ObjectSource
	identity artifact.MaterialIdentity
	signer   *artifact.DeviceIdentity
	last     digest.Digest
	sync     func() error
}

func NewJournal(path string, sink artifact.ObjectSink, source artifact.ObjectSource, identity artifact.MaterialIdentity, signer *artifact.DeviceIdentity) (*Journal, error) {
	if path == "" || sink == nil || source == nil || signer == nil || identity.RecipientString() == "" {
		return nil, fmt.Errorf("%w: missing journal dependency", ErrJournal)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrJournal, err)
	}
	journal := &Journal{file: file, sink: sink, source: source, identity: identity, signer: signer, sync: file.Sync}
	if err := journal.recoverFrames(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *Journal) Append(ctx context.Context, event Event) (artifact.Descriptor, error) {
	if journal == nil || journal.file == nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: closed journal", ErrJournal)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if ctx == nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: nil context", ErrJournal)
	}
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	event.PreviousDigest = journal.last
	event, err := SignEvent(event, journal.signer)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	encoded, err := EncodeEvent(event)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor, err := artifact.SealEncryptedEnvelope(ctx, journal.sink, journal.identity, artifact.MediaTypeEncryptedAuditSegment, bytes.NewReader(encoded))
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: encrypt event: %v", ErrJournal, err)
	}
	eventDigest := digest.FromBytes(encoded)
	encodedFrame, err := artifact.MarshalCanonical(frame{Descriptor: descriptor, EventDigest: eventDigest, PreviousDigest: event.PreviousDigest})
	if err != nil || len(encodedFrame) > MaxFrameBytes {
		return artifact.Descriptor{}, fmt.Errorf("%w: encode frame", ErrJournal)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encodedFrame)))
	startOffset, err := journal.file.Seek(0, io.SeekEnd)
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: locate append position: %v", ErrJournal, err)
	}
	if _, err := journal.file.Write(append(length[:], encodedFrame...)); err != nil {
		_ = journal.file.Truncate(startOffset)
		return artifact.Descriptor{}, fmt.Errorf("%w: append frame: %v", ErrJournal, err)
	}
	if err := journal.sync(); err != nil {
		_ = journal.file.Truncate(startOffset)
		_, _ = journal.file.Seek(0, io.SeekEnd)
		return artifact.Descriptor{}, fmt.Errorf("%w: fsync: %w", ErrJournal, err)
	}
	journal.last = eventDigest
	return descriptor, nil
}

func (journal *Journal) Replay(ctx context.Context, publicKey ed25519.PublicKey) ([]Event, error) {
	if journal == nil || journal.file == nil {
		return nil, fmt.Errorf("%w: closed journal", ErrJournal)
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrJournal)
	}
	if _, err := journal.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: seek: %v", ErrJournal, err)
	}
	reader := bufio.NewReader(journal.file)
	var previous digest.Digest
	var events []Event
	for {
		var length [4]byte
		_, err := io.ReadFull(reader, length[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: truncated length: %v", ErrJournal, err)
		}
		frameLength := binary.BigEndian.Uint32(length[:])
		if frameLength == 0 || frameLength > MaxFrameBytes {
			return nil, fmt.Errorf("%w: frame length", ErrJournal)
		}
		encodedFrame := make([]byte, frameLength)
		if _, err := io.ReadFull(reader, encodedFrame); err != nil {
			return nil, fmt.Errorf("%w: truncated frame: %v", ErrJournal, err)
		}
		var current frame
		if err := artifact.UnmarshalStrict(encodedFrame, &current); err != nil {
			return nil, fmt.Errorf("%w: frame decode: %v", ErrJournal, err)
		}
		canonical, err := artifact.MarshalCanonical(current)
		if err != nil || !bytes.Equal(encodedFrame, canonical) || current.PreviousDigest != previous {
			return nil, ErrChainBroken
		}
		var plaintext bytes.Buffer
		if err := artifact.OpenEncryptedEnvelope(ctx, journal.source, journal.identity, current.Descriptor, &plaintext); err != nil {
			return nil, fmt.Errorf("%w: decrypt event: %v", ErrJournal, err)
		}
		event, err := DecodeEvent(plaintext.Bytes())
		if err != nil || digest.FromBytes(plaintext.Bytes()) != current.EventDigest || event.PreviousDigest != previous {
			return nil, ErrChainBroken
		}
		if err := VerifyEvent(event, publicKey); err != nil {
			return nil, err
		}
		events = append(events, event)
		previous = current.EventDigest
	}
	return events, nil
}

func (journal *Journal) Close() error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.file == nil {
		return nil
	}
	err := journal.file.Close()
	journal.file = nil
	return err
}

func (journal *Journal) recoverFrames() error {
	if _, err := journal.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: seek: %v", ErrJournal, err)
	}
	reader := bufio.NewReader(journal.file)
	var previous digest.Digest
	var offset int64
	for {
		var length [4]byte
		_, err := io.ReadFull(reader, length[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if truncateErr := journal.file.Truncate(offset); truncateErr != nil {
				return fmt.Errorf("%w: truncate recovery: %v", ErrJournal, truncateErr)
			}
			break
		}
		frameLength := binary.BigEndian.Uint32(length[:])
		if frameLength == 0 || frameLength > MaxFrameBytes {
			return fmt.Errorf("%w: invalid frame length", ErrJournal)
		}
		encodedFrame := make([]byte, frameLength)
		if _, err := io.ReadFull(reader, encodedFrame); err != nil {
			if truncateErr := journal.file.Truncate(offset); truncateErr != nil {
				return fmt.Errorf("%w: truncate recovery: %v", ErrJournal, truncateErr)
			}
			break
		}
		var current frame
		if err := artifact.UnmarshalStrict(encodedFrame, &current); err != nil || current.PreviousDigest != previous {
			return ErrChainBroken
		}
		previous = current.EventDigest
		offset += int64(4 + frameLength)
	}
	journal.last = previous
	_, err := journal.file.Seek(0, io.SeekEnd)
	return err
}

// Dispatcher is an asynchronous delivery queue. A failed sink leaves the
// descriptor pending and never rolls back the already-fsynced local event.
type Dispatcher struct {
	mu      sync.Mutex
	pending map[digest.Digest]artifact.Descriptor
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{pending: make(map[digest.Digest]artifact.Descriptor)}
}

func (dispatcher *Dispatcher) Enqueue(descriptor artifact.Descriptor) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	dispatcher.mu.Lock()
	dispatcher.pending[descriptor.Digest] = descriptor
	dispatcher.mu.Unlock()
	return nil
}

func (dispatcher *Dispatcher) Pending() []artifact.Descriptor {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	result := make([]artifact.Descriptor, 0, len(dispatcher.pending))
	for _, descriptor := range dispatcher.pending {
		result = append(result, descriptor)
	}
	return result
}

type Sink interface {
	Deliver(context.Context, artifact.Descriptor) error
}

func (dispatcher *Dispatcher) Flush(ctx context.Context, sink Sink) error {
	if sink == nil {
		return fmt.Errorf("%w: nil sink", ErrDelivery)
	}
	descriptors := dispatcher.Pending()
	for _, descriptor := range descriptors {
		if err := sink.Deliver(ctx, descriptor); err != nil {
			return fmt.Errorf("%w: %w", ErrDelivery, err)
		}
		dispatcher.mu.Lock()
		delete(dispatcher.pending, descriptor.Digest)
		dispatcher.mu.Unlock()
	}
	return nil
}

func validateUnsigned(event Event) error {
	event.Signature = make([]byte, ed25519.SignatureSize)
	return event.Validate()
}

func validateText(value string, maximum int, field string) error {
	if value == "" || len(value) > maximum || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEvent, field)
	}
	return nil
}

func validateDigest(value digest.Digest) error {
	if value == "" {
		return errors.New("invalid digest")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	return nil
}

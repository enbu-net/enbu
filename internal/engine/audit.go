package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/audit"
	"github.com/opencontainers/go-digest"
)

var ErrInvalidAuditRecord = errors.New("engine: invalid audit record")

// AuditAction is a closed, host-owned vocabulary. Numeric values prevent
// callers from smuggling paths, secret names, or arbitrary error text into the
// journal through a string-shaped action.
type AuditAction uint8

const (
	AuditActionInitialize AuditAction = iota + 1
	AuditActionApply
	AuditActionTransform
	AuditActionMaterialize
	AuditActionChangeAccess
	AuditActionChangePolicy
	AuditActionMerge
	AuditActionRestore
)

func (action AuditAction) valid() bool {
	return action >= AuditActionInitialize && action <= AuditActionRestore
}

func (action AuditAction) eventValue() string {
	switch action {
	case AuditActionInitialize:
		return "initialize"
	case AuditActionApply:
		return "apply"
	case AuditActionTransform:
		return "transform"
	case AuditActionMaterialize:
		return "materialize"
	case AuditActionChangeAccess:
		return "change_access"
	case AuditActionChangePolicy:
		return "change_policy"
	case AuditActionMerge:
		return "merge"
	case AuditActionRestore:
		return "restore"
	default:
		return ""
	}
}

// AuditResult is likewise closed. Started is emitted only through Started;
// Finished accepts only Succeeded or Failed.
type AuditResult uint8

const (
	AuditResultStarted AuditResult = iota + 1
	AuditResultSucceeded
	AuditResultFailed
)

func (result AuditResult) eventValue() string {
	switch result {
	case AuditResultStarted:
		return "started"
	case AuditResultSucceeded:
		return "succeeded"
	case AuditResultFailed:
		return "failed"
	default:
		return ""
	}
}

type auditEventAppender interface {
	Append(context.Context, audit.Event) (artifact.Descriptor, error)
}

// JournalAuditTrail is the only adapter from publication operations to the
// encrypted Journal. Its API contains only fixed enums, opaque identifiers,
// and a ciphertext digest; there is no channel for arbitrary error text,
// paths, names, labels, or plaintext values.
type JournalAuditTrail struct {
	journal  auditEventAppender
	deviceID artifact.UUID
	actor    string
	now      func() time.Time
}

var _ AuditTrail = (*JournalAuditTrail)(nil)

func NewJournalAuditTrail(journal *audit.Journal, device *artifact.DeviceIdentity, actor string, now func() time.Time) (*JournalAuditTrail, error) {
	if journal == nil || device == nil {
		return nil, fmt.Errorf("%w: missing journal or device", ErrInvalidAuditRecord)
	}
	return newJournalAuditTrail(journal, device.DeviceID(), actor, now)
}

func newJournalAuditTrail(journal auditEventAppender, deviceID artifact.UUID, actor string, now func() time.Time) (*JournalAuditTrail, error) {
	if journal == nil {
		return nil, fmt.Errorf("%w: missing journal", ErrInvalidAuditRecord)
	}
	if err := deviceID.Validate(); err != nil {
		return nil, fmt.Errorf("%w: device ID", ErrInvalidAuditRecord)
	}
	if actor == "" || len(actor) > audit.MaxActorBytes || !strings.Contains(actor, ":") {
		return nil, fmt.Errorf("%w: actor", ErrInvalidAuditRecord)
	}
	if now == nil {
		now = time.Now
	}
	return &JournalAuditTrail{journal: journal, deviceID: deviceID, actor: actor, now: now}, nil
}

func (trail *JournalAuditTrail) Started(
	ctx context.Context,
	operationID artifact.UUID,
	action AuditAction,
	ciphertext digest.Digest,
) error {
	return trail.append(ctx, operationID, action, ciphertext, AuditResultStarted)
}

func (trail *JournalAuditTrail) Finished(
	ctx context.Context,
	operationID artifact.UUID,
	action AuditAction,
	ciphertext digest.Digest,
	result AuditResult,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil terminal context", ErrInvalidAuditRecord)
	}
	if result != AuditResultSucceeded && result != AuditResultFailed {
		return fmt.Errorf("%w: invalid terminal result", ErrInvalidAuditRecord)
	}
	// Terminal audit persistence is mandatory even when the operation context
	// has just been canceled. Values survive, but cancellation and deadlines do
	// not prevent the append/fsync from completing.
	return trail.append(context.WithoutCancel(ctx), operationID, action, ciphertext, result)
}

func (trail *JournalAuditTrail) append(
	ctx context.Context,
	operationID artifact.UUID,
	action AuditAction,
	ciphertext digest.Digest,
	result AuditResult,
) error {
	if trail == nil || trail.journal == nil || trail.now == nil {
		return fmt.Errorf("%w: uninitialized audit trail", ErrInvalidAuditRecord)
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidAuditRecord)
	}
	if err := operationID.Validate(); err != nil {
		return fmt.Errorf("%w: operation ID", ErrInvalidAuditRecord)
	}
	if !action.valid() || result.eventValue() == "" {
		return fmt.Errorf("%w: action or result enum", ErrInvalidAuditRecord)
	}
	if ciphertext == "" || ciphertext.Validate() != nil {
		return fmt.Errorf("%w: ciphertext digest", ErrInvalidAuditRecord)
	}
	_, err := trail.journal.Append(ctx, audit.Event{
		APIVersion:       audit.APIVersion,
		Kind:             audit.Kind,
		OperationID:      operationID,
		Action:           action.eventValue(),
		Actor:            trail.actor,
		DeviceID:         trail.deviceID,
		CiphertextDigest: ciphertext,
		ResultCode:       result.eventValue(),
		Timestamp:        trail.now().UTC().Format(time.RFC3339Nano),
	})
	return err
}

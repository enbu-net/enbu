package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
)

const MaxCommitGrantRecipients = 256

// EncryptedCommitVerifier opens the announced AccessGrant and encrypted
// Commit using the current device. Historical signing-key authority comes
// from the Grant's verified enrollment assertions, not mutable account data.
type EncryptedCommitVerifier struct {
	source      artifact.ObjectSource
	device      *artifact.DeviceIdentity
	enrollments artifact.EnrollmentVerifier
}

func NewEncryptedCommitVerifier(
	source artifact.ObjectSource,
	device *artifact.DeviceIdentity,
	enrollments artifact.EnrollmentVerifier,
) (*EncryptedCommitVerifier, error) {
	if source == nil || device == nil || enrollments == nil {
		return nil, errors.New("registry: nil encrypted Commit verifier dependency")
	}
	return &EncryptedCommitVerifier{source: source, device: device, enrollments: enrollments}, nil
}

func (v *EncryptedCommitVerifier) VerifyCommit(
	ctx context.Context,
	announcement CommitAnnouncement,
	budget *VerificationBudget,
) (VerifiedCommit, error) {
	if v == nil || v.source == nil || v.device == nil || v.enrollments == nil {
		return VerifiedCommit{}, errors.New("registry: uninitialized encrypted Commit verifier")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCommit{}, err
	}
	if err := announcement.Validate(); err != nil {
		return VerifiedCommit{}, err
	}
	if err := budget.ConsumeBytes(announcement.Grant.Size); err != nil {
		return VerifiedCommit{}, err
	}

	grantBytes, err := readVerifiedRemoteObject(ctx, v.source, announcement.Grant, artifact.MaxGrantBytes)
	if err != nil {
		if isRejectedObjectError(err) {
			return VerifiedCommit{}, fmt.Errorf("%w: announced Grant object: %w", ErrInvalidCommitVerification, err)
		}
		return VerifiedCommit{}, fmt.Errorf("open announced Grant: %w", err)
	}
	decodedGrant, err := artifact.DecodeAccessGrant(grantBytes)
	if err != nil {
		wipeBytes(grantBytes)
		return VerifiedCommit{}, fmt.Errorf("%w: decode announced Grant: %w", ErrInvalidCommitVerification, err)
	}
	if len(decodedGrant.Wraps) > MaxCommitGrantRecipients {
		wipeBytes(grantBytes)
		return VerifiedCommit{}, fmt.Errorf("%w: Commit Grant exceeds recipient work limit", ErrInvalidCommitVerification)
	}
	if err := budget.ConsumeUnwrapAttempts(len(decodedGrant.Wraps)); err != nil {
		wipeBytes(grantBytes)
		return VerifiedCommit{}, err
	}
	openedGrant, err := artifact.OpenAccessGrant(ctx, grantBytes, v.device, v.enrollments)
	wipeBytes(grantBytes)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, artifact.ErrGrantAccessDenied) {
			return VerifiedCommit{}, err
		}
		return VerifiedCommit{}, fmt.Errorf("%w: verify announced Grant: %w", ErrInvalidCommitVerification, err)
	}
	if openedGrant.Claims.Material != announcement.EncryptedCommit.Digest {
		return VerifiedCommit{}, fmt.Errorf("%w: Grant does not bind encrypted Commit", ErrInvalidRemoteObject)
	}
	issuer, ok := grantIssuer(openedGrant.Claims)
	if !ok {
		return VerifiedCommit{}, fmt.Errorf("%w: Grant issuer is missing or ambiguous", ErrInvalidCommitVerification)
	}
	if err := VerifyCommitAnnouncement(ctx, announcement, issuer.Ed25519PublicKey); err != nil {
		return VerifiedCommit{}, err
	}
	if err := budget.ConsumeBytes(announcement.EncryptedCommit.Size); err != nil {
		return VerifiedCommit{}, err
	}

	verified, err := commitmodel.OpenCommit(
		ctx,
		v.source,
		openedGrant,
		announcement.EncryptedCommit,
		announcement.CommitID,
		v.enrollments,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return VerifiedCommit{}, err
		}
		if isInvalidCommitContentError(err) || isRejectedObjectError(err) {
			return VerifiedCommit{}, fmt.Errorf("%w: announced Commit: %w", ErrInvalidCommitVerification, err)
		}
		return VerifiedCommit{}, fmt.Errorf("verify announced Commit: %w", err)
	}
	value := verified.Commit()
	if value.WorkspaceID != announcement.WorkspaceID ||
		value.Policy.Revision != openedGrant.Claims.Policy {
		return VerifiedCommit{}, fmt.Errorf("%w: Commit, Grant, and announcement binding", ErrInvalidCommitVerification)
	}
	return VerifiedCommit{
		CommitID:          verified.Digest(),
		WorkspaceID:       value.WorkspaceID,
		CommitSignerKeyID: verified.SignerKeyID(),
		EncryptedCommit:   announcement.EncryptedCommit,
		Grant:             announcement.Grant,
		Value:             verified,
	}, nil
}

func grantIssuer(claims artifact.GrantClaims) (artifact.GrantRecipient, bool) {
	var issuer artifact.GrantRecipient
	found := false
	for _, recipient := range claims.Recipients {
		if recipient.DeviceID != claims.Issuer {
			continue
		}
		if found {
			return artifact.GrantRecipient{}, false
		}
		issuer = recipient
		found = true
	}
	return issuer, found
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func isInvalidCommitContentError(err error) bool {
	return errors.Is(err, artifact.ErrInvalidArtifact) ||
		errors.Is(err, artifact.ErrMaterialMismatch) ||
		errors.Is(err, artifact.ErrInvalidEncryptedObject) ||
		errors.Is(err, artifact.ErrInvalidEnrollment) ||
		errors.Is(err, artifact.ErrDeviceSignature) ||
		errors.Is(err, commitmodel.ErrInvalidCommit) ||
		errors.Is(err, commitmodel.ErrNonCanonicalCommit) ||
		errors.Is(err, commitmodel.ErrInvalidSignature) ||
		errors.Is(err, commitmodel.ErrSigningKeyBinding)
}

var _ CommitVerifier = (*EncryptedCommitVerifier)(nil)

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

// AuditTrail is the fail-closed publication subset of the host-owned audit
// journal. Implementations must durably persist Started before returning nil.
// The interface has no field capable of carrying secret names, values, paths,
// labels, or arbitrary error text.
type AuditTrail interface {
	Started(context.Context, artifact.UUID, AuditAction, digest.Digest) error
	Finished(context.Context, artifact.UUID, AuditAction, digest.Digest, AuditResult) error
}

// CommitMutation contains only already-sealed graph state and bounded signed
// provenance. All plaintext work must finish before this publication step.
type CommitMutation struct {
	WorkspaceID artifact.UUID
	Root        artifact.SealedRef
	Policy      artifact.SealedRef
	Parents     []digest.Digest
	Actor       string
	OperationID artifact.UUID
	Provenance  []commitmodel.MutationProvenance
	Closure     Closure
}

type PublishedCommit struct {
	CommitID     digest.Digest
	Announcement artifact.Descriptor
	Encrypted    artifact.Descriptor
	Grant        artifact.Descriptor
}

// Publisher seals, audits, and publishes a Commit. The announcement tag is
// created only after every object in the supplied closure is available and
// verified remotely.
type Publisher struct {
	Local interface {
		artifact.ObjectSink
		artifact.ObjectSource
	}
	Remote     registry.Remote
	Device     *artifact.DeviceIdentity
	Author     artifact.VerifiedDevice
	Recipients []artifact.VerifiedDevice
	Audit      AuditTrail
	// AuditExternallyManaged is set only by the trusted application host after
	// it has durably recorded Started before the first plaintext access. In that
	// mode the host Finalize hook writes the sole terminal event after output
	// commit/abort, so Publisher must not create a duplicate lifecycle.
	AuditExternallyManaged bool
	Now                    func() time.Time
}

func (publisher Publisher) Publish(
	ctx context.Context,
	action AuditAction,
	mutation CommitMutation,
) (result PublishedCommit, returnedErr error) {
	if err := ctx.Err(); err != nil {
		return PublishedCommit{}, err
	}
	if publisher.Local == nil || publisher.Remote == nil || publisher.Device == nil || publisher.Audit == nil || len(publisher.Recipients) == 0 {
		return PublishedCommit{}, errors.New("engine: incomplete publisher")
	}
	if !action.valid() {
		return PublishedCommit{}, errors.New("engine: invalid audit action")
	}
	now := publisher.Now
	if now == nil {
		now = time.Now
	}
	value := commitmodel.Commit{
		APIVersion:  commitmodel.APIVersion,
		Kind:        commitmodel.Kind,
		WorkspaceID: mutation.WorkspaceID,
		Root:        mutation.Root,
		Policy:      mutation.Policy,
		Parents:     append([]digest.Digest(nil), mutation.Parents...),
		Actor:       mutation.Actor,
		DeviceID:    publisher.Device.DeviceID(),
		OperationID: mutation.OperationID,
		Timestamp:   commitmodel.NewTimestamp(now()),
		Provenance:  append([]commitmodel.MutationProvenance(nil), mutation.Provenance...),
	}
	sealed, err := commitmodel.SealCommit(ctx, publisher.Local, value, publisher.Device, publisher.Author)
	if err != nil {
		return PublishedCommit{}, fmt.Errorf("seal commit: %w", err)
	}
	grant, err := sealed.CreateAccessGrant(ctx, mutation.Policy.Revision, publisher.Device, append([]artifact.VerifiedDevice(nil), publisher.Recipients...))
	if err != nil {
		return PublishedCommit{}, fmt.Errorf("grant commit: %w", err)
	}
	grantBytes, err := artifact.EncodeAccessGrant(grant)
	if err != nil {
		return PublishedCommit{}, err
	}
	grantDescriptor, err := publisher.Local.Ingest(ctx, artifact.MediaTypeAccessGrant, bytes.NewReader(grantBytes))
	clearBytes(grantBytes)
	if err != nil {
		return PublishedCommit{}, fmt.Errorf("store commit grant: %w", err)
	}
	announcement, err := registry.NewCommitAnnouncement(
		mutation.WorkspaceID,
		sealed.CommitID(),
		sealed.Descriptor(),
		grantDescriptor,
		publisher.Device,
		publisher.Author,
	)
	if err != nil {
		return PublishedCommit{}, err
	}

	ciphertext := sealed.Descriptor().Digest
	if publisher.AuditExternallyManaged {
		announcementDescriptor, err := registry.Publish(ctx, publisher.Remote, publisher.Local, registry.PublicationClosure{
			PayloadChunks:     append([]artifact.Descriptor(nil), mutation.Closure.Chunks...),
			MaterialManifests: append([]artifact.Descriptor(nil), mutation.Closure.Materials...),
			AccessGrants:      append([]artifact.Descriptor(nil), mutation.Closure.Grants...),
		}, announcement)
		if err != nil {
			return PublishedCommit{}, err
		}
		return PublishedCommit{
			CommitID: sealed.CommitID(), Announcement: announcementDescriptor,
			Encrypted: sealed.Descriptor(), Grant: grantDescriptor,
		}, nil
	}
	if err := publisher.Audit.Started(ctx, mutation.OperationID, action, ciphertext); err != nil {
		return PublishedCommit{}, fmt.Errorf("persist publication audit start: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		terminalContext := context.WithoutCancel(ctx)
		terminalErr := publisher.Audit.Finished(terminalContext, mutation.OperationID, action, ciphertext, AuditResultFailed)
		if terminalErr != nil {
			if returnedErr == nil {
				returnedErr = fmt.Errorf("persist publication audit failure: %w", terminalErr)
			} else {
				returnedErr = errors.Join(returnedErr, fmt.Errorf("persist publication audit failure: %w", terminalErr))
			}
		}
	}()

	announcementDescriptor, err := registry.Publish(ctx, publisher.Remote, publisher.Local, registry.PublicationClosure{
		PayloadChunks:     append([]artifact.Descriptor(nil), mutation.Closure.Chunks...),
		MaterialManifests: append([]artifact.Descriptor(nil), mutation.Closure.Materials...),
		AccessGrants:      append([]artifact.Descriptor(nil), mutation.Closure.Grants...),
	}, announcement)
	if err != nil {
		return PublishedCommit{}, err
	}
	if err := publisher.Audit.Finished(context.WithoutCancel(ctx), mutation.OperationID, action, ciphertext, AuditResultSucceeded); err != nil {
		return PublishedCommit{}, fmt.Errorf("persist publication audit success: %w", err)
	}
	finished = true
	return PublishedCommit{
		CommitID:     sealed.CommitID(),
		Announcement: announcementDescriptor,
		Encrypted:    sealed.Descriptor(),
		Grant:        grantDescriptor,
	}, nil
}

func MergeClosures(values ...Closure) Closure {
	var merged Closure
	for _, value := range values {
		merged.Chunks = append(merged.Chunks, value.Chunks...)
		merged.Materials = append(merged.Materials, value.Materials...)
		merged.Grants = append(merged.Grants, value.Grants...)
	}
	return merged
}

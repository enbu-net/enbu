package registry

import "errors"

var (
	ErrInvalidAnnouncement          = errors.New("invalid commit announcement")
	ErrInvalidAnnouncementSignature = errors.New("invalid commit announcement signature")
	ErrInvalidRemoteObject          = errors.New("invalid remote object")
	ErrInvalidCommitVerification    = errors.New("invalid encrypted commit verification")
	ErrDiscoveryBudgetExceeded      = errors.New("registry discovery work budget exceeded")
	ErrObjectNotFound               = errors.New("remote object not found")
	ErrAnnouncementConflict         = errors.New("commit announcement tag conflict")
)

type RejectionCode string

const (
	RejectionInvalidTag          RejectionCode = "invalid_tag"
	RejectionAmbiguousTag        RejectionCode = "ambiguous_tag"
	RejectionInvalidDescriptor   RejectionCode = "invalid_descriptor"
	RejectionInvalidAnnouncement RejectionCode = "invalid_announcement"
	RejectionDigestMismatch      RejectionCode = "digest_mismatch"
	RejectionInvalidSignature    RejectionCode = "invalid_signature"
	RejectionInvalidBinding      RejectionCode = "invalid_binding"
	RejectionInvalidCommit       RejectionCode = "invalid_commit"
)

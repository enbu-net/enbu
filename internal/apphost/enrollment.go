package apphost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/workspace"
	"github.com/opencontainers/go-digest"
)

const maxApprovedEnrollments = 1_024

type approvedEnrollmentCatalog struct {
	Assertions [][]byte `cbor:"assertions"`
}

// CreateEnrollmentRequest returns a public, candidate-signed key binding. It
// carries no private key and is safe to transport to a workspace owner.
func (runtime *Runtime) CreateEnrollmentRequest(ctx context.Context, subject string) ([]byte, error) {
	if err := runtime.validateContext(ctx); err != nil {
		return nil, err
	}
	device, err := runtime.loadOrCreateDevice(ctx)
	if err != nil {
		return nil, err
	}
	return enrollment.CreateRequest(ctx, device, device.DeviceID(), subject, device.RecipientString())
}

// ApproveEnrollment is an explicit owner decision. expectedSubject prevents a
// transported request from silently selecting a different policy identity.
func (runtime *Runtime) ApproveEnrollment(
	ctx context.Context,
	root string,
	request []byte,
	expectedSubject string,
) ([]byte, error) {
	if err := runtime.validateContext(ctx); err != nil {
		return nil, err
	}
	root, err := validateRoot(root)
	if err != nil {
		return nil, err
	}
	config, _, err := workspace.Load(root)
	if err != nil {
		return nil, err
	}
	claims, err := enrollment.VerifyRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	if expectedSubject == "" || claims.Subject != expectedSubject {
		return nil, errors.New("apphost: enrollment request subject was not explicitly approved")
	}
	device, err := artifact.LoadDeviceIdentity(ctx, runtime.credentials)
	if err != nil {
		return nil, err
	}
	if !isWorkspaceAuthority(config, device.SigningPublicKey()) {
		return nil, errors.New("apphost: local device is not a workspace enrollment authority")
	}
	assertion, err := enrollment.SignWithSigner(enrollment.Claims{
		Issuer: localEnrollmentIssuer, DeviceID: claims.DeviceID, Subject: claims.Subject,
		X25519Recipient: claims.X25519Recipient, Ed25519PublicKey: claims.Ed25519PublicKey,
	}, device)
	if err != nil {
		return nil, err
	}
	verifier, err := enrollment.NewVerifier(config.Authorities)
	if err != nil {
		return nil, err
	}
	verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
	if err != nil {
		return nil, err
	}
	runtime.enrollmentMu.Lock()
	err = runtime.storeApprovedEnrollment(ctx, config.Workspace, verifier, assertion)
	runtime.enrollmentMu.Unlock()
	if err != nil {
		return nil, err
	}
	runtime.executor.addKnownEnrollment(config.Workspace, verified)
	return append([]byte(nil), assertion...), nil
}

// ImportEnrollment installs an owner-issued public assertion only when it
// exactly binds this device's locally held keys.
func (runtime *Runtime) ImportEnrollment(ctx context.Context, root string, assertion []byte) error {
	if err := runtime.validateContext(ctx); err != nil {
		return err
	}
	root, err := validateRoot(root)
	if err != nil {
		return err
	}
	config, _, err := workspace.Load(root)
	if err != nil {
		return err
	}
	verifier, err := enrollment.NewVerifier(config.Authorities)
	if err != nil {
		return err
	}
	verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
	if err != nil {
		return err
	}
	device, err := artifact.LoadDeviceIdentity(ctx, runtime.credentials)
	if err != nil {
		return err
	}
	if verified.DeviceID() != device.DeviceID() || verified.RecipientString() != device.RecipientString() ||
		!bytes.Equal(verified.SigningPublicKey(), device.SigningPublicKey()) {
		return errors.New("apphost: imported enrollment does not bind the local device")
	}
	return runtime.storeEnrollment(ctx, config.Workspace, assertion)
}

func isWorkspaceAuthority(config workspace.Config, publicKey ed25519.PublicKey) bool {
	keyID := digest.FromBytes(publicKey)
	for _, authority := range config.Authorities {
		if authority.Issuer == localEnrollmentIssuer && authority.KeyID == keyID && bytes.Equal(authority.PublicKey, publicKey) {
			return true
		}
	}
	return false
}

func (runtime *Runtime) loadApprovedEnrollments(
	ctx context.Context,
	workspaceID artifact.UUID,
	verifier artifact.EnrollmentVerifier,
) (map[digest.Digest]artifact.VerifiedDevice, error) {
	result := make(map[digest.Digest]artifact.VerifiedDevice)
	encoded, err := runtime.credentials.Load(ctx, approvedEnrollmentCredentialKey(workspaceID))
	if errors.Is(err, fs.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > artifact.MaxEnrollmentAssertionBytes*maxApprovedEnrollments {
		return nil, errors.New("apphost: approved enrollment catalog size")
	}
	var catalog approvedEnrollmentCatalog
	if err := artifact.UnmarshalStrict(encoded, &catalog); err != nil {
		return nil, fmt.Errorf("apphost: decode approved enrollment catalog: %w", err)
	}
	canonical, err := artifact.MarshalCanonical(catalog)
	if err != nil || !bytes.Equal(encoded, canonical) || len(catalog.Assertions) > maxApprovedEnrollments {
		return nil, errors.New("apphost: non-canonical approved enrollment catalog")
	}
	for _, assertion := range catalog.Assertions {
		verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[verified.AssertionDigest()]; duplicate {
			return nil, errors.New("apphost: duplicate approved enrollment")
		}
		result[verified.AssertionDigest()] = verified
	}
	return result, nil
}

func (runtime *Runtime) storeApprovedEnrollment(
	ctx context.Context,
	workspaceID artifact.UUID,
	verifier artifact.EnrollmentVerifier,
	assertion []byte,
) error {
	known, err := runtime.loadApprovedEnrollments(ctx, workspaceID, verifier)
	if err != nil {
		return err
	}
	verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
	if err != nil {
		return err
	}
	if _, exists := known[verified.AssertionDigest()]; !exists && len(known) == maxApprovedEnrollments {
		return errors.New("apphost: approved enrollment limit")
	}
	assertions := make(map[digest.Digest][]byte, len(known)+1)
	encoded, loadErr := runtime.credentials.Load(ctx, approvedEnrollmentCredentialKey(workspaceID))
	if loadErr == nil {
		var catalog approvedEnrollmentCatalog
		if err := artifact.UnmarshalStrict(encoded, &catalog); err != nil {
			return err
		}
		for _, existing := range catalog.Assertions {
			assertions[digest.FromBytes(existing)] = append([]byte(nil), existing...)
		}
	} else if !errors.Is(loadErr, fs.ErrNotExist) {
		return loadErr
	}
	assertions[verified.AssertionDigest()] = append([]byte(nil), assertion...)
	digests := make([]digest.Digest, 0, len(assertions))
	for value := range assertions {
		digests = append(digests, value)
	}
	sort.Slice(digests, func(i, j int) bool { return digests[i].String() < digests[j].String() })
	catalog := approvedEnrollmentCatalog{Assertions: make([][]byte, 0, len(digests))}
	for _, value := range digests {
		catalog.Assertions = append(catalog.Assertions, assertions[value])
	}
	encoded, err = artifact.MarshalCanonical(catalog)
	if err != nil {
		return err
	}
	return runtime.credentials.Store(ctx, approvedEnrollmentCredentialKey(workspaceID), encoded)
}

func (executor *Executor) addKnownEnrollment(workspaceID artifact.UUID, verified artifact.VerifiedDevice) {
	executor.mu.RLock()
	state := executor.states[workspaceID]
	executor.mu.RUnlock()
	if state == nil {
		return
	}
	state.enrollmentMu.Lock()
	state.knownEnrollments[verified.AssertionDigest()] = verified
	state.enrollmentMu.Unlock()
}

func approvedEnrollmentCredentialKey(workspaceID artifact.UUID) string {
	return "workspace-approved-enrollments-v1-" + digest.FromString(string(workspaceID)).Encoded()
}

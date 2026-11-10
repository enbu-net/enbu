package selfupdate

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ErrUnverified marks an update whose signature or checksum did not match;
// nothing of it is installed.
var ErrUnverified = errors.New("update failed verification")

// The release workflow signs checksums.txt with Sigstore's keyless signing:
// the certificate names the workflow file that ran (release-build.yaml of
// this repository, called from main or from a pushed version tag) and the
// GitHub Actions OIDC issuer. Anyone else's signature is refused, as is a
// signature from another workflow of this repository.
const (
	signerIssuer    = "https://token.actions.githubusercontent.com"
	signerSANRegexp = `^https://github\.com/enbu-net/enbu/\.github/workflows/release-build\.yaml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$`
	signerRepoURI   = "https://github.com/enbu-net/enbu"
)

var signerSAN = regexp.MustCompile(signerSANRegexp)

// VerifyChecksums checks the Sigstore bundle of checksums.txt against the
// trusted root: a Fulcio certificate for the release workflow, an SCT, and
// an entry in the Rekor transparency log.
func VerifyChecksums(trusted root.TrustedMaterial, checksums, bundleJSON []byte) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("%w: read the signature: %w", ErrUnverified, err)
	}
	verifier, err := verify.NewVerifier(trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	san, err := verify.NewSANMatcher("", signerSANRegexp)
	if err != nil {
		return err
	}
	issuer, err := verify.NewIssuerMatcher(signerIssuer, "")
	if err != nil {
		return err
	}
	identity, err := verify.NewCertificateIdentity(san, issuer, certificate.Extensions{SourceRepositoryURI: signerRepoURI})
	if err != nil {
		return err
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(checksums)), verify.WithCertificateIdentity(identity))
	if _, err := verifier.Verify(&b, policy); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return nil
}

// ChecksumFor finds a file's SHA-256 in a sha256sum listing.
func ChecksumFor(checksums []byte, name string) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		sum, file, ok := strings.Cut(scanner.Text(), "  ")
		if !ok || strings.TrimPrefix(file, "*") != name {
			continue
		}
		digest, err := hex.DecodeString(sum)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("%w: bad checksum for %s", ErrUnverified, name)
		}
		return digest, nil
	}
	return nil, fmt.Errorf("%w: %s is not in %s", ErrUnverified, name, checksumsName)
}

// VerifyFile checks that r hashes to want.
func VerifyFile(r io.Reader, want []byte) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return fmt.Errorf("%w: checksum mismatch", ErrUnverified)
	}
	return nil
}

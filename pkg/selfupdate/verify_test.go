package selfupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata holds the real checksums.txt of v0.9.0, its Sigstore bundle, and
// the Sigstore public-good trusted root it verified against, so the check
// runs offline against a signature the release workflow made.
func fixture(t *testing.T) (root.TrustedMaterial, []byte, []byte) {
	t.Helper()
	trusted, err := root.NewTrustedRootFromPath("testdata/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := os.ReadFile("testdata/checksums-v0.9.0.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := os.ReadFile("testdata/checksums-v0.9.0.txt.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return trusted, checksums, bundleJSON
}

func TestVerifyChecksumsAcceptsTheReleaseSignature(t *testing.T) {
	trusted, checksums, bundleJSON := fixture(t)
	if err := VerifyChecksums(trusted, checksums, bundleJSON); err != nil {
		t.Fatalf("VerifyChecksums() = %v", err)
	}
}

func TestVerifyChecksumsRefusesChangedContent(t *testing.T) {
	trusted, checksums, bundleJSON := fixture(t)
	changed := bytes.Replace(checksums, []byte("73ebe49f"), []byte("00000000"), 1)
	if bytes.Equal(changed, checksums) {
		t.Fatal("fixture lacks the expected line")
	}
	if err := VerifyChecksums(trusted, changed, bundleJSON); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyChecksums(changed) = %v, want ErrUnverified", err)
	}
}

func TestVerifyChecksumsRefusesABrokenBundle(t *testing.T) {
	trusted, checksums, _ := fixture(t)
	if err := VerifyChecksums(trusted, checksums, []byte(`{}`)); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyChecksums(empty bundle) = %v, want ErrUnverified", err)
	}
}

func TestSignerIdentity(t *testing.T) {
	for _, san := range []string{
		"https://github.com/enbu-net/enbu/.github/workflows/release-build.yaml@refs/heads/main",
		"https://github.com/enbu-net/enbu/.github/workflows/release-build.yaml@refs/tags/v1.2.3",
	} {
		if !signerSAN.MatchString(san) {
			t.Errorf("signer %q refused", san)
		}
	}
	for _, san := range []string{
		"https://github.com/enbu-net/enbu/.github/workflows/ci.yaml@refs/heads/main",
		"https://github.com/enbu-net/enbu/.github/workflows/release-build.yaml@refs/heads/feature",
		"https://github.com/someone/enbu/.github/workflows/release-build.yaml@refs/heads/main",
		"https://github.com/enbu-net/enbu/.github/workflows/release-build.yaml@refs/tags/v1.2.3-evil",
	} {
		if signerSAN.MatchString(san) {
			t.Errorf("signer %q accepted", san)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	_, checksums, _ := fixture(t)
	sum, err := ChecksumFor(checksums, "enbu-desktop_v0.9.0_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sum); !strings.HasPrefix(got, "73ebe49f") {
		t.Errorf("checksum = %s", got)
	}
	if _, err := ChecksumFor(checksums, "enbu-desktop_v0.9.0_plan9_amd64.tar.gz"); !errors.Is(err, ErrUnverified) {
		t.Errorf("missing file = %v, want ErrUnverified", err)
	}
	if _, err := ChecksumFor([]byte("zz  a.tar.gz\n"), "a.tar.gz"); !errors.Is(err, ErrUnverified) {
		t.Errorf("bad hex = %v, want ErrUnverified", err)
	}
}

func TestVerifyFile(t *testing.T) {
	want := sha256.Sum256([]byte("archive"))
	if err := VerifyFile(strings.NewReader("archive"), want[:]); err != nil {
		t.Errorf("VerifyFile(match) = %v", err)
	}
	if err := VerifyFile(strings.NewReader("other"), want[:]); !errors.Is(err, ErrUnverified) {
		t.Errorf("VerifyFile(mismatch) = %v, want ErrUnverified", err)
	}
}

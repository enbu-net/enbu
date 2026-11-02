package identity

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2/transport"
)

// fakeVerifier stands in for Windows Hello: its secret is fixed per
// credential, and it counts how often the user would have been asked.
type fakeVerifier struct {
	secret      []byte
	unsupported bool
	enrolls     int
	asks        int
}

func (f *fakeVerifier) Enroll() ([]byte, []byte, error) {
	f.enrolls++
	if f.unsupported {
		return nil, nil, ErrUserVerificationUnsupported
	}
	return []byte("credential"), bytes.Clone(f.secret), nil
}

func (f *fakeVerifier) Secret(credential []byte) ([]byte, error) {
	f.asks++
	if !bytes.Equal(credential, []byte("credential")) {
		return nil, errors.New("unknown credential")
	}
	return bytes.Clone(f.secret), nil
}

func verifiedBackend(t *testing.T, open func() (transport.TPMCloser, error), v UserVerifier) *TPMBackend {
	t.Helper()
	return &TPMBackend{Device: "test", plainSessions: true, Open: open, Verifier: v}
}

// TestTPMKeysUseTheVerifiedSecret creates the identity, its sealed seed and
// the signing key under one verification, then loads them again in a new
// process with one more, and checks that another secret cannot use them.
func TestTPMKeysUseTheVerifiedSecret(t *testing.T) {
	v := newVirtualTPM(t)
	open := func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }
	hello := &fakeVerifier{secret: bytes.Repeat([]byte{7}, 32)}
	b := verifiedBackend(t, open, hello)
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(md.TPMAuthCredential, []byte("credential")) {
		t.Fatalf("identity credential = %q", md.TPMAuthCredential)
	}
	seed := bytes.Repeat([]byte{3}, 64)
	if err := b.SealSeed(md, seed); err != nil {
		t.Fatal(err)
	}
	s, smd, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_ = id.Close()
	if hello.enrolls != 1 || hello.asks != 0 {
		t.Fatalf("creation asked the user %d+%d times, want one enrollment", hello.enrolls, hello.asks)
	}

	// A new process: one verification covers the identity, seed and signer.
	b = verifiedBackend(t, open, hello)
	id, err = b.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	got, err := b.UnsealSeed(md)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("UnsealSeed: %v", err)
	}
	s, err = b.LoadSigner(smd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ciphertext, err := age.EncryptForPublicKeys([]byte("secret"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ciphertext, id); err != nil || string(out) != "secret" {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := s.Sign(signing.DomainState, []byte("state")); err != nil {
		t.Fatal(err)
	}
	if hello.asks != 1 {
		t.Fatalf("using the keys asked the user %d times, want 1", hello.asks)
	}

	// Another secret loads the blobs (only the parent authorizes Load) but
	// cannot use them.
	other := verifiedBackend(t, open, &fakeVerifier{secret: bytes.Repeat([]byte{8}, 32)})
	wrong, err := other.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrong.Close() }()
	if _, err := age.Decrypt(ciphertext, wrong); err == nil {
		t.Fatal("another secret decrypted")
	}
	if _, err := other.UnsealSeed(md); err == nil {
		t.Fatal("another secret unsealed the seed")
	}
	wrongSigner, err := other.LoadSigner(smd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrongSigner.Close() }()
	if _, err := wrongSigner.Sign(signing.DomainState, []byte("state")); err == nil {
		t.Fatal("another secret signed")
	}

	// Removing the credential from the metadata does not help either: the
	// key is used with an empty authValue, which the TPM refuses.
	stripped := *md
	stripped.TPMAuthCredential = nil
	bare, err := verifiedBackend(t, open, nil).Load(&stripped)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bare.Close() }()
	if _, err := age.Decrypt(ciphertext, bare); err == nil {
		t.Fatal("an empty authValue decrypted")
	}
	unverified, err := verifiedBackend(t, open, nil).Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unverified.Close() }()
	if _, err := age.Decrypt(ciphertext, unverified); err == nil {
		t.Fatal("a key that needs verification decrypted without a verifier")
	}
}

// TestTPMLoadingKeysDoesNotAsk loads the identity and signer only to read
// their public parts, as `enbu identity` and the member list do, and checks
// that the user is asked only when a key is used.
func TestTPMLoadingKeysDoesNotAsk(t *testing.T) {
	v := newVirtualTPM(t)
	open := func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }
	hello := &fakeVerifier{secret: bytes.Repeat([]byte{7}, 32)}
	b := verifiedBackend(t, open, hello)
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	s, smd, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	b = verifiedBackend(t, open, hello)
	id, err = b.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	s, err = b.LoadSigner(smd)
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Recipient()
	_ = s.Public()
	if hello.asks != 0 {
		t.Fatalf("loading asked the user %d times", hello.asks)
	}
	if _, err := s.Sign(signing.DomainState, []byte("state")); err != nil || hello.asks != 1 {
		t.Fatalf("Sign: asks=%d err=%v", hello.asks, err)
	}
	_ = id.Close()
	_ = s.Close()
	if _, err := s.Sign(signing.DomainState, []byte("state")); err == nil || hello.asks != 1 {
		t.Fatalf("a closed signer signed or asked: asks=%d err=%v", hello.asks, err)
	}
}

func TestTPMKeysWithoutPRFHaveNoAuthValue(t *testing.T) {
	v := newVirtualTPM(t)
	open := func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }
	hello := &fakeVerifier{unsupported: true}
	id, md, err := verifiedBackend(t, open, hello).Create()
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if len(md.TPMAuthCredential) != 0 {
		t.Fatal("a key without PRF recorded a credential")
	}
	id, err = verifiedBackend(t, open, nil).Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	ciphertext, err := age.EncryptForPublicKeys([]byte("secret"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ciphertext, id); err != nil {
		t.Fatal(err)
	}
}

func TestTPMAuthIsCachedForItsTTL(t *testing.T) {
	now := time.Unix(0, 0)
	hello := &fakeVerifier{secret: bytes.Repeat([]byte{7}, 32)}
	b := &TPMBackend{Verifier: hello}
	b.auth.now = func() time.Time { return now }
	credential, first, err := b.enrollAuth()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Fatalf("authValue has %d bytes", len(first))
	}
	if _, again, _ := b.enrollAuth(); !bytes.Equal(again, first) || hello.enrolls != 1 {
		t.Fatal("a second key in the TTL enrolled again")
	}
	if got, _ := b.authFor(credential); !bytes.Equal(got, first) || hello.asks != 0 {
		t.Fatal("a cached secret asked the user")
	}
	// A caller clearing its copy leaves the cache intact.
	clear(first)
	if got, _ := b.authFor(credential); bytes.Equal(got, first) {
		t.Fatal("the cache handed out its own buffer")
	}
	now = now.Add(authTTL + time.Second)
	if b.auth.cached(nil) != nil || b.auth.value != nil {
		t.Fatal("an expired secret stayed in the cache")
	}
	if _, err := b.authFor(credential); err != nil || hello.asks != 1 {
		t.Fatalf("an expired secret was reused: asks=%d err=%v", hello.asks, err)
	}
	if _, err := b.authFor([]byte("other")); err == nil {
		t.Fatal("an unknown credential was answered from the cache")
	}
	if _, err := deriveAuth(make([]byte, 16)); err == nil {
		t.Fatal("a short secret was accepted")
	}
}

//go:build windows && !identitytest

package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// helloVerifier derives the TPM keys' authValue from the PRF (hmac-secret) of
// a Windows Hello passkey, through webauthn.dll. Windows asks for the user's
// face, fingerprint or PIN each time the secret is read.
type helloVerifier struct {
	api uintptr // WebAuthNGetApiVersionNumber
}

const (
	helloRPID    = "enbu:"
	helloRPName  = "enbu"
	helloTimeout = 120_000 // milliseconds

	webauthnAttachmentPlatform = 1
	webauthnUVRequired         = 1
	webauthnAttestationNone    = 1
	webauthnCOSEES256          = -7
)

var (
	modWebAuthn             = windows.NewLazySystemDLL("webauthn.dll")
	procAPIVersion          = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procUVPAAvailable       = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procMakeCredential      = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procGetAssertion        = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeAttestation     = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procFreeAssertion       = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procConsoleWindow       = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	helloCredentialType, _  = windows.UTF16PtrFromString("public-key")
	helloHashSHA256, _      = windows.UTF16PtrFromString("SHA-256")
	helloRPIDPtr, _         = windows.UTF16PtrFromString(helloRPID)
	helloRPNamePtr, _       = windows.UTF16PtrFromString(helloRPName)
	helloUserName, _        = windows.UTF16PtrFromString("enbu")
	helloUserDisplayName, _ = windows.UTF16PtrFromString("enbu device key")
	errHelloCancelled       = errors.New("verification with Windows Hello was cancelled")
	helloPRFSalt            = sha256.Sum256([]byte("enbu tpm auth salt v1"))
)

// The structs below mirror webauthn.h (github.com/microsoft/webauthn) up to
// the versions enbu sets. Go lays them out like C on 64-bit Windows, the only
// Windows targets enbu builds.

type webauthnRPInfo struct {
	version uint32
	id      *uint16
	name    *uint16
	icon    *uint16
}

type webauthnUserInfo struct {
	version     uint32
	idLen       uint32
	id          *byte
	name        *uint16
	icon        *uint16
	displayName *uint16
}

type webauthnCOSEParam struct {
	version  uint32
	credType *uint16
	alg      int32
}

type webauthnCOSEParams struct {
	count  uint32
	params *webauthnCOSEParam
}

type webauthnClientData struct {
	version uint32
	jsonLen uint32
	json    *byte
	hashAlg *uint16
}

type webauthnCredential struct {
	version  uint32
	idLen    uint32
	id       *byte
	credType *uint16
}

type webauthnCredentials struct {
	count uint32
	creds *webauthnCredential
}

type webauthnExtensions struct {
	count uint32
	exts  unsafe.Pointer
}

type helloSalt struct {
	firstLen uint32
	first    *byte
	_        uint32 // cbSecond
	_        *byte  // pbSecond
}

type helloSaltValues struct {
	global *helloSalt
	_      uint32         // cCredWithHmacSecretSaltList
	_      unsafe.Pointer // pCredWithHmacSecretSaltList
}

// webauthnMakeCredentialOptions is WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
// version 8, whose pPRFGlobalEval returns the PRF with the new credential.
type webauthnMakeCredentialOptions struct {
	version            uint32
	timeout            uint32
	credentials        webauthnCredentials
	extensions         webauthnExtensions
	attachment         uint32
	requireResidentKey int32
	userVerification   uint32
	attestation        uint32
	flags              uint32
	cancellationID     unsafe.Pointer // v2
	excludeList        unsafe.Pointer // v3
	enterpriseAtt      uint32         // v4
	largeBlobSupport   uint32
	preferResidentKey  int32
	browserInPrivate   int32 // v5
	enablePRF          int32 // v6
	linkedDevice       unsafe.Pointer
	jsonExtLen         uint32 // v7
	jsonExt            *byte
	prfGlobalEval      *helloSalt // v8
	hintCount          uint32
	hints              unsafe.Pointer
	thirdPartyPayment  int32
}

// webauthnAttestation is WEBAUTHN_CREDENTIAL_ATTESTATION up to version 7.
// Fields past the version the DLL reports must not be read.
type webauthnAttestation struct {
	version              uint32
	formatType           *uint16
	authDataLen          uint32
	authData             *byte
	attestationLen       uint32
	attestation          *byte
	decodeType           uint32
	decoded              unsafe.Pointer
	attestationObjectLen uint32
	attestationObject    *byte
	credentialIDLen      uint32
	credentialID         *byte
	extensions           webauthnExtensions // v2
	usedTransport        uint32             // v3
	epAtt                int32              // v4
	largeBlobSupported   int32
	residentKey          int32
	prfEnabled           int32 // v5
	unsignedExtLen       uint32
	unsignedExt          *byte      // v6
	hmacSecret           *helloSalt // v7
}

// webauthnGetAssertionOptions is WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
// version 6, the first with PRF salts.
type webauthnGetAssertionOptions struct {
	version          uint32
	timeout          uint32
	credentials      webauthnCredentials
	extensions       webauthnExtensions
	attachment       uint32
	userVerification uint32
	flags            uint32
	u2fAppID         *uint16        // v2
	u2fAppIDUsed     *int32         // v2
	cancellationID   unsafe.Pointer // v3
	allowList        unsafe.Pointer // v4
	largeBlobOp      uint32         // v5
	largeBlobLen     uint32
	largeBlob        *byte
	saltValues       *helloSaltValues // v6
	browserInPrivate int32
}

// webauthnAssertion is WEBAUTHN_ASSERTION up to version 3.
type webauthnAssertion struct {
	version         uint32
	authDataLen     uint32
	authData        *byte
	signatureLen    uint32
	signature       *byte
	credential      webauthnCredential
	userIDLen       uint32
	userID          *byte
	extensions      webauthnExtensions // v2
	largeBlobLen    uint32
	largeBlob       *byte
	largeBlobStatus uint32
	hmacSecret      *helloSalt // v3
}

// newHelloVerifier returns the Windows Hello verifier, or nil when this
// Windows has no webauthn.dll or no user-verifying platform authenticator
// (Hello is not set up). Keys are then created without an authValue.
func newHelloVerifier() UserVerifier {
	if procAPIVersion.Find() != nil || procUVPAAvailable.Find() != nil {
		return nil
	}
	// API version 4 is the first whose GetAssertion takes PRF salts.
	api, _, _ := procAPIVersion.Call()
	if api < 4 {
		return nil
	}
	var available int32
	if hr, _, _ := procUVPAAvailable.Call(uintptr(unsafe.Pointer(&available))); hr != 0 || available == 0 {
		return nil
	}
	return helloVerifier{api: api}
}

// helloWindow is the window the Hello prompt belongs to: the foreground
// window when this process owns it (the desktop app), else the console
// window (the CLI), else the desktop (`enbu rpc` under an editor, which has
// neither). A foreground window of another process would be a wrong parent.
func helloWindow() uintptr {
	if w := windows.GetForegroundWindow(); w != 0 {
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(w, &pid); err == nil && pid == windows.GetCurrentProcessId() {
			return uintptr(w)
		}
	}
	if w, _, _ := procConsoleWindow.Call(); w != 0 {
		return w
	}
	return uintptr(windows.GetDesktopWindow())
}

// clientData is the client data webauthn.dll signs. enbu only reads the PRF,
// never the signature, so the challenge is random and unchecked.
func helloClientData(kind string) (*webauthnClientData, []byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, err
	}
	json := []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q}`,
		kind, base64.RawURLEncoding.EncodeToString(challenge), helloRPID))
	return &webauthnClientData{version: 1, jsonLen: uint32(len(json)), json: &json[0], hashAlg: helloHashSHA256}, json, nil
}

func helloError(op string, hr uintptr) error {
	switch uint32(hr) {
	case 0x80090036, // NTE_USER_CANCELLED
		0x800704C7, // HRESULT_FROM_WIN32(ERROR_CANCELLED)
		0x800705B4: // HRESULT_FROM_WIN32(ERROR_TIMEOUT)
		return errHelloCancelled
	case 0x80090029, // NTE_NOT_SUPPORTED
		0x80070032: // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
		// NTE_INVALID_PARAMETER is not here: it would turn a bad option or a
		// bad window into keys without an authValue, silently.
		return fmt.Errorf("%s with Windows Hello: %w", op, ErrUserVerificationUnsupported)
	}
	return fmt.Errorf("%s with Windows Hello failed: HRESULT 0x%08X", op, uint32(hr))
}

func (h helloVerifier) Enroll() ([]byte, []byte, error) {
	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, nil, err
	}
	rp := webauthnRPInfo{version: 1, id: helloRPIDPtr, name: helloRPNamePtr}
	user := webauthnUserInfo{version: 1, idLen: uint32(len(userID)), id: &userID[0], name: helloUserName, displayName: helloUserDisplayName}
	param := webauthnCOSEParam{version: 1, credType: helloCredentialType, alg: webauthnCOSEES256}
	params := webauthnCOSEParams{count: 1, params: &param}
	client, json, err := helloClientData("webauthn.create")
	if err != nil {
		return nil, nil, err
	}
	salt := helloSalt{firstLen: uint32(len(helloPRFSalt)), first: &helloPRFSalt[0]}
	// bEnablePrf needs make-credential options version 6 (API 6). Version 8
	// (API 8) also evaluates the PRF with the new passkey; with version 6 the
	// secret is read with an assertion.
	if h.api < 6 {
		return nil, nil, fmt.Errorf("WebAuthn API %d has no PRF: %w", h.api, ErrUserVerificationUnsupported)
	}
	version := uint32(6)
	if h.api >= 8 {
		version = 8
	}
	opts := webauthnMakeCredentialOptions{version: version, timeout: helloTimeout,
		attachment: webauthnAttachmentPlatform, userVerification: webauthnUVRequired,
		attestation: webauthnAttestationNone, enablePRF: 1, prfGlobalEval: &salt}
	var att *webauthnAttestation
	hr, _, _ := procMakeCredential.Call(helloWindow(), uintptr(unsafe.Pointer(&rp)), uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(client)), uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&att)))
	runtime.KeepAlive(userID)
	runtime.KeepAlive(json)
	runtime.KeepAlive(&salt)
	if hr != 0 {
		return nil, nil, helloError("creating a passkey", hr)
	}
	if att == nil {
		return nil, nil, errors.New("no passkey came back from Windows Hello")
	}
	defer procFreeAttestation.Call(uintptr(unsafe.Pointer(att))) //nolint:errcheck // void function
	if att.version < 5 || att.prfEnabled == 0 {
		return nil, nil, fmt.Errorf("the Windows Hello passkey has no PRF: %w", ErrUserVerificationUnsupported)
	}
	if att.credentialIDLen == 0 || att.credentialID == nil {
		return nil, nil, errors.New("no credential ID came back from Windows Hello")
	}
	credential := append([]byte(nil), unsafe.Slice(att.credentialID, att.credentialIDLen)...)
	if att.version >= 7 {
		if secret := saltOutput(att.hmacSecret); secret != nil {
			return credential, secret, nil
		}
	}
	// This Windows does not return the PRF with a new passkey, so read it now:
	// the user verifies a second time, once per identity.
	secret, err := h.Secret(credential)
	if err != nil {
		return nil, nil, err
	}
	return credential, secret, nil
}

func (helloVerifier) Secret(credential []byte) ([]byte, error) {
	if len(credential) == 0 {
		return nil, errors.New("no Windows Hello credential")
	}
	client, json, err := helloClientData("webauthn.get")
	if err != nil {
		return nil, err
	}
	cred := webauthnCredential{version: 1, idLen: uint32(len(credential)), id: &credential[0], credType: helloCredentialType}
	salt := helloSalt{firstLen: uint32(len(helloPRFSalt)), first: &helloPRFSalt[0]}
	values := helloSaltValues{global: &salt}
	opts := webauthnGetAssertionOptions{version: 6, timeout: helloTimeout,
		credentials: webauthnCredentials{count: 1, creds: &cred},
		attachment:  webauthnAttachmentPlatform, userVerification: webauthnUVRequired, saltValues: &values}
	var assertion *webauthnAssertion
	hr, _, _ := procGetAssertion.Call(helloWindow(), uintptr(unsafe.Pointer(helloRPIDPtr)), uintptr(unsafe.Pointer(client)),
		uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&assertion)))
	runtime.KeepAlive(json)
	runtime.KeepAlive(credential)
	runtime.KeepAlive(&values)
	if hr != 0 {
		return nil, helloError("verifying", hr)
	}
	if assertion == nil {
		return nil, errors.New("no assertion came back from Windows Hello")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(assertion))) //nolint:errcheck // void function
	if assertion.version < 3 {
		return nil, fmt.Errorf("no PRF came back from Windows Hello: %w", ErrUserVerificationUnsupported)
	}
	secret := saltOutput(assertion.hmacSecret)
	if secret == nil {
		return nil, fmt.Errorf("no PRF came back from Windows Hello: %w", ErrUserVerificationUnsupported)
	}
	return secret, nil
}

// saltOutput copies the first PRF output, which webauthn.dll owns.
func saltOutput(s *helloSalt) []byte {
	if s == nil || s.first == nil || s.firstLen < 32 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(s.first, s.firstLen)...)
}

package winbridge

import (
	"encoding/json"
	"errors"
	"io/fs"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/signing"
)

// Protocol is the bridge protocol version. Both sides must speak the same
// one; there is no compatibility layer, so the person installs the same enbu
// in Windows and in WSL.
const Protocol = 1

// The wire format is a stream of JSON objects in each direction: one request,
// then its response. The WSL side sends "hello" first.
type request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wireError      `json:"error,omitempty"`
}

const (
	methodHello              = "hello"
	methodCreate             = "identity.create"
	methodCreatePending      = "identity.create_pending"
	methodLoad               = "identity.load"
	methodLoadRetained       = "identity.load_retained"
	methodInfo               = "identity.info"
	methodPendingInfo        = "identity.pending_info"
	methodPromotePending     = "identity.promote_pending"
	methodUnwrap             = "identity.unwrap"
	methodCreateSigner       = "signer.create"
	methodLoadSigner         = "signer.load"
	methodSignerInfo         = "signer.info"
	methodSign               = "signer.sign"
	methodClose              = "close"
	methodDoctor             = "doctor"
	methodKeyringStore       = "keyring.store"
	methodKeyringLoad        = "keyring.load"
	methodKeyringDelete      = "keyring.delete"
	errIncompatibleProtocol  = "incompatible bridge protocol"
	errUnknownMethod         = "unknown bridge method"
	errUnknownHandle         = "unknown bridge handle"
	errKeyringEntryForbidden = "the bridge does not share this keyring entry"
)

type helloParams struct {
	Protocol int `json:"protocol"`
}

type helloResult struct {
	Protocol int    `json:"protocol"`
	Version  string `json:"version"`
}

type workspaceParams struct {
	WorkspaceID string `json:"workspace_id"`
}

type handleParams struct {
	Handle uint64 `json:"handle"`
}

type identityResult struct {
	Handle    uint64              `json:"handle"`
	Recipient string              `json:"recipient"`
	Info      identity.PublicInfo `json:"info"`
	Created   bool                `json:"created,omitempty"`
	Warning   string              `json:"warning,omitempty"`
}

type retainedResult struct {
	Identities []identityResult `json:"identities"`
}

type infoResult struct {
	Info    identity.PublicInfo `json:"info"`
	Created bool                `json:"created,omitempty"`
}

type unwrapParams struct {
	Handle  uint64        `json:"handle"`
	Stanzas []*age.Stanza `json:"stanzas"`
}

type unwrapResult struct {
	FileKey []byte `json:"file_key"`
}

type signerResult struct {
	Handle  uint64              `json:"handle"`
	Public  signing.PublicKey   `json:"public"`
	Info    identity.SignerInfo `json:"info"`
	Created bool                `json:"created,omitempty"`
	Warning string              `json:"warning,omitempty"`
}

type signerInfoResult struct {
	Info    identity.SignerInfo `json:"info"`
	Created bool                `json:"created,omitempty"`
}

type signParams struct {
	Handle uint64 `json:"handle"`
	Domain string `json:"domain"`
	Body   []byte `json:"body"`
}

type signResult struct {
	Signature []byte `json:"signature"`
}

type keyringParams struct {
	Service string `json:"service"`
	Key     string `json:"key"`
	Secret  []byte `json:"secret,omitempty"`
}

type keyringResult struct {
	Secret []byte `json:"secret"`
}

// wireError keeps what callers test with errors.Is and errors.As: a missing
// key, an unavailable or locked keyring, an identity that does not match, and
// an AppError code. The rest is the message.
type wireError struct {
	Message           string      `json:"message"`
	NotExist          bool        `json:"not_exist,omitempty"`
	Unavailable       bool        `json:"unavailable,omitempty"`
	Reason            string      `json:"reason,omitempty"`
	Locked            bool        `json:"locked,omitempty"`
	NoKeyring         bool        `json:"no_keyring,omitempty"`
	IncorrectIdentity bool        `json:"incorrect_identity,omitempty"`
	Code              apperr.Code `json:"code,omitempty"`
}

func encodeError(err error) *wireError {
	w := &wireError{
		Message:           err.Error(),
		NotExist:          errors.Is(err, fs.ErrNotExist),
		Locked:            errors.Is(err, keystore.ErrLocked),
		NoKeyring:         errors.Is(err, keystore.ErrNoKeyring),
		IncorrectIdentity: errors.Is(err, age.ErrIncorrectIdentity),
	}
	var unavailable *identity.UnavailableError
	if errors.As(err, &unavailable) {
		w.Unavailable, w.Reason = true, unavailable.Reason
	}
	var appErr *apperr.Error
	if errors.As(err, &appErr) {
		w.Code = appErr.Code()
	}
	return w
}

// remoteError is an error from the Windows side. It unwraps to the sentinels
// the Windows error wrapped, so errors.Is works the same on both sides.
type remoteError struct {
	msg    string
	causes []error
}

func (e *remoteError) Error() string   { return e.msg }
func (e *remoteError) Unwrap() []error { return e.causes }

func (w *wireError) decode() error {
	if w.IncorrectIdentity {
		return age.ErrIncorrectIdentity
	}
	base := &remoteError{msg: w.Message}
	for _, c := range []struct {
		set bool
		err error
	}{{w.NotExist, fs.ErrNotExist}, {w.Locked, keystore.ErrLocked}, {w.NoKeyring, keystore.ErrNoKeyring}} {
		if c.set {
			base.causes = append(base.causes, c.err)
		}
	}
	var err error = base
	if w.Unavailable {
		err = &identity.UnavailableError{Reason: w.Reason, Err: base}
	}
	if w.Code != "" {
		err = apperr.Wrap(w.Code, w.Message, err, nil)
	}
	return err
}

package apperr

import (
	"errors"
	"fmt"
)

type Code string

const (
	CodeInternal           Code = "internal"
	CodeInvalidArgument    Code = "invalid_argument"
	CodeNotAuthenticated   Code = "not_authenticated"
	CodeAccessDenied       Code = "access_denied"
	CodeAuthExpired        Code = "authentication_expired"
	CodeNotInitialized     Code = "not_initialized"
	CodeConfigNotFound     Code = "config_not_found"
	CodeEnvironmentMissing Code = "environment_not_found"
	CodeEnvironmentExists  Code = "environment_already_exists"
	CodeSecretMissing      Code = "secret_not_found"
	CodeSecretExists       Code = "secret_already_exists"
	CodeArtifactNotFound   Code = "artifact_not_found"
	CodeConflict           Code = "conflict"
	CodeUnavailable        Code = "unavailable"

	// Workspace security protocol.
	CodeNotMember           Code = "not_member"           // device is not (yet) in the verified Control
	CodeUntrusted           Code = "untrusted_state"      // signature, author or encoding failed verification
	CodeRollback            Code = "rollback_detected"    // storage returned something older than accepted
	CodeIncompatibleStorage Code = "incompatible_storage" // storage lacks a workspace control
	CodeSecretConflict      Code = "secret_conflict"      // concurrent edits changed a secret differently; a person must choose
	CodeControlForked       Code = "control_forked"       // two admins changed the members at once; an admin must resolve it
	CodeReencryptIncomplete Code = "reencrypt_incomplete" // membership changed but secrets are not re-encrypted yet
)

var knownCodes = map[Code]struct{}{
	CodeInternal:           {},
	CodeInvalidArgument:    {},
	CodeNotAuthenticated:   {},
	CodeAccessDenied:       {},
	CodeAuthExpired:        {},
	CodeNotInitialized:     {},
	CodeConfigNotFound:     {},
	CodeEnvironmentMissing: {},
	CodeEnvironmentExists:  {},
	CodeSecretMissing:      {},
	CodeSecretExists:       {},
	CodeArtifactNotFound:   {},
	CodeConflict:           {},
	CodeUnavailable:        {},

	CodeNotMember:           {},
	CodeUntrusted:           {},
	CodeRollback:            {},
	CodeIncompatibleStorage: {},
	CodeSecretConflict:      {},
	CodeControlForked:       {},
	CodeReencryptIncomplete: {},
}

type Params map[string]string

type Payload struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Params  Params `json:"params"`
}

type Error struct {
	code    Code
	message string
	params  Params
	cause   error
}

func New(code Code, message string, params Params) *Error {
	return &Error{code: code, message: message, params: cloneParams(params)}
}

func Wrap(code Code, message string, cause error, params Params) *Error {
	if cause == nil {
		return New(code, message, params)
	}
	return &Error{code: code, message: message, params: cloneParams(params), cause: cause}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.cause == nil {
		return e.message
	}
	return fmt.Sprintf("%s: %v", e.message, e.cause)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *Error) Code() Code {
	if e == nil {
		return CodeInternal
	}
	return e.code
}

func (e *Error) Params() Params {
	if e == nil {
		return Params{}
	}
	return cloneParams(e.params)
}

func Is(err error, code Code) bool {
	var appErr *Error
	return errors.As(err, &appErr) && appErr != nil && appErr.code == code
}

func CodeOf(err error) Code {
	var appErr *Error
	if errors.As(err, &appErr) && appErr != nil {
		return appErr.code
	}
	return CodeInternal
}

func Normalize(err error) error {
	if err == nil {
		return nil
	}
	if direct, ok := err.(*Error); ok {
		return direct
	}

	var appErr *Error
	if errors.As(err, &appErr) && appErr != nil {
		return Wrap(appErr.code, appErr.message, err, appErr.params)
	}
	return Wrap(CodeInternal, "unexpected error", err, nil)
}

func NormalizeInto(err *error) {
	if err == nil || *err == nil {
		return
	}
	*err = Normalize(*err)
}

func PayloadOf(err error) Payload {
	normalized := Normalize(err)
	appErr, ok := normalized.(*Error)
	if !ok || !IsKnownCode(appErr.code) {
		return Payload{Code: CodeInternal, Message: "An unexpected error occurred.", Params: Params{}}
	}
	message := appErr.message
	params := appErr.Params()
	if appErr.code == CodeInternal {
		message = "An unexpected error occurred."
		params = Params{}
	}
	return Payload{Code: appErr.code, Message: message, Params: params}
}

func IsKnownCode(code Code) bool {
	_, ok := knownCodes[code]
	return ok
}

func ExitCode(err error) int {
	switch CodeOf(err) {
	case CodeInvalidArgument:
		return 2
	case CodeNotAuthenticated, CodeAccessDenied:
		return 3
	case CodeConflict:
		return 4
	case CodeNotMember:
		return 3
	case CodeUntrusted, CodeRollback:
		return 5
	default:
		return 1
	}
}

func cloneParams(params Params) Params {
	cloned := make(Params, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

package desktop

import (
	"context"
	"errors"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// Error is how a Service method fails: its message is the AppError payload's,
// so the cause of an internal error never leaves the process. The cause is
// logged when the Error is made.
type Error struct {
	err *apperr.Error
}

func (e *Error) Error() string { return e.err.Error() }

func (e *Error) Unwrap() error { return e.err }

// Payload is what the frontend receives for the failure.
func (e *Error) Payload() apperr.Payload { return apperr.PayloadOf(e.err) }

// publicError turns err into the *Error a Service method returns.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	var public *Error
	if errors.As(err, &public) {
		return public
	}
	normalized := apperr.Normalize(err)
	apperr.Report(context.Background(), "desktop", normalized)
	payload := apperr.PayloadOf(normalized)
	return &Error{err: apperr.New(payload.Code, payload.Message, payload.Params)}
}

func publicInto(err *error) {
	*err = publicError(*err)
}

// ErrorPayload is the AppError payload a frontend receives for err, from a
// Service method or from the transport that called it.
func ErrorPayload(err error) apperr.Payload {
	var public *Error
	if !errors.As(publicError(err), &public) {
		return apperr.PayloadOf(err)
	}
	return public.Payload()
}

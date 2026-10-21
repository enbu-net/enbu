package identity

import (
	"errors"
	"testing"
)

func TestUnavailableCarriesTheReasonAndTheCause(t *testing.T) {
	cause := errors.New("dbus: no reply")
	err := unavailable("OS keyring unavailable", cause)
	var u *UnavailableError
	if !errors.As(err, &u) || u.Reason != "OS keyring unavailable: dbus: no reply" {
		t.Fatalf("reason = %+v", u)
	}
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("errors.Is lost the sentinel or the cause: %v", err)
	}
	if got, want := err.Error(), "identity backend unavailable: OS keyring unavailable: dbus: no reply"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if u := unavailable("keyring unavailable", nil).(*UnavailableError); u.Reason != "keyring unavailable" || u.Unwrap() != nil {
		t.Fatalf("without a cause: %+v", u)
	}
}

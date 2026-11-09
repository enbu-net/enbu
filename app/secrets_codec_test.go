package app

import (
	"reflect"
	"testing"
)

func TestDecodeSecretsRejectsNonObject(t *testing.T) {
	t.Parallel()
	for _, data := range []string{"null", "[]", `"x"`, `{"A":1}`} {
		if _, err := decodeSecrets([]byte(data)); err == nil {
			t.Errorf("decodeSecrets(%s) succeeded", data)
		}
	}
}

func TestEncodeSecretsRoundTrip(t *testing.T) {
	t.Parallel()
	for _, secrets := range []map[string]string{nil, {}, {"A": "1"}} {
		got, err := decodeSecrets(encodeSecrets(secrets))
		if err != nil {
			t.Fatalf("decode(encode(%v)): %v", secrets, err)
		}
		if got == nil || len(got) != len(secrets) || (len(secrets) > 0 && !reflect.DeepEqual(got, secrets)) {
			t.Fatalf("decode(encode(%v)) = %#v", secrets, got)
		}
	}
}

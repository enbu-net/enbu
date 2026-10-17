package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func testObject(kind Kind, scope, signed, cipher string) Object {
	return Object{Kind: kind, Scope: scope, Rev: digest.FromString(signed), Signed: []byte(signed), Cipher: []byte(cipher)}
}

func TestNameAndPrefix(t *testing.T) {
	scope := StateScope("ws", "secrets/dev")
	rev := digest.FromString("x")
	name, err := Name(KindState, scope, rev)
	if err != nil || name != "s-"+scope+"-"+rev.Encoded() {
		t.Fatalf("state name = %q %v", name, err)
	}
	if err := ValidateKey(name); err != nil || len(name) > 128 {
		t.Fatalf("state name is not a legal tag: %v (%d)", err, len(name))
	}
	if name, _ := Name(KindControl, "", rev); name != "c-"+rev.Encoded() {
		t.Fatalf("control name = %q", name)
	}
	if name, _ := Name(KindRequest, "", rev); name != "r-"+rev.Encoded() {
		t.Fatalf("request name = %q", name)
	}
	for _, bad := range []struct {
		kind  Kind
		scope string
	}{{KindState, ""}, {KindState, "UPPERCASE00000000000000000000000"}, {KindControl, scope}, {"other", ""}} {
		if _, err := Name(bad.kind, bad.scope, rev); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	prefix, _ := namePrefix(KindState, scope)
	if got, ok := revFromName(prefix, name2(t, KindState, scope, rev)); !ok || got != rev {
		t.Fatalf("revFromName = %s %v", got, ok)
	}
	for _, tag := range []string{"", prefix, prefix + "short", "s-other-" + rev.Encoded(), prefix + strings.Repeat("g", 64)} {
		if _, ok := revFromName(prefix, tag); ok {
			t.Fatalf("accepted tag %q", tag)
		}
	}
}

func name2(t *testing.T, kind Kind, scope string, rev digest.Digest) string {
	t.Helper()
	n, err := Name(kind, scope, rev)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStateScopeDependsOnWorkspaceAndResource(t *testing.T) {
	a := StateScope("ws", "secrets/dev")
	if a != StateScope("ws", "secrets/dev") || a == StateScope("ws", "secrets/prod") || a == StateScope("other", "secrets/dev") {
		t.Fatal("scope must be stable and depend on both inputs")
	}
	if StateScope("a", "b\x00c") == StateScope("a\x00b", "c") {
		t.Fatal("scope inputs are ambiguous")
	}
}

func TestValidateObject(t *testing.T) {
	scope := StateScope("ws", "r")
	good := testObject(KindState, scope, "signed", "cipher")
	if err := ValidateObject(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Object){
		"wrong digest":         func(o *Object) { o.Rev = digest.FromString("other") },
		"empty signed":         func(o *Object) { o.Signed = nil },
		"state without cipher": func(o *Object) { o.Cipher = nil },
		"oversized cipher":     func(o *Object) { o.Cipher = bytes.Repeat([]byte("x"), MaxPayloadBytes+1) },
		"bad scope":            func(o *Object) { o.Scope = "bad" },
	}
	for name, mutate := range cases {
		o := good
		mutate(&o)
		if err := ValidateObject(o); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	control := testObject(KindControl, "", "signed", "")
	if err := ValidateObject(control); err != nil {
		t.Fatal(err)
	}
	control.Cipher = []byte("x")
	if err := ValidateObject(control); err == nil {
		t.Fatal("control with ciphertext accepted")
	}
}

func TestFrameRoundTripAndRejectsMalformed(t *testing.T) {
	scope := StateScope("ws", "r")
	o := testObject(KindState, scope, "signed", "cipher")
	got, err := unframe(o.Kind, o.Scope, o.Rev, frame(o))
	if err != nil || !bytes.Equal(got.Signed, o.Signed) || !bytes.Equal(got.Cipher, o.Cipher) {
		t.Fatalf("round trip: %v", err)
	}
	for name, data := range map[string][]byte{"empty": nil, "zero length": {0}, "length past end": {200, 1}, "tampered": append([]byte{6}, []byte("signeX")...)} {
		if _, err := unframe(o.Kind, o.Scope, o.Rev, data); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestLocalRejectsCorruptionAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	st := NewLocal(dir)
	ctx := context.Background()
	o := testObject(KindControl, "", "signed-control", "")
	if err := st.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	name := name2(t, KindControl, "", o.Rev)
	path := filepath.Join(dir, revisionDir, name)

	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Fetch(ctx, o.Kind, o.Scope, o.Rev); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("garbage file: %v", err)
	}
	if err := st.Publish(ctx, o); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("publish over a damaged name: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, frame(o), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skip("symlinks are not available:", err)
	}
	if _, err := st.Fetch(ctx, o.Kind, o.Scope, o.Rev); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("symlink followed: %v", err)
	}
}

func TestLocalDiscoverIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	st := NewLocal(dir)
	ctx := context.Background()
	o := testObject(KindRequest, "", "signed-request", "")
	if err := st.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README", "r-short", ".pending-x"} {
		if err := os.WriteFile(filepath.Join(dir, revisionDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := st.Discover(ctx, KindRequest, "")
	if err != nil || len(revs) != 1 || revs[0] != o.Rev {
		t.Fatalf("discover = %v %v", revs, err)
	}
}

package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func testObject(kind Kind, scope, head string, blobs ...string) Object {
	o := Object{Kind: kind, Scope: scope, Rev: digest.FromString(head), Head: []byte(head)}
	for _, b := range blobs {
		o.Blobs = append(o.Blobs, []byte(b))
	}
	return o
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
	good := testObject(KindState, scope, "head", "blob")
	if err := ValidateObject(good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Object){
		"wrong digest":    func(o *Object) { o.Rev = digest.FromString("other") },
		"empty head":      func(o *Object) { o.Head = nil },
		"oversized head":  func(o *Object) { o.Head = bytes.Repeat([]byte("x"), MaxHeadBytes+1) },
		"oversized blob":  func(o *Object) { o.Blobs = [][]byte{bytes.Repeat([]byte("x"), MaxPayloadBytes+1)} },
		"empty blob":      func(o *Object) { o.Blobs = [][]byte{{}} },
		"too many blobs":  func(o *Object) { o.Blobs = make([][]byte, MaxBlobs+1) },
		"bad scope":       func(o *Object) { o.Scope = "bad" },
		"unknown kind":    func(o *Object) { o.Kind = "other" },
		"scope on a head": func(o *Object) { o.Kind = KindControl },
	}
	for name, mutate := range cases {
		o := good
		mutate(&o)
		if err := ValidateObject(o); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// What a state or a control may attach is the protocol's business, not storage's.
	for _, o := range []Object{testObject(KindControl, "", "head"), testObject(KindControl, "", "head", "x", "y"), testObject(KindState, scope, "head")} {
		if err := ValidateObject(o); err != nil {
			t.Fatalf("%s with %d blobs: %v", o.Kind, len(o.Blobs), err)
		}
	}
}

func TestFrameLayoutReachesEachPartWithoutTheOthers(t *testing.T) {
	scope := StateScope("ws", "r")
	o := testObject(KindState, scope, "the head", "first", "second blob")
	data := frame(o)
	r := bytes.NewReader(data)
	head, layout, err := readHead(r, int64(len(data)), o.Rev)
	if err != nil || string(head) != "the head" {
		t.Fatalf("head = %q %v", head, err)
	}
	for i, want := range []string{"first", "second blob"} {
		section, err := blobSection(r, layout, i)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, section.Size())
		if _, err := section.ReadAt(got, 0); err != nil && string(got) != want {
			t.Fatalf("blob %d = %q %v", i, got, err)
		}
		if string(got) != want {
			t.Fatalf("blob %d = %q", i, got)
		}
	}
	if _, err := blobSection(r, layout, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a blob past the end: %v", err)
	}
}

func TestFrameRejectsMalformedAndTampered(t *testing.T) {
	scope := StateScope("ws", "r")
	o := testObject(KindState, scope, "the head", "blob")
	good := frame(o)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-6] ^= 1 // inside the head
	for name, data := range map[string][]byte{
		"empty":           nil,
		"zero parts":      {0},
		"too many parts":  {200, 1},
		"length past end": append([]byte{1, 100}, 'x'),
		"trailing bytes":  append(append([]byte(nil), good...), 'x'),
		"short":           good[:len(good)-1],
		"tampered head":   tampered,
		// 2^64-1 as a length: it must be refused before it is added to anything.
		"length of 2^64-1":  {2, 5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"blob over the cap": append([]byte{2, 1}, append(binary.AppendUvarint(nil, MaxPayloadBytes+1), 'x')...),
		"head over the cap": append([]byte{1}, append(binary.AppendUvarint(nil, MaxHeadBytes+1), 'x')...),
		"zero-length head":  {1, 0},
	} {
		if _, _, err := readHead(bytes.NewReader(data), int64(len(data)), o.Rev); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestLocalRejectsCorruptionAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	st := NewLocal(dir)
	ctx := context.Background()
	o := testObject(KindControl, "", "head-control")
	if err := st.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	name := name2(t, KindControl, "", o.Rev)
	path := filepath.Join(dir, revisionDir, name)

	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FetchHead(ctx, o.Kind, o.Scope, o.Rev); !errors.Is(err, ErrCorrupt) {
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
	if _, err := st.FetchHead(ctx, o.Kind, o.Scope, o.Rev); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("symlink followed: %v", err)
	}
}

func TestLocalDiscoverIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	st := NewLocal(dir)
	ctx := context.Background()
	o := testObject(KindRequest, "", "head-request")
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

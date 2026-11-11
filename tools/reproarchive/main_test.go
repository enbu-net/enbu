package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tree writes files under a new directory with the given modification time.
func tree(t *testing.T, mtime time.Time, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		perm := os.FileMode(0o600)
		if filepath.Ext(name) == ".exe" || filepath.Base(name) == "enbu" {
			perm = 0o700
		}
		if err := os.WriteFile(p, []byte(body), perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func build(t *testing.T, args ...string) []byte {
	t.Helper()
	if err := run(args); err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var sample = map[string]string{
	"enbu":           "binary",
	"share/LICENSE":  "MIT",
	"share/a/b.txt":  "nested",
	"enbu-setup.exe": "exe",
}

func TestArchivesDependOnlyOnContent(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1762790400")
	for _, kind := range []string{"zip", "tar"} {
		t.Run(kind, func(t *testing.T) {
			a := tree(t, time.Unix(1, 0), sample)
			b := tree(t, time.Now(), sample)
			out := t.TempDir()
			first := build(t, kind, filepath.Join(out, "a"), a)
			second := build(t, kind, filepath.Join(out, "b"), b)
			if !bytes.Equal(first, second) {
				t.Fatal("the same files at other times and permissions gave different archives")
			}
		})
	}
}

func TestZipEntries(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1762790400")
	out := filepath.Join(t.TempDir(), "out.zip")
	build(t, "zip", out, tree(t, time.Now(), sample))
	r, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var names []string
	for _, f := range r.File {
		names = append(names, f.Name)
		if !f.Modified.Equal(time.Unix(1762790400, 0)) {
			t.Errorf("%s: modified %v", f.Name, f.Modified)
		}
		want := os.FileMode(0o644)
		if f.Name == "enbu" || f.Name == "enbu-setup.exe" {
			want = 0o755
		}
		if f.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", f.Name, f.Mode().Perm(), want)
		}
	}
	wantNames := []string{"enbu", "enbu-setup.exe", "share/LICENSE", "share/a/b.txt"}
	if len(names) != len(wantNames) {
		t.Fatalf("entries %v, want %v", names, wantNames)
	}
	for i := range names {
		if names[i] != wantNames[i] {
			t.Fatalf("entries %v, want %v", names, wantNames)
		}
	}
}

func TestTarEntries(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1762790400")
	out := filepath.Join(t.TempDir(), "out.tar.gz")
	build(t, "tar", out, tree(t, time.Now(), sample))
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if gz.Name != "" || !gz.ModTime.IsZero() {
		t.Errorf("gzip header carries name %q, time %v", gz.Name, gz.ModTime)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "root" || !h.ModTime.Equal(time.Unix(1762790400, 0)) {
			t.Errorf("%s: owner %d/%d %s, time %v", h.Name, h.Uid, h.Gid, h.Uname, h.ModTime)
		}
	}
	want := "enbu enbu-setup.exe share/ share/LICENSE share/a/ share/a/b.txt"
	if got := join(names); got != want {
		t.Errorf("entries %q, want %q", got, want)
	}
}

func join(s []string) string {
	var b bytes.Buffer
	for i, v := range s {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(v)
	}
	return b.String()
}

func TestRezipKeepsOrderAndContent(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1762790400")
	write := func(name string, when time.Time) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, n := range []string{"[Content_Types].xml", "extension.vsixmanifest", "extension/a.js"} {
			h := &zip.FileHeader{Name: n, Method: zip.Deflate, Modified: when}
			w, err := zw.CreateHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("body of " + n)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.vsix"), filepath.Join(dir, "b.vsix")
	write(a, time.Unix(100, 0))
	write(b, time.Now())
	first, second := build(t, "rezip", a), build(t, "rezip", b)
	if !bytes.Equal(first, second) {
		t.Fatal("rezip of the same entries at other times differs")
	}
	r, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	if r.File[0].Name != "[Content_Types].xml" || r.File[2].Name != "extension/a.js" {
		t.Errorf("order changed: %s, %s", r.File[0].Name, r.File[2].Name)
	}
	rc, err := r.File[2].Open()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(body) != "body of extension/a.js" {
		t.Errorf("content %q", body)
	}
}

func TestRequiresSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	if err := run([]string{"zip", filepath.Join(t.TempDir(), "x.zip"), t.TempDir()}); err == nil {
		t.Fatal("ran without SOURCE_DATE_EPOCH")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "yesterday")
	if err := run([]string{"zip", filepath.Join(t.TempDir(), "x.zip"), t.TempDir()}); err == nil {
		t.Fatal("accepted a SOURCE_DATE_EPOCH that is not a number")
	}
}

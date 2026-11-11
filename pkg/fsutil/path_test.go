package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// A folder name with Japanese, spaces and other non-ASCII characters, in both
// Unicode normalizations where they differ (ド, が).
const nonASCIIName = "日本語 フォルダ (テスト) ドが émoji🔑"

func TestCanonicalKeepsNonASCIIPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), nonASCIIName)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	got := Canonical(dir)
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, string(filepath.Separator)+norm.NFC.String(nonASCIIName)) {
		t.Fatalf("Canonical(%q) = %q", dir, got)
	}
	if info, err := os.Stat(got); err != nil || !info.IsDir() {
		t.Fatalf("the canonical path does not open the folder: %v", err)
	}
	if again := Canonical(got); again != got {
		t.Fatalf("Canonical is not idempotent: %q then %q", got, again)
	}
}

// The CLI (the working directory), git (forward slashes on Windows) and a
// folder picker spell one folder differently; all must compare equal.
func TestCanonicalJoinsSpellingsOfOneFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), nonASCIIName)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := Canonical(dir)
	spellings := []string{
		dir + string(filepath.Separator),
		filepath.Join(dir, "sub", ".."),
		filepath.ToSlash(dir),
	}
	if runtime.GOOS == "windows" {
		spellings = append(spellings, strings.ToUpper(dir), strings.ToLower(dir))
	}
	if runtime.GOOS == "darwin" {
		// macOS opens the NFD spelling a picker or an archive may hand over.
		spellings = append(spellings, norm.NFD.String(dir))
	}
	for _, spelling := range spellings {
		if got := Canonical(spelling); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", spelling, got, want)
		}
	}
}

func TestCanonicalResolvesSymbolicLinks(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, nonASCIIName)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "リンク link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if got, want := Canonical(link), Canonical(target); got != want {
		t.Fatalf("Canonical(link) = %q, want %q", got, want)
	}
}

// A path that does not exist yet still gets an absolute, clean spelling.
func TestCanonicalOfAMissingPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), nonASCIIName, "まだ無い")
	got := Canonical(dir + string(filepath.Separator))
	if !filepath.IsAbs(got) || filepath.Base(got) != norm.NFC.String("まだ無い") {
		t.Fatalf("Canonical = %q", got)
	}
}

func TestSameOrMissing(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Link(a, link); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	for _, c := range []struct {
		path, other string
		want        bool
	}{
		{missing, a, true},
		{a, a, true},
		{a, link, true},
		// Two files whose names differ only by normalization are kept apart.
		{a, b, false},
		{a, missing, false},
	} {
		if got := sameOrMissing(c.path, c.other); got != c.want {
			t.Errorf("sameOrMissing(%q, %q) = %v, want %v", c.path, c.other, got, c.want)
		}
	}
}

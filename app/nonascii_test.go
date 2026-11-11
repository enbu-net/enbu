package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/config"
	"golang.org/x/text/unicode/norm"
)

// A repository, a data directory and an output whose paths hold Japanese and
// spaces work like ASCII ones: init, import, pull to the file, .gitignore.
func TestWorkspaceInNonASCIIPaths(t *testing.T) {
	base := filepath.Join(t.TempDir(), "日本語 フォルダ (テスト)")
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "データ 置き場"))
	a := &App{
		Storage:       newMemRegistry(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: "owner", repo: "repo"},
		Identities:    &apptest.Identities{},
		RepositoryDir: filepath.Join(base, "マイ リポジトリ"),
		CheckpointDir: filepath.Join(base, "チェックポイント"),
		CacheDir:      filepath.Join(base, "キャッシュ"),
	}
	if err := os.MkdirAll(a.RepositoryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a.Identities.(*apptest.Identities).Use(testWorkspaceID, mustKeyPair(t).Identity, nil)
	prepareApp(t, a, "default")
	const output = "本番 環境 (日本語).env"
	setSecretTestOutput(t, a, output)
	if _, err := a.InitializeRepository(bg, InitOptions{}); err != nil {
		t.Fatal(err)
	}

	// What Windows PowerShell 5.1 writes for `Get-Content .env > 秘密.env`.
	units := utf16.Encode([]rune("\uFEFFGREETING=\"こんにちは 世界\"\r\nPATH_JA=C:\\Users\\山田 太郎\r\n"))
	text := make([]byte, 0, 2*len(units))
	for _, u := range units {
		text = append(text, byte(u), byte(u>>8))
	}
	if _, err := a.ImportDotenv(bg, "default", text, false); err != nil {
		t.Fatal(err)
	}
	written, err := a.PullSecretsToFileWith(bg, "default", false)
	if err != nil || written.Output != output || written.Count != 2 {
		t.Fatalf("pull = %+v, %v", written, err)
	}
	got, err := os.ReadFile(filepath.Join(a.RepositoryDir, filepath.FromSlash(output)))
	if err != nil || !strings.Contains(string(got), "GREETING=\"こんにちは 世界\"") || !strings.Contains(string(got), `PATH_JA="C:\\Users\\山田 太郎"`) {
		t.Fatalf("output = %q, %v", got, err)
	}
	ignore, err := os.ReadFile(filepath.Join(a.RepositoryDir, ".gitignore"))
	if err != nil || !strings.Contains(string(ignore), "\n"+output+"\n") {
		t.Fatalf(".gitignore = %q, %v", ignore, err)
	}
}

// The CLI, the desktop app and the VS Code extension reach one repository by
// different spellings; every one of them must find the same trust pin.
func TestRepositoryKeyJoinsSpellingsOfOneRepository(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "日本語 リポジトリ")
	if err := os.MkdirAll(filepath.Join(dir, "サブ"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(dir, config.NewProjectWithEnvironment("default")); err != nil {
		t.Fatal(err)
	}
	key := func(repositoryDir string) string { return (&App{RepositoryDir: repositoryDir}).repositoryKey() }
	want := key(dir)
	if want == "" {
		t.Fatal("no key")
	}
	spellings := []string{filepath.Join(dir, "サブ"), filepath.ToSlash(dir) + "/", filepath.Join(dir, "サブ", "..")}
	if link := filepath.Join(base, "リンク"); os.Symlink(dir, link) == nil {
		spellings = append(spellings, link)
	}
	switch runtime.GOOS {
	case "windows":
		spellings = append(spellings, strings.ToUpper(dir))
	case "darwin":
		spellings = append(spellings, norm.NFD.String(dir))
	}
	for _, spelling := range spellings {
		if got := key(spelling); got != want {
			t.Errorf("repositoryKey(%q) = %q, want %q", spelling, got, want)
		}
	}
}

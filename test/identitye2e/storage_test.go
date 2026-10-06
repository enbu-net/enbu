//go:build identitye2e

package identitye2e

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/minio/minio-go/v7"
)

func localStorageURL(dir string) string {
	path := "/" + strings.TrimPrefix(filepath.ToSlash(dir), "/")
	return (&url.URL{Scheme: "local", Path: path}).String()
}

func TestLocalStorageURL(t *testing.T) {
	for _, test := range []struct {
		dir  string
		path string
	}{
		{dir: "/tmp/enbu objects", path: "/tmp/enbu objects"},
		{dir: "C:/enbu objects", path: "/C:/enbu objects"},
		{dir: "D:/enbu/objects", path: "/D:/enbu/objects"},
	} {
		t.Run(test.dir, func(t *testing.T) {
			raw := localStorageURL(test.dir)
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "local" || u.Host != "" || u.Opaque != "" || u.Path != test.path {
				t.Fatalf("URL %q parsed as %+v, want empty host and path %q", raw, u, test.path)
			}
		})
	}
}

// Every operation starts a new production CLI process. These workspaces have
// neither a Git repository nor GitHub credentials.
func TestStorageBackendLifecycles(t *testing.T) {
	registry := httptest.NewServer(newRegistry())
	defer registry.Close()
	host := "localhost:" + strings.Split(registry.Listener.Addr().String(), ":")[1]
	binary := buildCLI(t, host, true)
	backends := []string{"local", "oci"}
	if os.Getenv("ENBU_TEST_S3_BUCKET") != "" {
		backends = append(backends, "s3")
	}
	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) {
			alice := newHarness(t, binary, "keyring")
			cfg, err := config.LoadProjectFrom(alice.dir)
			if err != nil {
				t.Fatal(err)
			}
			switch backend {
			case "local":
				cfg.Storage = config.StorageConfig{URL: localStorageURL(filepath.Join(t.TempDir(), "objects"))}
			case "s3":
				cfg.Storage = config.StorageConfig{URL: "s3://" + os.Getenv("ENBU_TEST_S3_BUCKET") + "/cli/" + cfg.WorkspaceID, Region: os.Getenv("AWS_REGION"), Endpoint: os.Getenv("ENBU_TEST_S3_ENDPOINT"), PathStyle: os.Getenv("ENBU_TEST_S3_ENDPOINT") != ""}
				client, err := storage.NewS3Client(cfg.Storage.Endpoint, cfg.Storage.Region, cfg.Storage.PathStyle)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					bucket := os.Getenv("ENBU_TEST_S3_BUCKET")
					for object := range client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: "cli/" + cfg.WorkspaceID + "/", Recursive: true}) {
						if object.Err != nil {
							t.Error(object.Err)
							return
						}
						if err := client.RemoveObject(ctx, bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
							t.Error(err)
						}
					}
				})
			}
			if err := config.SaveProjectTo(alice.dir, cfg); err != nil {
				t.Fatal(err)
			}
			alice.env["GITHUB_TOKEN"] = ""
			alice.env["GITHUB_ACTOR"] = ""
			alice.run("init")
			alice.run("add", "DATABASE_URL", "first")
			assertSecret(t, alice.run("pull"), "first")
			alice.run("edit", "DATABASE_URL", "second")
			alice.run("history", "diff", "1", "2")
			alice.run("history", "restore", "1")
			assertSecret(t, alice.run("pull"), "first")
			bob := newHarness(t, binary, "keyring")
			bob.env["GITHUB_TOKEN"] = ""
			bob.env["GITHUB_ACTOR"] = ""
			// Bob receives alice's enbu.toml, which now carries the trusted genesis.
			shared, err := config.LoadProjectFrom(alice.dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := config.SaveProjectTo(bob.dir, shared); err != nil {
				t.Fatal(err)
			}
			bob.workspaceID = cfg.WorkspaceID
			joined := bob.run("init")
			if joined["pending"] != true {
				t.Fatalf("joining member: %+v", joined)
			}
			bob.fails("pull")
			alice.run("member", "approve", "--device", joined["device_id"].(string))
			assertSecret(t, bob.run("pull"), "first")
			bob.run("delete", "DATABASE_URL")
			if data := alice.run("pull"); len(data["secrets"].(map[string]any)) != 0 {
				t.Fatalf("delete: %+v", data)
			}
			// Moving a workspace retains its device Identity because its UUID is stable.
			before := alice.run("identity", "show")["recipient"]
			moved := filepath.Join(t.TempDir(), "moved")
			if err := os.Rename(alice.dir, moved); err != nil {
				t.Fatal(err)
			}
			oldData := alice.env["XDG_DATA_HOME"]
			alice.dir = moved
			alice.env["XDG_DATA_HOME"] = strings.Replace(oldData, filepath.Dir(oldData), moved, 1)
			if after := alice.run("identity", "show")["recipient"]; after != before {
				t.Fatal("moving workspace replaced Identity")
			}
		})
	}
}

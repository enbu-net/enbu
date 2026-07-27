package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
)

type recordingExporter struct {
	input ExportInput
}

func (e *recordingExporter) Export(_ context.Context, input ExportInput) (string, error) {
	e.input = input
	return "recording", nil
}

func TestExportSecretsUsesPluggableExporter(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"TOKEN": "secret"})
	exporter := &recordingExporter{}

	result, err := a.ExportSecrets(context.Background(), "default", exporter)
	if err != nil {
		t.Fatalf("ExportSecrets: %v", err)
	}
	if result.Destination != "recording" || result.Count != 1 {
		t.Fatalf("result = %#v", result)
	}
	if exporter.input.Owner != "owner" || exporter.input.Repository != "repo" || exporter.input.Environment != "default" {
		t.Fatalf("input metadata = %#v", exporter.input)
	}
	if exporter.input.Secrets["TOKEN"] != "secret" {
		t.Fatalf("input secrets = %#v", exporter.input.Secrets)
	}
}

func TestDotenvExporterWritesToWriter(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"TOKEN": "secret"})
	var output bytes.Buffer

	result, err := a.ExportSecrets(context.Background(), "default", DotenvExporter{Writer: &output})
	if err != nil {
		t.Fatalf("ExportSecrets: %v", err)
	}
	if result.Destination != "stdout" {
		t.Fatalf("destination = %q", result.Destination)
	}
	if output.String() != "TOKEN=\"secret\"\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestDotenvExporterCreatesOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	exporter := DotenvExporter{RepositoryDir: dir}

	destination, err := exporter.Export(context.Background(), ExportInput{
		Output:  filepath.Join("config", ".env"),
		Secrets: map[string]string{"TOKEN": "secret"},
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if destination != filepath.Join("config", ".env") {
		t.Fatalf("destination = %q", destination)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config", ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "TOKEN=\"secret\"\n" {
		t.Fatalf("output = %q", data)
	}
}

func TestExportEmptyExistingBundleWritesEmptyOutput(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(map[string]string{}), []string{kp.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	ref := a.secretsRef("owner", "repo", "default")
	if err := a.Registry.Push(context.Background(), ref, "application/vnd.enbu.secrets.age.v1", ciphertext, "tok", nil); err != nil {
		t.Fatal(err)
	}
	if count, found, err := a.PullSecrets(context.Background(), "default"); err != nil || !found || count != 0 {
		t.Fatalf("PullSecrets = count %d, found %v, err %v", count, found, err)
	}

	var output bytes.Buffer
	result, err := a.ExportSecrets(context.Background(), "default", DotenvExporter{Writer: &output})
	if err != nil {
		t.Fatalf("ExportSecrets: %v", err)
	}
	if result.Count != 0 || output.Len() != 0 {
		t.Fatalf("result = %#v, output = %q", result, output.String())
	}
}

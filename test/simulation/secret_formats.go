package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

func (w *World) SecretFormats(ctx context.Context) error {
	values := map[string]string{
		"EMPTY":             "",
		"PEM":               "-----BEGIN PRIVATE KEY-----\nsynthetic-fixture-only\n-----END PRIVATE KEY-----\n",
		"JSON":              "{\"quoted\":\"value\",\"array\":[1,2]}",
		"UNICODE":           "日本語🔐 café",
		"WHITESPACE":        " \t padded \t ",
		"CRLF":              "first\r\nsecond\r\n",
		"LITERAL_EXPANSION": "$HOME ${TOKEN} $(touch must-not-run) `echo literal`",
		"COMMENT_EQUALS":    "#literal=value # still literal",
		"QUOTES":            "single' double\" backslash\\",
	}
	if _, err := w.Devices[0].App.ImportSecrets(ctx, "default", values, true); err != nil {
		return err
	}
	for k, v := range values {
		w.Model["default"][k] = v
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	for i, d := range w.Devices {
		data, _, count, err := d.App.PullSecrets(ctx, "default")
		if err != nil {
			return err
		}
		decoded, err := secretmap.ImportDotenv(data)
		if err != nil {
			return err
		}
		if count != len(w.Model["default"]) || !reflect.DeepEqual(map[string]string(decoded), w.Model["default"]) {
			return fmt.Errorf("secret format roundtrip changed device %d values", i)
		}
		path := filepath.Join(d.App.RepositoryDir, ".env")
		if err := os.WriteFile(path, []byte("LOCAL_ONLY=personal\n"), 0600); err != nil {
			return err
		}
		if err := d.App.PullSecretsToFile(ctx, "default"); err != nil {
			return err
		}
		expected := clone(w.Model["default"])
		expected["LOCAL_ONLY"] = "personal"
		if err := w.checkOutput("secret-format-file", path, expected); err != nil {
			return err
		}
	}
	if err := w.Devices[1].App.SyncSecrets(ctx, "default"); err != nil {
		return err
	}
	if _, err := w.Devices[0].App.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	return w.Check(ctx, "default")
}

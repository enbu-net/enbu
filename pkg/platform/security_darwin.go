//go:build darwin

package platform

import (
	"fmt"
	"path/filepath"
	"strings"
)

var darwinSystemAliases = map[string]string{
	"/etc": "/private/etc",
	"/tmp": "/private/tmp",
	"/var": "/private/var",
}

func canonicalizeParentPath(path string) (string, error) {
	parent := filepath.Dir(path)
	for alias, expected := range darwinSystemAliases {
		if parent != alias && !strings.HasPrefix(parent, alias+string(filepath.Separator)) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(alias)
		if err != nil {
			return "", fmt.Errorf("platform: resolve macOS system alias %q: %w", alias, err)
		}
		if resolved != expected {
			return "", fmt.Errorf("%w: macOS system alias %q resolved to an unexpected target", ErrUnsafePath, alias)
		}
		parent = expected + strings.TrimPrefix(parent, alias)
		return filepath.Join(parent, filepath.Base(path)), nil
	}
	return path, nil
}

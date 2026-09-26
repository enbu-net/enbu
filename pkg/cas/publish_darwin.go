//go:build darwin

package cas

import (
	"errors"
	"fmt"
	"os"
)

func publishNoReplace(root *os.Root, source, destination string) (bool, error) {
	if err := root.Link(source, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("%w: atomic link: %v", ErrUnsupportedAtomicPublish, err)
	}
	if err := root.Remove(source); err != nil {
		return true, fmt.Errorf("remove linked temporary object: %w", err)
	}
	return true, nil
}

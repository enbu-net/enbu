//go:build !linux && !darwin && !windows

package cas

func publishNoReplace(_, _ string) (bool, error) {
	return false, ErrUnsupportedAtomicPublish
}

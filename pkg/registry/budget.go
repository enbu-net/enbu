package registry

import (
	"fmt"
	"sync"
)

const (
	MaxDiscoveryBytes          int64 = 512 * 1024 * 1024
	MaxDiscoveryUnwrapAttempts       = 100_000
)

// VerificationBudget bounds aggregate network and anonymous age-unwrapping
// work across one discovery operation. It is shared by every entry verifier;
// exhaustion aborts discovery and is never classified as a hostile tag.
type VerificationBudget struct {
	mu               sync.Mutex
	remainingBytes   int64
	remainingUnwraps int
}

func newVerificationBudget() *VerificationBudget {
	return &VerificationBudget{
		remainingBytes:   MaxDiscoveryBytes,
		remainingUnwraps: MaxDiscoveryUnwrapAttempts,
	}
}

func (b *VerificationBudget) ConsumeBytes(count int64) error {
	if b == nil || count < 0 {
		return fmt.Errorf("%w: invalid byte accounting", ErrDiscoveryBudgetExceeded)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if count > b.remainingBytes {
		return fmt.Errorf("%w: byte limit", ErrDiscoveryBudgetExceeded)
	}
	b.remainingBytes -= count
	return nil
}

func (b *VerificationBudget) ConsumeUnwrapAttempts(count int) error {
	if b == nil || count < 0 {
		return fmt.Errorf("%w: invalid unwrap accounting", ErrDiscoveryBudgetExceeded)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if count > b.remainingUnwraps {
		return fmt.Errorf("%w: unwrap-attempt limit", ErrDiscoveryBudgetExceeded)
	}
	b.remainingUnwraps -= count
	return nil
}

//go:build enbucoverage && identitye2e

package identitye2e

// The coverage build links tobari into the Identity E2E test binary. The tobari
// toolexec then finds github.com/goccy/tobari in the link importcfg and reuses
// the package compiled by this build. Without this import, a build served
// entirely from the Go build cache (nothing to compile, so the compile hook
// that records the tobari packages never runs) makes tobari rebuild them at
// link time without the -race flag of the outer build, and the link fails
// with "fingerprint mismatch: github.com/goccy/tobari".
import _ "github.com/goccy/tobari"

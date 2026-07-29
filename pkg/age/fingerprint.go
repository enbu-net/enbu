package age

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func Fingerprint(pubKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(pubKey)))
	return hex.EncodeToString(sum[:])[:8]
}

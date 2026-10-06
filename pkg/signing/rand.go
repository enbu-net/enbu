package signing

import (
	"crypto/rand"
	"io"
)

func randReader() io.Reader { return rand.Reader }

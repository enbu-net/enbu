package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// historyFlags is what listing history learns about one revision by decrypting
// it. The repeated parent is retained so removing that parent invalidates the flag.
type historyFlags struct {
	Readable     bool          `json:"r,omitempty"` // this device can decrypt it
	Repeats      bool          `json:"p,omitempty"` // its content equals a parent's (a re-encryption)
	RepeatParent digest.Digest `json:"parent,omitempty"`
}

const historyIndexVersion = 2

type historyIndexFile struct {
	Version   int                            `json:"version"`
	Revisions map[digest.Digest]historyFlags `json:"revisions"`
}

// historyIndex caches display flags, not content or protocol authority. It is
// keyed by the complete set of loaded decryption identities. These local flags
// are trusted as written: editing them can hide entries and change the indices
// used by diff and restore. A cache can never add an unverified revision.
// Missing, malformed, or obsolete files are ignored and rebuilt by decrypting.
type historyIndex struct{ path string }

func (a *App) openHistoryIndex(s *session, resource string) historyIndex {
	sum := sha256.Sum256([]byte(s.workspace + "\x00" + resource + "\x00" + s.id.Recipient().String()))
	return historyIndex{path: filepath.Join(a.cacheDir(), "history", hex.EncodeToString(sum[:])+".json")}
}

func (x historyIndex) load() map[digest.Digest]historyFlags {
	out := map[digest.Digest]historyFlags{}
	b, err := os.ReadFile(x.path)
	if err != nil {
		return out
	}
	var f historyIndexFile
	if json.Unmarshal(b, &f) != nil || f.Version != historyIndexVersion {
		return out
	}
	for d, flags := range f.Revisions {
		if d.Validate() == nil {
			out[d] = flags
		}
	}
	return out
}

// save writes the flags of the revisions still in the history. It is best
// effort, like any cache.
func (x historyIndex) save(flags map[digest.Digest]historyFlags, states map[digest.Digest]*wsp.VerifiedState) {
	if x.path == "" {
		return
	}
	f := historyIndexFile{Version: historyIndexVersion, Revisions: map[digest.Digest]historyFlags{}}
	for d := range states {
		if v, ok := flags[d]; ok {
			f.Revisions[d] = v
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(x.path), 0o700); err != nil {
		return
	}
	_ = fsutil.WriteFileAtomicWith(x.path, b, 0o600, fsutil.AtomicOptions{NoSync: true})
}

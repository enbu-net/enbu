package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// historyFlags is what listing history learns about one revision by decrypting
// it. A revision never changes, so neither do its flags for the same identity.
type historyFlags struct {
	Readable bool `json:"r,omitempty"` // this device can decrypt it
	Repeats  bool `json:"p,omitempty"` // its content equals a parent's (a re-encryption)
}

const historyIndexVersion = 1

type historyIndexFile struct {
	Version   int                            `json:"version"`
	Revisions map[digest.Digest]historyFlags `json:"revisions"`
}

// historyIndex keeps historyFlags of one resource on this device so a listing
// does not decrypt every revision again. It holds no content, only two flags
// per revision. It is keyed by the device's recipient: a device whose key
// changed may read different revisions, so it starts a new index. Anything
// wrong with the file only costs decrypting again; it is never trusted to
// show a revision, which must still be in the verified history.
type historyIndex struct{ path string }

func (a *App) openHistoryIndex(s *session, resource string) historyIndex {
	recipient := ""
	if p, ok := s.head.Principal(s.self()); ok {
		recipient = p.Recipient
	}
	sum := sha256.Sum256([]byte(s.workspace + "\x00" + resource + "\x00" + recipient))
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
	tmp, err := os.CreateTemp(filepath.Dir(x.path), ".history-*")
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(b)
	if errors.Join(err, tmp.Close()) != nil {
		return
	}
	_ = os.Rename(tmp.Name(), x.path)
}

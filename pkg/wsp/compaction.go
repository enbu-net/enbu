package wsp

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// Compaction is an admin's signed record that revisions of one resource were
// removed from storage. Removing revisions would otherwise look like a rollback
// to every device that accepted one of them, and leave the parents of the
// oldest kept revisions missing.
//
// Everything removed is outside Floor: Floor and the revisions descending from
// it were kept. A device excuses an accepted revision that storage no longer
// shows only when a verified record lists it and the record's floor is still
// shown (or was itself removed by a later record whose floor is shown), so the
// view always holds a descendant of what it excuses.
type Compaction struct {
	Workspace string           `cbor:"workspace"`
	Resource  string           `cbor:"resource"`
	Floor     digest.Digest    `cbor:"floor"`
	Removed   []digest.Digest  `cbor:"removed"` // sorted, unique
	Control   digest.Digest    `cbor:"control"` // Control revision the author saw
	Author    signing.DeviceID `cbor:"author"`
	CreatedAt int64            `cbor:"created_at"` // display only
}

// MaxCompactionRemoved bounds the revisions one record lists. A compaction
// that removes more publishes several records with the same floor.
const MaxCompactionRemoved = 4000

// maxCompactions bounds how many records of one resource a load reads.
var maxCompactions = 1000

// VerifiedCompaction is a record whose author was an admin of the Control it names.
type VerifiedCompaction struct {
	Compaction
	Digest digest.Digest
}

func (c Compaction) validate() error {
	if c.Workspace == "" || c.Resource == "" {
		return invalid("compaction has no workspace or resource")
	}
	if err := validDigest(c.Floor); err != nil {
		return invalid("compaction floor: %v", err)
	}
	if len(c.Removed) == 0 || len(c.Removed) > MaxCompactionRemoved {
		return invalid("compaction must remove 1..%d revisions", MaxCompactionRemoved)
	}
	for i, d := range c.Removed {
		if err := validDigest(d); err != nil {
			return invalid("compaction removed: %v", err)
		}
		if i > 0 && c.Removed[i-1] >= d {
			return invalid("compaction removed must be sorted and unique")
		}
		if d == c.Floor {
			return invalid("compaction removes its floor")
		}
	}
	if err := validDigest(c.Control); err != nil {
		return invalid("compaction control: %v", err)
	}
	if err := c.Author.Validate(); err != nil {
		return invalid("compaction author: %v", err)
	}
	return nil
}

// Scope is the storage listing bucket of the record, the scope of its resource.
func (c Compaction) Scope() string { return storage.StateScope(c.Workspace, c.Resource) }

// SignCompaction signs c, whose Author must be signer, and returns the stored bytes.
func SignCompaction(c Compaction, signer signing.Signer) ([]byte, error) {
	c.Removed = append([]digest.Digest(nil), c.Removed...)
	sortDigests(c.Removed)
	if err := c.validate(); err != nil {
		return nil, err
	}
	if signer.Public().DeviceID() != c.Author {
		return nil, invalid("signer is not the compaction author")
	}
	body, err := encMode.Marshal(c)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainCompact, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

// VerifyCompaction checks a stored record of workspace and resource. Its author
// must be an admin of the Control it names, which must be part of the verified
// DAG. Like a revision, it stays valid after its author stops being an admin:
// it only excuses revisions it lists, and only while its floor is shown.
func VerifyCompaction(view *ControlView, workspace, resource string, rev digest.Digest, blob []byte) (*VerifiedCompaction, error) {
	if digest.FromBytes(blob) != rev {
		return nil, invalid("compaction does not match its revision %s", rev)
	}
	signed, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	var c Compaction
	if err := decodeCanonical(signed.Body, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if c.Workspace != workspace || c.Resource != resource {
		return nil, invalid("compaction is for %s/%s, not %s/%s", c.Workspace, c.Resource, workspace, resource)
	}
	written, ok := view.Get(c.Control)
	if !ok {
		return nil, fmt.Errorf("%w: compaction names control %s that storage does not show", ErrRollback, c.Control)
	}
	author, ok := written.Principal(c.Author)
	if !ok || !author.Admin {
		return nil, invalid("compaction author %s is not an admin of the control it names", c.Author)
	}
	if err := signing.Verify(author.Signing, signing.DomainCompact, signed.Body, signed.Signature); err != nil {
		return nil, invalid("compaction signature: %v", err)
	}
	return &VerifiedCompaction{Compaction: c, Digest: rev}, nil
}

// LoadCompactions reads and verifies every compaction record of a resource.
// Records that are damaged or unauthorized carry no authority and are skipped.
func LoadCompactions(ctx context.Context, store storage.Store, view *ControlView, workspace, resource string) ([]*VerifiedCompaction, error) {
	scope := storage.StateScope(workspace, resource)
	revs, err := store.Discover(ctx, storage.KindCompaction, scope)
	if err != nil {
		return nil, err
	}
	if len(revs) > maxCompactions {
		return nil, invalid("resource has too many compaction records")
	}
	var out []*VerifiedCompaction
	for _, rev := range revs {
		head, err := store.FetchHead(ctx, storage.KindCompaction, scope, rev)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):
			continue
		case err != nil:
			return nil, err
		}
		c, err := VerifyCompaction(view, workspace, resource, rev, head)
		if err != nil {
			if errors.Is(err, ErrRollback) {
				return nil, err
			}
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// Compacted is what the records of a resource say about the view storage shows.
type Compacted struct {
	// Removed holds the revisions a record excuses: listed by a record whose
	// floor the view holds, or whose floor is itself excused.
	Removed map[digest.Digest]bool
	// Floors are the floors the view holds. A head that does not descend from
	// every one of them was built on removed history.
	Floors []digest.Digest
}

// Compute applies records to graph g.
func Compute(records []*VerifiedCompaction, g *Graph) Compacted {
	out := Compacted{Removed: map[digest.Digest]bool{}}
	floorShown := map[digest.Digest]bool{}
	for _, r := range records {
		if g.Has(r.Floor) && !floorShown[r.Floor] {
			floorShown[r.Floor] = true
			out.Floors = append(out.Floors, r.Floor)
		}
	}
	sortDigests(out.Floors)
	// A record counts once its floor is shown or excused; excusing one floor
	// can make an older record count, so repeat until nothing changes.
	applied := make([]bool, len(records))
	for progress := true; progress; {
		progress = false
		for i, r := range records {
			if applied[i] || (!floorShown[r.Floor] && !out.Removed[r.Floor]) {
				continue
			}
			applied[i] = true
			progress = true
			for _, d := range r.Removed {
				if !g.Has(d) {
					out.Removed[d] = true
				}
			}
		}
	}
	return out
}

// Excuses reports whether d may be absent from the view.
func (c Compacted) Excuses(d digest.Digest) bool { return c.Removed[d] }

// AboveFloors reports whether revision d of g descends from every floor the view holds.
func (c Compacted) AboveFloors(g *Graph, d digest.Digest) bool {
	if len(c.Floors) == 0 {
		return true
	}
	anc := g.Ancestors(d)
	for _, f := range c.Floors {
		if !anc[f] {
			return false
		}
	}
	return true
}

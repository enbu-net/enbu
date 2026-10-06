package wsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// ControlRef names the mutable pointer to the newest SignedControl blob.
// The ref is a hint: whatever it points at is verified before use.
const ControlRef = "control-head"

const maxChain = 100000

// Checkpoint is the newest Control a client has accepted.
type Checkpoint struct {
	Generation uint64        `json:"generation"`
	Digest     digest.Digest `json:"digest"`
}

// Head is the verified current Control and the ref version to update from.
type Head struct {
	*Verified
	Version storage.Version
}

func readBlob(ctx context.Context, store *storage.Store, d digest.Digest) ([]byte, error) {
	rc, err := store.Blobs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

// LoadControl returns the verified head of the workspace's Control chain.
//
// genesis is the trusted digest from bootstrap information. cp, if not nil, is
// the newest Control this client accepted before; the head must descend from
// it. Verification walks back from the head and stops at cp (trusted by
// digest) or at genesis.
func LoadControl(ctx context.Context, store *storage.Store, workspace string, genesis digest.Digest, cp *Checkpoint) (*Head, error) {
	if err := validDigest(genesis); err != nil {
		return nil, invalid("trusted genesis digest: %v", err)
	}
	d, version, err := store.Refs.Get(ctx, ControlRef)
	if err != nil {
		return nil, err
	}
	var blobs [][]byte // newest first
	for cur := d; ; {
		blob, err := readBlob(ctx, store, cur)
		if err != nil {
			return nil, fmt.Errorf("reading control %s: %w", cur, err)
		}
		blobs = append(blobs, blob)
		if cur == genesis || cp != nil && cur == cp.Digest {
			break
		}
		if len(blobs) > maxChain {
			return nil, invalid("control chain is too long")
		}
		s, err := DecodeSigned(blob)
		if err != nil {
			return nil, err
		}
		c, err := decodeControl(s.Body)
		if err != nil {
			return nil, err
		}
		if c.Generation == 0 || cp != nil && c.Generation <= cp.Generation {
			// Reached the bottom, or went below the checkpoint, without meeting
			// a trusted digest: this chain does not descend from what we trust.
			if cp != nil && c.Generation <= cp.Generation {
				return nil, fmt.Errorf("%w: control chain does not include accepted generation %d", ErrRollback, cp.Generation)
			}
			return nil, invalid("control chain does not start at the trusted genesis")
		}
		cur = c.Previous
	}
	// Anchor: the oldest blob read is trusted by its digest.
	anchor := blobs[len(blobs)-1]
	var prev *Verified
	if digest.FromBytes(anchor) == genesis {
		if prev, err = VerifyGenesis(workspace, anchor, genesis); err != nil {
			return nil, err
		}
	} else {
		s, err := DecodeSigned(anchor)
		if err != nil {
			return nil, err
		}
		c, err := decodeControl(s.Body)
		if err != nil {
			return nil, err
		}
		if c.Workspace != workspace || c.Generation != cp.Generation {
			return nil, fmt.Errorf("%w: checkpoint control does not match the recorded generation", ErrRollback)
		}
		prev = &Verified{Control: c, Digest: cp.Digest}
	}
	for i := len(blobs) - 2; i >= 0; i-- {
		if prev, err = VerifyNext(prev, blobs[i]); err != nil {
			return nil, err
		}
	}
	if cp != nil && prev.Generation < cp.Generation {
		return nil, fmt.Errorf("%w: head generation %d is older than accepted %d", ErrRollback, prev.Generation, cp.Generation)
	}
	return &Head{Verified: prev, Version: version}, nil
}

// CreateControl publishes the genesis Control. It fails with
// storage.ErrConflict when a Control already exists.
func CreateControl(ctx context.Context, store *storage.Store, workspace string, founder Principal, signer signing.Signer) (*Verified, error) {
	founder.Admin = true
	blob, err := SignControl(Control{Workspace: workspace, Principals: []Principal{founder}, Author: founder.ID}, signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyGenesis(workspace, blob, digest.FromBytes(blob))
	if err != nil {
		return nil, err
	}
	if err := putControl(ctx, store, blob, ""); err != nil {
		return nil, err
	}
	return v, nil
}

func putControl(ctx context.Context, store *storage.Store, blob []byte, expected storage.Version) error {
	d, err := store.Blobs.Put(ctx, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	return store.Refs.Put(ctx, ControlRef, d, expected)
}

// UpdateControl signs and publishes the successor of head. mutate edits the
// principal list. signer must be an admin of head; otherwise the result could
// never verify, so it is refused before anything is written.
func UpdateControl(ctx context.Context, store *storage.Store, head *Head, signer signing.Signer, mutate func(*Control) error) (*Verified, error) {
	next := head.Control
	next.Principals = append([]Principal(nil), head.Principals...)
	next.Generation++
	next.Previous = head.Digest
	next.Author = signer.Public().DeviceID()
	if a, ok := head.Principal(next.Author); !ok || !a.Admin {
		return nil, errors.New("only an admin can change the workspace control")
	}
	if err := mutate(&next); err != nil {
		return nil, err
	}
	blob, err := SignControl(next, signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyNext(head.Verified, blob)
	if err != nil {
		return nil, err
	}
	if err := putControl(ctx, store, blob, head.Version); err != nil {
		return nil, err
	}
	return v, nil
}

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

// maxChain bounds how many controls one load walks, and maxChainBytes how many
// bytes it reads in total. Both are variables so tests can lower them.
var (
	maxChain      = 10000
	maxChainBytes = 32 << 20
)

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

// readBlob returns the bytes stored under d, refusing anything larger than
// limit. The storage layer already checks the digest at end of stream; checking
// again here keeps the protocol from depending on every backend doing so, since
// these bytes become trust anchors.
func readBlob(ctx context.Context, store *storage.Store, d digest.Digest, limit int) ([]byte, error) {
	rc, err := store.Blobs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, invalid("blob %s exceeds %d bytes", d, limit)
	}
	if digest.FromBytes(data) != d {
		return nil, invalid("blob does not match its digest %s", d)
	}
	return data, nil
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
	total := 0
	for cur := d; ; {
		blob, err := readBlob(ctx, store, cur, MaxSignedBytes)
		if err != nil {
			return nil, fmt.Errorf("reading control %s: %w", cur, err)
		}
		blobs = append(blobs, blob)
		total += len(blob)
		if cur == genesis || cp != nil && cur == cp.Digest {
			break
		}
		if len(blobs) > maxChain || total > maxChainBytes {
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
	// Anchor: the oldest blob read is trusted only because its digest equals the
	// genesis or the checkpoint, so decide by the digest of the bytes themselves.
	anchor := blobs[len(blobs)-1]
	anchorDigest := digest.FromBytes(anchor)
	var prev *Verified
	switch {
	case anchorDigest == genesis:
		if prev, err = VerifyGenesis(workspace, anchor, genesis); err != nil {
			return nil, err
		}
	case cp != nil && anchorDigest == cp.Digest:
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
	default:
		return nil, invalid("control chain does not end at a trusted digest")
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

// ControlAt returns the control of the given generation and digest from the
// verified chain behind head. It is for judging an old state against the
// control it was written under.
//
// No signatures are checked again: head is verified, and each older control is
// named by the Previous digest inside the one after it, so its digest already
// fixes its content. Reading stops at the requested generation.
func ControlAt(ctx context.Context, store *storage.Store, head *Verified, generation uint64, d digest.Digest) (*Verified, error) {
	switch {
	case generation > head.Generation:
		return nil, invalid("control generation %d is newer than the verified head %d", generation, head.Generation)
	case generation == head.Generation:
		if d != head.Digest {
			return nil, invalid("control digest does not match generation %d", generation)
		}
		return head, nil
	}
	cur, gen, total := head.Previous, head.Generation-1, 0
	for steps := 0; ; steps++ {
		blob, err := readBlob(ctx, store, cur, MaxSignedBytes)
		if err != nil {
			return nil, fmt.Errorf("reading control %s: %w", cur, err)
		}
		if total += len(blob); steps >= maxChain || total > maxChainBytes {
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
		if c.Generation != gen {
			return nil, invalid("control %s is generation %d, expected %d", cur, c.Generation, gen)
		}
		if gen == generation {
			if cur != d {
				return nil, invalid("control digest does not match generation %d", generation)
			}
			return &Verified{Control: c, Digest: cur}, nil
		}
		cur, gen = c.Previous, gen-1
	}
}

// NewGenesis signs the genesis Control for a workspace founded by founder and
// returns its stored bytes and digest, without publishing anything. A caller
// that must record the digest locally can do that first and publish afterwards,
// so a failure to record it never leaves a published control nobody trusts.
func NewGenesis(workspace string, founder Principal, signer signing.Signer) ([]byte, digest.Digest, error) {
	founder.Admin = true
	blob, err := SignControl(Control{Workspace: workspace, Principals: []Principal{founder}, Author: founder.ID}, signer)
	if err != nil {
		return nil, "", err
	}
	d := digest.FromBytes(blob)
	if _, err := VerifyGenesis(workspace, blob, d); err != nil {
		return nil, "", err
	}
	return blob, d, nil
}

// PublishGenesis stores a genesis Control from NewGenesis. It fails with
// storage.ErrConflict when a Control already exists.
func PublishGenesis(ctx context.Context, store *storage.Store, blob []byte) error {
	return putControl(ctx, store, blob, "")
}

// CreateControl signs and publishes the genesis Control.
func CreateControl(ctx context.Context, store *storage.Store, workspace string, founder Principal, signer signing.Signer) (*Verified, error) {
	blob, d, err := NewGenesis(workspace, founder, signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyGenesis(workspace, blob, d)
	if err != nil {
		return nil, err
	}
	if err := PublishGenesis(ctx, store, blob); err != nil {
		return nil, err
	}
	return v, nil
}

func putControl(ctx context.Context, store *storage.Store, blob []byte, expected storage.Version) error {
	d, err := store.Blobs.Put(ctx, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	// The ref is about to name this digest, so it must be the digest of our bytes.
	if d != digest.FromBytes(blob) {
		return fmt.Errorf("storage stored the control under a different digest %s", d)
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

package commit

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func addCommit(t *testing.T, objects map[digest.Digest][]byte, signer testSigner, value Commit) digest.Digest {
	t.Helper()
	encoded, objectDigest := signForTest(t, value, signer)
	objects[objectDigest] = encoded
	return objectDigest
}

func TestDAGLinearForkAndMerge(t *testing.T) {
	signer := newTestSigner(2, 7)
	objects := make(map[digest.Digest][]byte)
	root := addCommit(t, objects, signer, baseCommit(0, nil))
	left := addCommit(t, objects, signer, baseCommit(1, []digest.Digest{root}))
	right := addCommit(t, objects, signer, baseCommit(2, []digest.Digest{root}))

	fork, err := BuildDAG(context.Background(), objects, resolverFor(signer))
	if err != nil {
		t.Fatalf("BuildDAG fork: %v", err)
	}
	wantFrontier := []digest.Digest{left, right}
	sortDigests(wantFrontier)
	if got := fork.Frontier(); !slices.Equal(got, wantFrontier) {
		t.Fatalf("fork frontier = %v, want %v", got, wantFrontier)
	}
	for range 10 {
		if got := fork.Frontier(); !slices.Equal(got, wantFrontier) {
			t.Fatalf("frontier is nondeterministic: %v", got)
		}
	}
	if fork.WorkspaceID() != testUUID(1) || fork.Root() != root || fork.Len() != 3 {
		t.Fatalf("DAG metadata = workspace %s root %s len %d", fork.WorkspaceID(), fork.Root(), fork.Len())
	}
	if reachable, reachErr := fork.Reachable(left, root); reachErr != nil || !reachable {
		t.Fatalf("left -> root reachable = %v, error %v", reachable, reachErr)
	}
	if reachable, reachErr := fork.Reachable(left, right); reachErr != nil || reachable {
		t.Fatalf("left -> right reachable = %v, error %v", reachable, reachErr)
	}
	if reachable, reachErr := fork.Reachable(root, root); reachErr != nil || !reachable {
		t.Fatalf("root -> root reachable = %v, error %v", reachable, reachErr)
	}
	if _, reachErr := fork.Reachable(left, digest.FromString("unknown")); !errors.Is(reachErr, ErrCommitNotFound) {
		t.Fatalf("unknown reachability error = %v", reachErr)
	}

	merge := addCommit(t, objects, signer, baseCommit(3, []digest.Digest{right, left}))
	merged, err := BuildDAG(context.Background(), objects, resolverFor(signer))
	if err != nil {
		t.Fatalf("BuildDAG merged: %v", err)
	}
	if got := merged.Frontier(); !slices.Equal(got, []digest.Digest{merge}) {
		t.Fatalf("merged frontier = %v, want %v", got, []digest.Digest{merge})
	}
	reachable, err := merged.ReachableFrom(merge)
	if err != nil {
		t.Fatalf("ReachableFrom: %v", err)
	}
	wantReachable := []digest.Digest{root, left, right, merge}
	sortDigests(wantReachable)
	if !slices.Equal(reachable, wantReachable) {
		t.Fatalf("reachable = %v, want %v", reachable, wantReachable)
	}
	bases, err := merged.MergeBases(left, merge)
	if err != nil {
		t.Fatalf("MergeBases: %v", err)
	}
	if !slices.Equal(bases, []digest.Digest{left}) {
		t.Fatalf("merge bases = %v, want %v", bases, []digest.Digest{left})
	}

	copyOfMerge, ok := merged.Commit(merge)
	if !ok {
		t.Fatal("merged commit not found")
	}
	copyOfMerge.Parents[0] = root
	secondCopy, _ := merged.Commit(merge)
	if secondCopy.Parents[0] == root || secondCopy.Parents[1] == root {
		t.Fatal("DAG.Commit exposed mutable parent storage")
	}
}

func TestDAGRetainsMultipleMergeBases(t *testing.T) {
	signer := newTestSigner(2, 7)
	objects := make(map[digest.Digest][]byte)
	root := addCommit(t, objects, signer, baseCommit(0, nil))
	baseA := addCommit(t, objects, signer, baseCommit(1, []digest.Digest{root}))
	baseB := addCommit(t, objects, signer, baseCommit(2, []digest.Digest{root}))
	left := addCommit(t, objects, signer, baseCommit(3, []digest.Digest{baseB, baseA}))
	right := addCommit(t, objects, signer, baseCommit(4, []digest.Digest{baseA, baseB}))

	dag, err := BuildDAG(context.Background(), objects, resolverFor(signer))
	if err != nil {
		t.Fatalf("BuildDAG: %v", err)
	}
	wantBases := []digest.Digest{baseA, baseB}
	sortDigests(wantBases)
	bases, err := dag.MergeBases(left, right)
	if err != nil {
		t.Fatalf("MergeBases: %v", err)
	}
	if !slices.Equal(bases, wantBases) {
		t.Fatalf("merge bases = %v, want %v", bases, wantBases)
	}
	wantFrontier := []digest.Digest{left, right}
	sortDigests(wantFrontier)
	if got := dag.Frontier(); !slices.Equal(got, wantFrontier) {
		t.Fatalf("frontier = %v, want %v", got, wantFrontier)
	}
}

func TestBuildDAGRejectsInvalidHistories(t *testing.T) {
	signer := newTestSigner(2, 7)
	resolver := resolverFor(signer)

	t.Run("empty", func(t *testing.T) {
		if _, err := BuildDAG(context.Background(), nil, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		encoded, _ := signForTest(t, baseCommit(0, nil), signer)
		objects := map[digest.Digest][]byte{digest.FromString("wrong"): encoded}
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrCommitDigestMismatch) {
			t.Fatalf("error = %v, want %v", err, ErrCommitDigestMismatch)
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		objects := make(map[digest.Digest][]byte)
		addCommit(t, objects, signer, baseCommit(1, []digest.Digest{digest.FromString("missing")}))
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})

	t.Run("invalid embedded enrollment binding", func(t *testing.T) {
		encoded, objectDigest := signForTest(t, baseCommit(0, nil), signer)
		invalid := resolverFor(signer)
		invalid.claims.Ed25519PublicKey = newTestSigner(4, 9).SigningPublicKey()
		if _, err := BuildDAG(context.Background(), map[digest.Digest][]byte{objectDigest: encoded}, invalid); !errors.Is(err, ErrSigningKeyBinding) || !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want binding and DAG errors", err)
		}
	})

	t.Run("workspace mismatch", func(t *testing.T) {
		objects := make(map[digest.Digest][]byte)
		root := addCommit(t, objects, signer, baseCommit(0, nil))
		child := baseCommit(1, []digest.Digest{root})
		child.WorkspaceID = testUUID(99)
		addCommit(t, objects, signer, child)
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})

	t.Run("duplicate operation", func(t *testing.T) {
		objects := make(map[digest.Digest][]byte)
		rootCommit := baseCommit(0, nil)
		root := addCommit(t, objects, signer, rootCommit)
		child := baseCommit(1, []digest.Digest{root})
		child.OperationID = rootCommit.OperationID
		addCommit(t, objects, signer, child)
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})

	t.Run("multiple initialization roots", func(t *testing.T) {
		objects := make(map[digest.Digest][]byte)
		addCommit(t, objects, signer, baseCommit(0, nil))
		secondRoot := baseCommit(1, nil)
		secondRoot.Provenance[0].ID = testUUID(9090)
		addCommit(t, objects, signer, secondRoot)
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})

	t.Run("signature tamper", func(t *testing.T) {
		encoded, objectDigest := signForTest(t, baseCommit(0, nil), signer)
		decoded, decodeErr := DecodeSignedCommit(encoded)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		decoded.Signature[0] ^= 0xff
		tampered, marshalErr := artifact.MarshalCanonical(decoded)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		objects := map[digest.Digest][]byte{objectDigest: tampered}
		if _, err := BuildDAG(context.Background(), objects, resolver); !errors.Is(err, ErrInvalidCommitDAG) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
		}
	})
}

func TestValidateAcyclicRejectsCycle(t *testing.T) {
	a := digest.FromString("a")
	b := digest.FromString("b")
	parents := map[digest.Digest][]digest.Digest{a: {b}, b: {a}}
	children := map[digest.Digest][]digest.Digest{a: {b}, b: {a}}
	if err := validateAcyclic(parents, children); !errors.Is(err, ErrInvalidCommitDAG) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidCommitDAG)
	}
}

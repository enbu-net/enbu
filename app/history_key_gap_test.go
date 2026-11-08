package app

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/opencontainers/go-digest"
)

func TestHistoryPreservesAncestryAcrossUnreadableRevisions(t *testing.T) {
	for _, backward := range []bool{false, true} {
		for _, gap := range []int{1, 2} {
			t.Run(fmt.Sprintf("backward-%t/gap-%d", backward, gap), func(t *testing.T) {
				currentKey, historicalKey := mustKeyPair(t), mustKeyPair(t)
				a := newTestApp(t, "owner", "repo", "default", currentKey, nil)
				s, err := a.openSession(bg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				workspace := mustWorkspace(t, a)
				at := int64(1000)
				if backward {
					at = 4000
				}
				publish := func(recipient string, values map[string]string, parents ...digest.Digest) digest.Digest {
					cipher, err := age.EncryptForPublicKeys(encodeSecrets(values), []string{recipient})
					if err != nil {
						t.Fatal(err)
					}
					rev := publishRevisionAt(t, a.Storage, a, workspace, s.resource("default"), s.head.Digest, cipher, at, parents...)
					if backward {
						at -= 1000
					}
					return rev
				}
				oldValues := map[string]string{"OLD_ONLY": "old", "CHANGED": "old"}
				old := publish(currentKey.PublicKey, oldValues)
				parent := old
				for range gap {
					// This client has lost the key for these historical revisions.
					parent = publish(historicalKey.PublicKey, map[string]string{"HIDDEN": "not readable"}, parent)
				}
				latest := publish(currentKey.PublicKey, map[string]string{"NEW_ONLY": "new", "CHANGED": "new"}, parent)
				entries, err := a.ListHistory(bg, "default")
				if err != nil || len(entries) != 2 || entries[0].Tag != old.Encoded() || entries[1].Tag != latest.Encoded() {
					t.Fatalf("history lost ancestry through an unreadable key epoch: entries=%v error=%v", entries, err)
				}
				diff, err := a.DiffHistory(bg, "default", 1, 2)
				want := &Diff{Added: []string{"NEW_ONLY"}, Removed: []string{"OLD_ONLY"}, Modified: []string{"CHANGED"}}
				if err != nil || !reflect.DeepEqual(diff, want) {
					t.Fatalf("history indices reversed the diff: got=%+v want=%+v error=%v", diff, want, err)
				}
				if err := a.RestoreHistory(bg, "default", 1); err != nil {
					t.Fatal(err)
				}
				values, err := a.ListSecrets(bg, "default")
				if err != nil || !reflect.DeepEqual(values, oldValues) {
					t.Fatalf("restoring index 1 selected the wrong side of the key gap: %v", err)
				}
			})
		}
	}
}

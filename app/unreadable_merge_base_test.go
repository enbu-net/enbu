package app

import (
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestNewMemberMergesWithoutHistoricalDecryptionKey(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		deleted     bool
	}{{"same", "v1", false}, {"edit", "restored", false}, {"empty", "", false}, {"delete", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.value
			alice := newAlice(t)
			s, err := alice.openSession(bg)
			if err != nil {
				t.Fatal(err)
			}
			resource := s.resource("default")
			read, err := s.readResource(bg, resource, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			parents := read.parents()
			s.Close()
			bob := approved(t, alice)
			// Approval publishes v1 for Bob. A concurrent restore also
			// publishes for Bob but branches from the pre-approval revision.
			s, err = alice.openSession(bg)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{}
			if !tc.deleted {
				want["KEY"] = value
			}
			_, err = s.writeState(bg, resource, want, parents)
			s.Close()
			if err != nil {
				t.Fatal(err)
			}
			got, err := bob.ListSecrets(bg, "default")
			if tc.name == "same" {
				if err != nil || got["KEY"] != "v1" {
					t.Fatalf("identical heads need no historical key: %v %v", got, err)
				}
			} else {
				if !apperr.Is(err, apperr.CodeSecretConflict) {
					t.Fatalf("unknown base must preserve competing values: %v", err)
				}
				set, err := bob.ListConflicts(bg, "default")
				if err != nil || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "KEY" {
					t.Fatalf("missing conflict: %+v %v", set, err)
				}
				candidates := set.Conflicts[0].Candidates
				actual := map[ConflictCandidate]bool{}
				for _, candidate := range candidates {
					actual[candidate] = true
				}
				expected := map[ConflictCandidate]bool{{Value: "v1"}: true, {Value: value, Deleted: tc.deleted}: true}
				if len(candidates) != 2 || !reflect.DeepEqual(actual, expected) {
					t.Fatalf("wrong conflict candidates: %+v", candidates)
				}
			}
			// An existing member can decrypt the base, infer the change,
			// and publish one merged head readable by the new member.
			if err := alice.SyncSecrets(bg, "default"); err != nil {
				t.Fatal(err)
			}
			got, err = bob.ListSecrets(bg, "default")
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("known-base sync failed to recover: %v %v", got, err)
			}
		})
	}
}

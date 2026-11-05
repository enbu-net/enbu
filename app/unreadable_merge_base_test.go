package app

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestNewMemberMergesWithoutHistoricalDecryptionKey(t *testing.T) {
	for _, value := range []string{"v1", "restored"} {
		t.Run(value, func(t *testing.T) {
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
			_, err = s.writeState(bg, resource, map[string]string{"KEY": value}, parents)
			s.Close()
			if err != nil {
				t.Fatal(err)
			}
			got, err := bob.ListSecrets(bg, "default")
			if value == "v1" {
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
				if len(candidates) != 2 || candidates[0].Value != "restored" || candidates[1].Value != "v1" {
					t.Fatalf("wrong conflict candidates: %+v", candidates)
				}
			}
			// An existing member can decrypt the base, infer the change,
			// and publish one merged head readable by the new member.
			if err := alice.SyncSecrets(bg, "default"); err != nil {
				t.Fatal(err)
			}
			got, err = bob.ListSecrets(bg, "default")
			if err != nil || got["KEY"] != value {
				t.Fatalf("known-base sync failed to recover: %v %v", got, err)
			}
		})
	}
}

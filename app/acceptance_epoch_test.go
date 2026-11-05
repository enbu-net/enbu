package app

import (
	"github.com/enbu-net/enbu/pkg/wsp"
	"testing"
)

func TestReadmittedObserverKeepsStateAcceptedInNewEpoch(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	carol := approved(t, alice)
	bobsEntry := principalOf(t, bob)
	bobsEntry.Admin = true
	carolsEntry := principalOf(t, carol)
	before, err := carol.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	oldControl := before.head.Digest
	before.Close()
	changeControl(t, alice, func(c *wsp.Control) {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			if p.ID != bobsEntry.ID {
				kept = append(kept, p)
			}
		}
		c.Principals = kept
	})
	changeControl(t, alice, func(c *wsp.Control) { c.Principals = append(c.Principals, bobsEntry) })
	current, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	read, err := current.readResource(bg, current.resource("default"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encryptForTest(current, map[string]string{"KEY": "v1", "CAROL": "accepted after readmission"})
	if err != nil {
		t.Fatal(err)
	}
	publishRevision(t, alice.Storage, carol, current.workspace, current.resource("default"), oldControl, raw, read.parents()...)
	current.Close()
	if got := listOK(t, bob); got["CAROL"] != "accepted after readmission" {
		t.Fatalf("readmitted observer: %v", got)
	}
	// Simulate a fresh process using the persisted acceptance epoch.
	restarted := *bob
	bob = &restarted
	if err := bob.RemoveMember(bg, string(carolsEntry.ID)); err != nil {
		t.Fatal(err)
	}
	for _, observer := range []*App{alice, bob} {
		if got := listOK(t, observer); got["CAROL"] != "accepted after readmission" {
			t.Fatalf("takeover lost accepted value: %v", got)
		}
	}
}

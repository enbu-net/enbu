package wsp

import (
	"fmt"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/opencontainers/go-digest"
	"sync"
	"testing"
)

func membershipHistory(n int) (*ControlView, digest.Digest, digest.Digest, signing.DeviceID) {
	id := signing.DeviceID("device")
	v := &ControlView{verified: map[digest.Digest]*Verified{}}
	var first, previous digest.Digest
	for i := 0; i < n; i++ {
		hash := d(fmt.Sprintf("epoch-%d", i))
		c := &Verified{Digest: hash, Control: Control{Principals: []Principal{{ID: id}}}}
		if i > 0 {
			c.Parents = []digest.Digest{previous}
		} else {
			first = hash
		}
		v.verified[hash] = c
		previous = hash
	}
	return v, previous, first, id
}
func TestMembershipMemoPreservesConcurrentResults(t *testing.T) {
	v, head, from, id := membershipHistory(100)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if !v.MembershipUnbroken(head, from, id) {
				t.Error("continuous member rejected")
			}
			if v.MembershipUnbroken(head, d("missing"), id) {
				t.Error("missing Control accepted")
			}
		})
	}
	wg.Wait()
	count := 0
	v.membership.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("expected one decision per distinct query, got %d", count)
	}
}
func BenchmarkMembershipUnbroken(b *testing.B) {
	v, head, from, id := membershipHistory(1000)
	for _, memo := range []bool{false, true} {
		b.Run(fmt.Sprintf("memo-%t", memo), func(b *testing.B) {
			for b.Loop() {
				var ok bool
				if memo {
					ok = v.MembershipUnbroken(head, from, id)
				} else {
					ok = v.membershipUnbroken(head, from, id)
				}
				if !ok {
					b.Fatal("continuous member rejected")
				}
			}
		})
	}
}

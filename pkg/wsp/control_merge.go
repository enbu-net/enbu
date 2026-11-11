package wsp

import (
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/opencontainers/go-digest"
)

// MergePrincipals computes the principals of the Control that joins heads, a
// 3-way merge of each head against their common ancestor (the base). get looks
// up any verified ancestor of the heads.
//
// The merge is deterministic, so a resolution is valid only when it lists
// exactly these principals:
//
//   - A branch is the Controls an ancestor of its head but not of the base. A
//     branch whose Controls were signed by an admin of the base that another
//     head no longer lists as an admin is discarded: its head counts as the
//     base. An admin that was removed or demoted on one branch cannot change
//     anything through a concurrent branch, even one forked from an older
//     Control.
//   - When every branch is discarded, as when two admins removed each other,
//     the merge keeps only what every head keeps: the principals every head
//     lists with the same recipient, each an admin only if an admin in every
//     head.
//   - A principal of the base stays only if every head still lists it; a
//     removal on any branch wins. It stays an admin only if every head keeps
//     it one, and it becomes one if any head made it one.
//   - A principal that is not in the base is added if any head added it, as
//     an admin only if every head that added it made it one.
//   - A principal whose recipient two branches changed differently, or that
//     two branches added with different recipients, is left out; an admin
//     approves it again.
//
// The result has at least one admin, or the merge fails.
func MergePrincipals(heads []*Verified, get func(digest.Digest) (*Verified, bool)) ([]Principal, error) {
	if len(heads) < 2 {
		return nil, invalid("a merge needs at least two heads")
	}
	ancestors := make([]map[digest.Digest]*Verified, len(heads))
	for i, h := range heads {
		a, err := controlAncestors(h, get)
		if err != nil {
			return nil, err
		}
		ancestors[i] = a
	}
	base := mergeBase(ancestors)
	if base == nil {
		return nil, invalid("the competing controls share no ancestor")
	}
	baseAncestors, err := controlAncestors(base, get)
	if err != nil {
		return nil, err
	}
	effective := make([]Control, len(heads))
	standing := 0
	for i, h := range heads {
		effective[i] = h.Control
		if branchStands(i, heads, ancestors[i], baseAncestors, base) {
			standing++
		} else {
			effective[i] = base.Control
		}
	}
	if standing == 0 {
		return intersection(heads)
	}
	ids := map[signing.DeviceID]bool{}
	for _, p := range base.Principals {
		ids[p.ID] = true
	}
	for _, c := range effective {
		for _, p := range c.Principals {
			ids[p.ID] = true
		}
	}
	var out []Principal
	for id := range ids {
		if p, ok := mergePrincipal(id, base.Control, effective); ok {
			out = append(out, p)
		}
	}
	merged := Control{Principals: out}.canonical()
	if requireAnAdmin(merged.Principals) != nil {
		return nil, invalid("the merged control has no admin")
	}
	return merged.Principals, nil
}

// branchStands reports whether the branch of head i counts. Every Control on
// it was signed by an admin of its parents; one signed by an admin of the base
// that another head removed or demoted is void, and so is the whole branch,
// since later Controls on it build on that one.
func branchStands(i int, heads []*Verified, ancestors, baseAncestors map[digest.Digest]*Verified, base *Verified) bool {
	for d, c := range ancestors {
		if baseAncestors[d] != nil {
			continue
		}
		author, ok := base.Principal(c.Author)
		if !ok || !author.Admin {
			continue
		}
		for j, other := range heads {
			if j == i {
				continue
			}
			if p, ok := other.Principal(c.Author); !ok || !p.Admin {
				return false
			}
		}
	}
	return true
}

func mergePrincipal(id signing.DeviceID, base Control, heads []Control) (Principal, bool) {
	b, inBase := base.Principal(id)
	var listed []Principal
	for _, h := range heads {
		if p, ok := h.Principal(id); ok {
			listed = append(listed, p)
		} else if inBase {
			return Principal{}, false // removed on a branch
		}
	}
	recipient := ""
	if inBase {
		recipient = b.Recipient
	}
	changed := ""
	for _, p := range listed {
		if p.Recipient == recipient {
			continue
		}
		if changed != "" && changed != p.Recipient {
			return Principal{}, false // changed differently on two branches
		}
		changed = p.Recipient
	}
	if changed != "" {
		recipient = changed
	}
	out := listed[0]
	out.Recipient = recipient
	if inBase && b.Admin {
		out.Admin = true
		for _, p := range listed {
			out.Admin = out.Admin && p.Admin // a demotion wins
		}
		return out, true
	}
	if inBase {
		out.Admin = false
		for _, p := range listed {
			out.Admin = out.Admin || p.Admin // a promotion counts
		}
		return out, true
	}
	out.Admin = true
	for _, p := range listed {
		out.Admin = out.Admin && p.Admin
	}
	return out, true
}

// mergeBase is the highest common ancestor of every head, the smallest digest
// among equal heights. A Control is higher than each of its parents, so it is
// never an ancestor of another common ancestor.
func mergeBase(ancestors []map[digest.Digest]*Verified) *Verified {
	var base *Verified
	for d, c := range ancestors[0] {
		common := true
		for _, a := range ancestors[1:] {
			if a[d] == nil {
				common = false
				break
			}
		}
		if !common {
			continue
		}
		if base == nil || c.Height > base.Height || (c.Height == base.Height && d < base.Digest) {
			base = c
		}
	}
	return base
}

func controlAncestors(head *Verified, get func(digest.Digest) (*Verified, bool)) (map[digest.Digest]*Verified, error) {
	out := map[digest.Digest]*Verified{}
	queue := []*Verified{head}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if out[c.Digest] != nil {
			continue
		}
		out[c.Digest] = c
		for _, p := range c.Parents {
			parent, ok := get(p)
			if !ok {
				return nil, invalid("control %s names a parent %s that is not verified", c.Digest, p)
			}
			queue = append(queue, parent)
		}
	}
	return out, nil
}

func intersection(heads []*Verified) ([]Principal, error) {
	var out []Principal
	for _, p := range heads[0].Principals {
		kept := true
		for _, h := range heads[1:] {
			q, ok := h.Principal(p.ID)
			kept = kept && ok && q.Recipient == p.Recipient
			p.Admin = p.Admin && ok && q.Admin
		}
		if kept {
			out = append(out, p)
		}
	}
	merged := Control{Principals: out}.canonical()
	if requireAnAdmin(merged.Principals) != nil {
		return nil, invalid("the merged control has no admin")
	}
	return merged.Principals, nil
}

func requireAnAdmin(ps []Principal) error {
	for _, p := range ps {
		if p.Admin {
			return nil
		}
	}
	return invalid("control has no admin")
}

// samePrincipals reports whether a and b, both sorted by ID, list the same
// principals with the same keys and roles.
func samePrincipals(a, b []Principal) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Signing.DeviceID() != b[i].Signing.DeviceID() || a[i].Recipient != b[i].Recipient || a[i].Admin != b[i].Admin {
			return false
		}
	}
	return true
}

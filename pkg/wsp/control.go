package wsp

import (
	"sort"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/opencontainers/go-digest"
)

const MaxPrincipals = 1024

// Principal is a trusted device. Admin is only membership management for v1;
// it is not a data-access permission and must not become one.
type Principal struct {
	ID        signing.DeviceID  `cbor:"id"`
	Signing   signing.PublicKey `cbor:"signing"`
	Recipient string            `cbor:"recipient"`
	Admin     bool              `cbor:"admin"`
}

// Control lists the principals trusted by a workspace. Controls form a DAG:
// a normal update has one parent, a fork resolution names every head it joins.
type Control struct {
	Workspace  string           `cbor:"workspace"`
	Parents    []digest.Digest  `cbor:"parents"` // sorted, unique; empty only at genesis
	Height     uint64           `cbor:"height"`  // a hint for display; never used for security
	Principals []Principal      `cbor:"principals"`
	Author     signing.DeviceID `cbor:"author"`
}

// Verified is a Control whose signature chain has been checked. Digest is the
// digest of the stored SignedControl bytes.
type Verified struct {
	Control
	Digest digest.Digest
}

func (c Control) Principal(id signing.DeviceID) (Principal, bool) {
	for _, p := range c.Principals {
		if p.ID == id {
			return p, true
		}
	}
	return Principal{}, false
}

// Recipients returns the age recipients of every principal. It is the only
// source of the encryption recipient set.
func (c Control) Recipients() []string {
	out := make([]string, len(c.Principals))
	for i, p := range c.Principals {
		out[i] = p.Recipient
	}
	return out
}

// Validate checks the structure of a Control, independent of who signed it.
func (c Control) Validate() error {
	if c.Workspace == "" {
		return invalid("control has no workspace")
	}
	if len(c.Parents) == 0 {
		if c.Height != 0 {
			return invalid("genesis control has a height")
		}
	} else if c.Height == 0 {
		return invalid("control with parents has height 0")
	}
	if len(c.Parents) > MaxPrincipals {
		return invalid("control has too many parents")
	}
	for i, p := range c.Parents {
		if err := validDigest(p); err != nil {
			return invalid("control parent: %v", err)
		}
		if i > 0 && c.Parents[i-1] >= p {
			return invalid("control parents must be sorted and unique")
		}
	}
	if err := c.Author.Validate(); err != nil {
		return invalid("control author: %v", err)
	}
	if n := len(c.Principals); n == 0 || n > MaxPrincipals {
		return invalid("control must have 1..%d principals", MaxPrincipals)
	}
	admins := 0
	for i, p := range c.Principals {
		if i > 0 && c.Principals[i-1].ID >= p.ID {
			return invalid("principals must be sorted by unique device id")
		}
		if err := p.Signing.Validate(); err != nil {
			return invalid("principal %s: %v", p.ID, err)
		}
		// A device id names exactly one key; anything else is a swapped key.
		if p.ID != p.Signing.DeviceID() {
			return invalid("principal %s does not match its signing key", p.ID)
		}
		if _, err := age.ParseRecipient(p.Recipient); err != nil {
			return invalid("principal %s recipient: %v", p.ID, err)
		}
		if p.Admin {
			admins++
		}
	}
	if admins == 0 {
		return invalid("control has no admin")
	}
	return nil
}

func validDigest(d digest.Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if d.Algorithm() != digest.SHA256 {
		return invalid("unsupported digest algorithm")
	}
	return nil
}

// Canonical sorts principals so equal sets share one encoding.
func (c Control) canonical() Control {
	c.Principals = append([]Principal(nil), c.Principals...)
	sort.Slice(c.Principals, func(i, j int) bool { return c.Principals[i].ID < c.Principals[j].ID })
	return c
}

// SignControl signs c with signer, which must be c.Author, and returns the
// SignedControl bytes as stored.
func SignControl(c Control, signer signing.Signer) ([]byte, error) {
	c = c.canonical()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if signer.Public().DeviceID() != c.Author {
		return nil, invalid("signer is not the control author")
	}
	body, err := encMode.Marshal(c)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainControl, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

func decodeControl(body []byte) (Control, error) {
	var c Control
	if err := decodeCanonical(body, &c); err != nil {
		return Control{}, err
	}
	if err := c.Validate(); err != nil {
		return Control{}, err
	}
	return c, nil
}

// VerifyGenesis accepts a genesis SignedControl whose stored digest is the
// trusted one from the bootstrap information. The author must be an admin and
// signs with its own key listed in the control.
func VerifyGenesis(workspace string, blob []byte, trusted digest.Digest) (*Verified, error) {
	if d := digest.FromBytes(blob); d != trusted {
		return nil, invalid("genesis control digest %s does not match the trusted %s", d, trusted)
	}
	s, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	c, err := decodeControl(s.Body)
	if err != nil {
		return nil, err
	}
	if len(c.Parents) != 0 || c.Workspace != workspace {
		return nil, invalid("not the genesis control of this workspace")
	}
	author, ok := c.Principal(c.Author)
	if !ok || !author.Admin {
		return nil, invalid("genesis author is not an admin of the control")
	}
	if err := signing.Verify(author.Signing, signing.DomainControl, s.Body, s.Signature); err != nil {
		return nil, invalid("genesis signature: %v", err)
	}
	return &Verified{Control: c, Digest: trusted}, nil
}

// VerifyChild verifies blob as a Control whose parents are all verified. Its
// legitimacy comes from them: the author must be an admin of every parent and
// the signature must verify under that admin's key. A Control with several
// parents resolves a fork and must list exactly the principals MergePrincipals
// computes from them; get looks up their verified ancestors and is used only
// then.
func VerifyChild(parents []*Verified, blob []byte, get func(digest.Digest) (*Verified, bool)) (*Verified, error) {
	if len(parents) == 0 {
		return nil, invalid("control has no parent")
	}
	s, err := DecodeSigned(blob)
	if err != nil {
		return nil, err
	}
	c, err := decodeControl(s.Body)
	if err != nil {
		return nil, err
	}
	want := make([]digest.Digest, len(parents))
	height := uint64(0)
	for i, p := range parents {
		want[i] = p.Digest
		if c.Workspace != p.Workspace {
			return nil, invalid("control belongs to another workspace")
		}
		height = max(height, p.Height)
	}
	sortDigests(want)
	if len(c.Parents) != len(want) {
		return nil, invalid("control does not name its parents")
	}
	for i := range want {
		if c.Parents[i] != want[i] {
			return nil, invalid("control does not name its parents")
		}
	}
	if c.Height != height+1 {
		return nil, invalid("control height %d does not follow %d", c.Height, height)
	}
	var key signing.PublicKey
	for _, p := range parents {
		author, ok := p.Principal(c.Author)
		if !ok || !author.Admin {
			return nil, invalid("control author %s is not an admin of parent %s", c.Author, p.Digest)
		}
		key = author.Signing
	}
	if err := signing.Verify(key, signing.DomainControl, s.Body, s.Signature); err != nil {
		return nil, invalid("control signature: %v", err)
	}
	if len(parents) > 1 {
		if err := checkResolution(parents, c, get); err != nil {
			return nil, err
		}
	}
	return &Verified{Control: c, Digest: digest.FromBytes(blob)}, nil
}

// checkResolution requires a resolution to list exactly the 3-way merge of its
// parents, so whoever signs it decides nothing: every admin of all heads would
// publish the same principals.
func checkResolution(parents []*Verified, c Control, get func(digest.Digest) (*Verified, bool)) error {
	if get == nil {
		return invalid("resolution cannot be checked without its ancestors")
	}
	heads := append([]*Verified(nil), parents...)
	sortVerified(heads)
	want, err := MergePrincipals(heads, get)
	if err != nil {
		return err
	}
	if !samePrincipals(c.canonical().Principals, want) {
		return invalid("resolution does not list the merge of its parents")
	}
	return nil
}

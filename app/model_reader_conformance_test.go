package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/internal/tla"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

// The reader conformance test lets TLC enumerate every read the StateDAG
// model can reach in a small configuration, then rebuilds each one with real
// signed Controls and revisions and runs the app's reader on it: the
// verification of what storage shows (wsp.LoadStates), the checkpoint, and
// the choice of trusted heads. Outcome, adopted heads and the checkpoint
// afterwards must match the model's.
//
// ENBU_MODEL_MUTANT selects a model variant; "before-fixes" is the reader
// before F1 and F2 were fixed (see spec/INVARIANTS.md).

const readerConformanceConfig = `CONSTANTS
    Writers = {"a", "b"}
    Compromised = {"r"}
    Reader = "a"
    Members <- %s
    MaxRevisions = 3
    MaxAttacks = 1
    MaxGen = %d
    Compaction = FALSE
    Witnessing = FALSE
    Conformance = TRUE
    Mutant = "%s"
SPECIFICATION Spec
CHECK_DEADLOCK FALSE
`

var canonicalCBOR = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

const conformanceWorkspace = "0192f3a0-7c1e-7a55-9d3c-5f6a1b2c3d4e"
const conformanceResource = "secrets/conformance"

type modelDevice struct {
	signer    signing.Signer
	recipient string
}

func newModelDevice(t *testing.T) modelDevice {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := agecrypto.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return modelDevice{signer: signing.NewEd25519Signer(k), recipient: id.Recipient().String()}
}

func (d modelDevice) id() signing.DeviceID { return d.signer.Public().DeviceID() }

// modelWorld holds the real keys and Controls behind the model's names.
type modelWorld struct {
	devices  map[string]modelDevice
	forger   modelDevice
	controls [][]byte // controls[i] is the (i+1)-th Control of the chain
	digests  []digest.Digest
}

func newModelWorld(t *testing.T, members [][]string) *modelWorld {
	t.Helper()
	w := &modelWorld{devices: map[string]modelDevice{}, forger: newModelDevice(t)}
	for _, name := range []string{"a", "b", "r"} {
		w.devices[name] = newModelDevice(t)
	}
	admin := w.devices["a"]
	for i, set := range members {
		c := wsp.Control{Workspace: conformanceWorkspace, Height: uint64(i), Author: admin.id()}
		if i > 0 {
			c.Parents = []digest.Digest{w.digests[i-1]}
		}
		for _, name := range set {
			d := w.devices[name]
			c.Principals = append(c.Principals, wsp.Principal{ID: d.id(), Signing: d.signer.Public(), Recipient: d.recipient, Admin: name == "a"})
		}
		blob, err := wsp.SignControl(c, admin.signer)
		if err != nil {
			t.Fatal(err)
		}
		w.controls = append(w.controls, blob)
		w.digests = append(w.digests, digest.FromBytes(blob))
	}
	return w
}

// modelRev is a revision of the model's store.
type modelRev struct {
	id, gen, ctl int64
	parents      []int64 // -1 is a digest no revision has
	author       string
	sig          bool
}

func (r modelRev) String() string {
	how := "signed"
	if !r.sig {
		how = "forged"
	}
	return fmt.Sprintf("#%d{parents %v gen %d ctl %d %s by %s}", r.id, r.parents, r.gen, r.ctl, how, r.author)
}

// revision builds the stored bytes of a model revision. digests maps model
// ids to the digests of revisions built before it.
func (w *modelWorld) revision(r modelRev, digests map[int64]digest.Digest) (blob, ciphertext []byte, err error) {
	var parents []digest.Digest
	for _, p := range r.parents {
		if p == -1 {
			parents = append(parents, digest.FromString("a parent no revision has"))
			continue
		}
		parents = append(parents, digests[p])
	}
	control := digest.FromString("a control the reader does not know")
	if int(r.ctl) <= len(w.digests) {
		control = w.digests[r.ctl-1]
	}
	author := w.devices[r.author]
	signer := author.signer
	if !r.sig {
		signer = w.forger.signer // claims the author, signed by another key
	}
	ciphertext = []byte(fmt.Sprintf("ciphertext of revision %d", r.id))
	st := wsp.State{Workspace: conformanceWorkspace, Resource: conformanceResource, Parents: parents,
		Generation: uint64(r.gen), Op: wsp.OpWrite, Control: control,
		Ciphertext: digest.FromBytes(ciphertext), Author: author.id(), CreatedAt: 1700000000 + r.id}
	sort.Slice(st.Parents, func(i, j int) bool { return st.Parents[i] < st.Parents[j] })
	st.Parents = slices.Compact(st.Parents)
	// Encoded like wsp.SignState, but without its validation: the model also
	// writes revisions the reader must refuse.
	body, err := canonicalCBOR.Marshal(st)
	if err != nil {
		return nil, nil, err
	}
	sig, err := signer.Sign(signing.DomainState, body)
	if err != nil {
		return nil, nil, err
	}
	blob, err = wsp.Signed{Body: body, Signature: sig}.Encode()
	return blob, ciphertext, err
}

type readerCase struct {
	now      int
	revs     []modelRev // every revision in the model's store, by id
	view     []int64
	cpBefore int64
	res      string
	heads    []int64
	cpAfter  int64
}

// key is everything a read depends on: the Control, the checkpoint, and the
// revisions storage shows. A parent it does not show is just missing,
// whatever revision it is.
func (c readerCase) key() string {
	var shown []string
	for _, r := range c.revs {
		if slices.Contains(c.view, r.id) {
			shown = append(shown, r.String())
		}
	}
	return fmt.Sprintf("%d|%d|%v", c.now, c.cpBefore, shown)
}

// readerCases runs the model and collects every distinct read it reaches.
func readerCases(t *testing.T, cfg string) (states int, out []readerCase) {
	t.Helper()
	seen := map[string]bool{}
	states = tla.DumpEach(t, "MCStateDAG.tla", cfg, func(s tla.State) {
		last := tla.Rec(t, s["lastRead"])
		if tla.Str(t, last["res"]) == "none" {
			return
		}
		var revs []modelRev
		for _, v := range tla.Elems(t, s["store"]) {
			r := tla.Rec(t, v)
			revs = append(revs, modelRev{id: tla.Int(t, r["id"]), gen: tla.Int(t, r["gen"]), ctl: tla.Int(t, r["ctl"]),
				parents: tla.Ints(t, r["parents"]), author: tla.Str(t, r["author"]), sig: tla.Bool(t, r["sig"])})
		}
		sort.Slice(revs, func(i, j int) bool { return revs[i].id < revs[j].id })
		c := readerCase{now: int(tla.Int(t, last["now"])), revs: revs, view: tla.Ints(t, last["view"]),
			cpBefore: tla.Int(t, last["cpBefore"]), res: tla.Str(t, last["res"]),
			heads: tla.Ints(t, last["heads"]), cpAfter: tla.Int(t, last["cpAfter"])}
		// The reader's view of a read is its whole input, so a state that
		// only differs elsewhere repeats the same check.
		if k := c.key(); !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	})
	return states, out
}

// runReader is readResource without decryption: verify what storage shows,
// compare with the checkpoint, choose the trusted heads and accept them. dir
// holds the checkpoint; each worker reuses its own.
func (w *modelWorld) runReader(c readerCase, dir string) (res string, heads []int64, cpAfter int64, err error) {
	ctx := context.Background()
	store := storagetest.NewMemory()
	for i := 0; i < c.now; i++ {
		if err := store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: w.digests[i], Head: w.controls[i]}); err != nil {
			return "", nil, 0, err
		}
	}
	digests := map[int64]digest.Digest{}
	ids := map[digest.Digest]int64{}
	scope := storage.StateScope(conformanceWorkspace, conformanceResource)
	for _, r := range c.revs {
		blob, ciphertext, err := w.revision(r, digests)
		if err != nil {
			return "", nil, 0, err
		}
		d := digest.FromBytes(blob)
		digests[r.id], ids[d] = d, r.id
		if slices.Contains(c.view, r.id) {
			if err := store.Publish(ctx, storage.Object{Kind: storage.KindState, Scope: scope, Rev: d, Head: blob, Payload: ciphertext}); err != nil {
				return "", nil, 0, err
			}
		}
	}
	view, err := wsp.LoadControl(ctx, store, conformanceWorkspace, w.digests[0], nil)
	if err != nil {
		return "", nil, 0, err
	}
	head, err := view.Head()
	if err != nil {
		return "", nil, 0, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", nil, 0, err
	}
	cps := wsp.OpenCheckpoints(dir, conformanceWorkspace, w.digests[0], clock.New())
	if c.cpBefore > 0 {
		seed := &wsp.StateView{States: map[digest.Digest]*wsp.VerifiedState{"seed": {State: wsp.State{Generation: uint64(c.cpBefore)}}}}
		if err := cps.AcceptState(conformanceResource, seed, uint64(c.cpBefore)); err != nil {
			return "", nil, 0, err
		}
	}
	s := &session{store: store, workspace: conformanceWorkspace, view: view, head: head, cps: cps}
	finish := func(res string, heads []int64) (string, []int64, int64, error) {
		g, err := cps.Generation(conformanceResource)
		return res, heads, int64(g), err
	}
	sv, err := s.loadResource(ctx, conformanceResource)
	if err != nil {
		var appErr *apperr.Error
		if !errors.As(err, &appErr) {
			return "", nil, 0, fmt.Errorf("unclassified error: %w", err)
		}
		switch appErr.Code() {
		case apperr.CodeRollback:
			return finish("rollback_detected", nil)
		case apperr.CodeArtifactNotFound:
			return finish("artifact_not_found", nil)
		case apperr.CodeUntrusted:
			return finish("untrusted_state", nil)
		}
		return "", nil, 0, fmt.Errorf("unexpected error code %s: %w", appErr.Code(), err)
	}
	trusted := s.trustedHeads(sv)
	if len(trusted) == 0 {
		return finish("untrusted_state", nil)
	}
	if err := s.acceptView(conformanceResource, sv); err != nil {
		return "", nil, 0, fmt.Errorf("accepting a view that loaded: %w", err)
	}
	for _, h := range trusted {
		heads = append(heads, ids[h.Digest])
	}
	slices.Sort(heads)
	return finish("ok", heads)
}

func TestReaderMatchesTheModel(t *testing.T) {
	mutant := os.Getenv("ENBU_MODEL_MUTANT")
	if mutant == "" {
		mutant = "none"
	}
	for _, chain := range []struct {
		name    string
		mc      string
		maxGen  int
		members [][]string
	}{
		{"removal", "MCRemoval", 3, [][]string{{"a", "b", "r"}, {"a", "b"}}},
		{"readmission", "MCReadmission", 2, [][]string{{"a", "b", "r"}, {"a", "b"}, {"a", "b", "r"}}},
	} {
		t.Run(chain.name, func(t *testing.T) {
			states, cases := readerCases(t, fmt.Sprintf(readerConformanceConfig, chain.mc, chain.maxGen, mutant))
			t.Logf("%d model states, %d distinct reads", states, len(cases))
			if len(cases) < 100 {
				t.Fatalf("the model produced only %d reads", len(cases))
			}
			w := newModelWorld(t, chain.members)
			outcomes := map[string]int{}
			for _, c := range cases {
				outcomes[c.res]++
			}
			mismatches := make([]string, len(cases))
			jobs := make(chan int)
			var wg sync.WaitGroup
			for worker := 0; worker < max(1, runtime.NumCPU()); worker++ {
				dir := filepath.Join(t.TempDir(), "checkpoints")
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range jobs {
						c := cases[i]
						res, heads, cpAfter, err := w.runReader(c, dir)
						if err != nil {
							mismatches[i] = fmt.Sprintf("view %v of %v: %v", c.view, c.revs, err)
						} else if res != c.res || !slices.Equal(heads, c.heads) || cpAfter != c.cpAfter {
							mismatches[i] = fmt.Sprintf(
								"control %d, checkpoint %d, view %v of %v:\n      model %s %v -> %d\n      code  %s %v -> %d",
								c.now, c.cpBefore, c.view, c.revs, c.res, c.heads, c.cpAfter, res, heads, cpAfter)
						}
					}
				}()
			}
			for i := range cases {
				jobs <- i
			}
			close(jobs)
			wg.Wait()
			mismatches = slices.DeleteFunc(mismatches, func(m string) bool { return m == "" })
			t.Logf("%d reads checked: %v", len(cases), outcomes)
			for _, want := range []string{"ok", "rollback_detected", "untrusted_state", "artifact_not_found"} {
				if outcomes[want] == 0 {
					t.Errorf("no read with outcome %s: the configuration is too small to check it", want)
				}
			}
			if len(mismatches) > 0 {
				shown := mismatches[:min(len(mismatches), 8)]
				t.Fatalf("%d of %d reads differ from the model (mutant %q):\n  %s", len(mismatches), len(cases), mutant, strings.Join(shown, "\n  "))
			}
		})
	}
}

package wsp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/internal/tla"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

// The Control conformance test lets TLC enumerate every store of Controls the
// ControlDAG model reaches (honest updates and joins, and the attacker's
// Controls signed with a leaked key or forged), rebuilds each one with real
// keys, and requires LoadControl to verify exactly the Controls the model
// verifies, with the same heads.

type modelControl struct {
	id, height int64
	parents    []int64
	roles      map[string]string
	author     string
	sig        bool
}

func (c modelControl) String() string {
	how := "signed"
	if !c.sig {
		how = "forged"
	}
	return fmt.Sprintf("#%d{parents %v height %d roles %v %s by %s}", c.id, c.parents, c.height, c.roles, how, c.author)
}

type controlCase struct {
	controls []modelControl // by id
	verified []int64
	heads    []int64
}

func controlCases(t *testing.T, module, cfg string) (states int, out []controlCase) {
	t.Helper()
	seen := map[string]bool{}
	states = tla.DumpEach(t, module, cfg, func(s tla.State) {
		var cs []modelControl
		for _, v := range tla.Elems(t, s["store"]) {
			r := tla.Rec(t, v)
			roles := map[string]string{}
			for name, role := range tla.Rec(t, r["roles"]) {
				roles[name] = tla.Str(t, role)
			}
			cs = append(cs, modelControl{id: tla.Int(t, r["id"]), height: tla.Int(t, r["height"]), parents: tla.Ints(t, r["parents"]),
				roles: roles, author: tla.Str(t, r["author"]), sig: tla.Bool(t, r["sig"])})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].id < cs[j].id })
		key := fmt.Sprint(cs)
		if seen[key] {
			return
		}
		seen[key] = true
		var verified []int64
		byID := map[int64]bool{}
		for _, v := range tla.Elems(t, s["ver"]) {
			id := tla.Int(t, tla.Rec(t, v)["id"])
			verified = append(verified, id)
			byID[id] = true
		}
		slices.Sort(verified)
		var heads []int64
		for _, id := range verified {
			child := false
			for _, c := range cs {
				if byID[c.id] && slices.Contains(c.parents, id) {
					child = true
				}
			}
			if !child {
				heads = append(heads, id)
			}
		}
		out = append(out, controlCase{controls: cs, verified: verified, heads: heads})
	})
	return states, out
}

type controlWorld struct {
	actors map[string]actor
	forger actor
}

// build signs a model Control. A forged one claims its author and is signed
// by another key; it is encoded like SignControl but without its checks.
func (w controlWorld) build(c modelControl, digests map[int64]digest.Digest) ([]byte, error) {
	ctl := Control{Workspace: testWorkspace, Height: uint64(c.height), Author: w.actors[c.author].p.ID}
	for _, p := range c.parents {
		ctl.Parents = append(ctl.Parents, digests[p])
	}
	sortDigests(ctl.Parents)
	for name, role := range c.roles {
		if role == "none" {
			continue
		}
		p := w.actors[name].p
		p.Admin = role == "admin"
		ctl.Principals = append(ctl.Principals, p)
	}
	sort.Slice(ctl.Principals, func(i, j int) bool { return ctl.Principals[i].ID < ctl.Principals[j].ID })
	signer := w.actors[c.author].signer
	if !c.sig {
		signer = w.forger.signer
	}
	body, err := encMode.Marshal(ctl)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signing.DomainControl, body)
	if err != nil {
		return nil, err
	}
	return Signed{Body: body, Signature: sig}.Encode()
}

func (w controlWorld) run(c controlCase) (verified, heads []int64, err error) {
	ctx := context.Background()
	store := storagetest.NewMemory()
	digests := map[int64]digest.Digest{}
	ids := map[digest.Digest]int64{}
	for _, m := range c.controls {
		blob, err := w.build(m, digests)
		if err != nil {
			return nil, nil, err
		}
		d := digest.FromBytes(blob)
		digests[m.id], ids[d] = d, m.id
		if err := store.Publish(ctx, storage.Object{Kind: storage.KindControl, Rev: d, Head: blob}); err != nil {
			return nil, nil, err
		}
	}
	view, err := LoadControl(ctx, store, testWorkspace, digests[0], nil)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range view.Digests() {
		verified = append(verified, ids[d])
	}
	for _, h := range view.Heads {
		heads = append(heads, ids[h.Digest])
	}
	slices.Sort(verified)
	slices.Sort(heads)
	return verified, heads, nil
}

func TestControlVerifierMatchesTheModel(t *testing.T) {
	for _, cfg := range []string{"ControlDAG.cfg", "ControlDAG_insider.cfg"} {
		t.Run(cfg, func(t *testing.T) {
			text := readSpecFile(t, cfg)
			states, cases := controlCases(t, "MCControlDAG.tla", text)
			t.Logf("%d model states, %d distinct stores", states, len(cases))
			if len(cases) < 1000 {
				t.Fatalf("the model produced only %d stores", len(cases))
			}
			w := controlWorld{actors: map[string]actor{}, forger: newActor(t, false)}
			for _, name := range []string{"a", "b", "m"} {
				w.actors[name] = newActor(t, false)
			}
			mismatches := make([]string, len(cases))
			forks, joins, attacks := 0, 0, 0
			for _, c := range cases {
				if len(c.heads) > 1 {
					forks++
				}
				for _, m := range c.controls {
					if len(m.parents) > 1 && slices.Contains(c.verified, m.id) {
						joins++
					}
					if !m.sig || m.author == "m" {
						attacks++
					}
				}
			}
			jobs := make(chan int)
			var wg sync.WaitGroup
			for range max(1, runtime.NumCPU()) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range jobs {
						c := cases[i]
						verified, heads, err := w.run(c)
						switch {
						case err != nil:
							mismatches[i] = fmt.Sprintf("%v: %v", c.controls, err)
						case !slices.Equal(verified, c.verified) || !slices.Equal(heads, c.heads):
							mismatches[i] = fmt.Sprintf("%v:\n      model verifies %v heads %v\n      code  verifies %v heads %v",
								c.controls, c.verified, c.heads, verified, heads)
						}
					}
				}()
			}
			for i := range cases {
				jobs <- i
			}
			close(jobs)
			wg.Wait()
			t.Logf("stores with a fork %d, verified joins %d, attacker Controls %d", forks, joins, attacks)
			if forks == 0 || joins == 0 || attacks == 0 {
				t.Fatal("the configuration no longer reaches forks, joins and attacks")
			}
			mismatches = slices.DeleteFunc(mismatches, func(m string) bool { return m == "" })
			if len(mismatches) > 0 {
				t.Fatalf("%d of %d stores differ from the model:\n  %s", len(mismatches), len(cases), strings.Join(mismatches[:min(8, len(mismatches))], "\n  "))
			}
		})
	}
}

func readSpecFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tla.SpecDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

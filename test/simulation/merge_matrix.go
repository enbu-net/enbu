package simulation

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"

	"encoding/json"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

type MergeCase struct {
	Shape           string
	Base, OtherBase int
	Heads           []int
	DeleteChoice    bool
}
type mergeDatum struct {
	Present bool
	Value   string
}

var mergeDomain = []mergeDatum{{}, {Present: true}, {true, "a"}, {true, "b"}}

func mergeSnapshot(v mergeDatum) map[string]string {
	out := map[string]string{"UNRELATED": "kept"}
	if v.Present {
		out["K"] = v.Value
	}
	return out
}

// referenceMerge enumerates outcomes satisfying the specification: against
// each base every head is either unchanged or equal to the candidate. Exactly
// one outcome must satisfy all bases. It does not call the merge package or DAG.
func referenceMerge(bases, heads []mergeDatum) (mergeDatum, bool) {
	if len(bases) == 0 {
		bases = []mergeDatum{{}}
	}
	candidates := map[mergeDatum]bool{}
	for _, v := range bases {
		candidates[v] = true
	}
	for _, v := range heads {
		candidates[v] = true
	}
	var result mergeDatum
	count := 0
	for candidate := range candidates {
		valid := true
		for _, base := range bases {
			for _, head := range heads {
				if head != base && head != candidate {
					valid = false
				}
			}
		}
		if valid {
			result = candidate
			count++
		}
	}
	return result, count == 1
}

func (w *World) publishMergeNode(ctx context.Context, actor int, values map[string]string, parents ...digest.Digest) (storage.Object, error) {
	return w.publishNodeAtControl(ctx, actor, "", values, parents...)
}

func (w *World) publishNodeAtControl(ctx context.Context, actor int, epoch digest.Digest, values map[string]string, parents ...digest.Digest) (storage.Object, error) {
	d := w.Devices[actor]
	cfg, err := config.LoadProjectFrom(d.App.RepositoryDir)
	if err != nil {
		return storage.Object{}, err
	}
	view, err := wsp.LoadControl(ctx, d.Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return storage.Object{}, err
	}
	control, err := view.Head()
	if err != nil {
		return storage.Object{}, err
	}
	plaintext, err := json.Marshal(values)
	if err != nil {
		return storage.Object{}, err
	}
	cipher, err := d.App.Runtime.Encrypt(plaintext, control.Recipients())
	if err != nil {
		return storage.Object{}, err
	}
	signer, err := d.Keys.Signer(cfg.WorkspaceID)
	if err != nil {
		return storage.Object{}, err
	}
	defer func() { _ = signer.Close() }()
	state := wsp.State{Workspace: cfg.WorkspaceID, Resource: cfg.Resource("default"), Control: control.Digest, Parents: slices.Clone(parents), Author: signer.Public().DeviceID(), Ciphertext: digest.FromBytes(cipher), CreatedAt: d.App.Runtime.Clock.Now().Unix()}
	if epoch != "" {
		state.Control = epoch
	}
	signed, err := wsp.SignState(state, signer)
	if err != nil {
		return storage.Object{}, err
	}
	obj := storage.Object{Kind: storage.KindState, Scope: state.Scope(), Rev: digest.FromBytes(signed), Head: signed, Payload: cipher}
	if err := d.Store.Publish(ctx, obj); err != nil {
		return storage.Object{}, err
	}
	if err := w.Tape.Observe("merge-node", []any{actor, values, parents}, obj.Rev); err != nil {
		return storage.Object{}, err
	}
	return obj, nil
}

func (w *World) MergeCase(ctx context.Context, c MergeCase) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	if c.Shape == "two-keys" {
		return w.twoKeyMerge(ctx)
	}
	if c.Base < 0 || c.Base >= len(mergeDomain) || c.OtherBase < 0 || c.OtherBase >= len(mergeDomain) || len(c.Heads) < 2 || len(c.Heads) > 3 {
		return fmt.Errorf("invalid merge case %+v", c)
	}
	headValues := make([]mergeDatum, len(c.Heads))
	for i, n := range c.Heads {
		if n < 0 || n >= len(mergeDomain) {
			return fmt.Errorf("invalid head value")
		}
		headValues[i] = mergeDomain[n]
	}
	var bases []mergeDatum
	var baseRefs, headRefs []digest.Digest
	var root storage.Object
	if c.Shape != "no-base" {
		rootValue := mergeDomain[c.Base]
		if c.Shape == "criss-cross" {
			rootValue = mergeDatum{true, "root"}
		}
		var err error
		root, err = w.publishMergeNode(ctx, 0, mergeSnapshot(rootValue))
		if err != nil {
			return err
		}
		w.Model["default"] = mergeSnapshot(rootValue)
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		bases = []mergeDatum{mergeDomain[c.Base]}
		baseRefs = []digest.Digest{root.Rev}
	}
	parents := slices.Clone(baseRefs)
	switch c.Shape {
	case "criss-cross":
		bases = []mergeDatum{mergeDomain[c.Base], mergeDomain[c.OtherBase]}
		baseRefs = nil
		for i, v := range bases {
			node, err := w.publishMergeNode(ctx, i, mergeSnapshot(v), root.Rev)
			if err != nil {
				return err
			}
			baseRefs = append(baseRefs, node.Rev)
		}
		parents = slices.Clone(baseRefs)
	case "normal", "unequal", "no-base", "three-heads", "late-resolution", "missing-base":
	default:
		return fmt.Errorf("unknown merge shape %s", c.Shape)
	}
	for i, value := range headValues {
		branchParents := slices.Clone(parents)
		if c.Shape == "unequal" && i == 0 {
			node, err := w.publishMergeNode(ctx, i, mergeSnapshot(mergeDatum{true, "intermediate"}), parents...)
			if err != nil {
				return err
			}
			branchParents = []digest.Digest{node.Rev}
		}
		node, err := w.publishMergeNode(ctx, i, mergeSnapshot(value), branchParents...)
		if err != nil {
			return err
		}
		headRefs = append(headRefs, node.Rev)
	}
	cfg, err := config.LoadProjectFrom(w.Devices[0].App.RepositoryDir)
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	dag, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
	if err != nil {
		return err
	}
	gotBases := dag.Graph.MergeBases(headRefs)
	slices.Sort(gotBases)
	slices.Sort(baseRefs)
	if !slices.Equal(gotBases, baseRefs) {
		return fmt.Errorf("merge bases got %v want %v", gotBases, baseRefs)
	}
	if c.Shape == "missing-base" {
		if err := w.Devices[0].Store.Delete(ctx, root.Kind, root.Scope, root.Rev); err != nil {
			return err
		}
		for i, d := range w.Devices {
			if err := os.RemoveAll(d.App.CacheDir); err != nil {
				return err
			}
			if err := w.Tape.Observe("erase-fixture-cache", i, nil); err != nil {
				return err
			}
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeRollback) != nil {
				return fmt.Errorf("missing merge base was accepted: %v", err)
			}
		}
		if err := w.Devices[0].Store.Publish(ctx, root); err != nil {
			return err
		}
	}
	value, clean := referenceMerge(bases, headValues)
	a := w.Devices[0].App
	if !clean {
		for _, d := range w.Devices {
			if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
				return fmt.Errorf("merge silently chose a value: %v", err)
			}
		}
		set, err := a.ListConflicts(ctx, "default")
		if err != nil {
			return err
		}
		if c.Shape == "late-resolution" {
			node, err := w.publishMergeNode(ctx, 2, mergeSnapshot(mergeDatum{true, "late"}), root.Rev)
			if err != nil {
				return err
			}
			if err := requireCode(a.ResolveSecrets(ctx, "default", set.Heads, []app.SecretChoice{{Key: "K", Value: "stale"}}), apperr.CodeConflict); err != nil {
				return err
			}
			headRefs = append(headRefs, node.Rev)
			headValues = append(headValues, mergeDatum{true, "late"})
			set, err = a.ListConflicts(ctx, "default")
			if err != nil {
				return err
			}
		}
		if len(set.Conflicts) != 1 || set.Conflicts[0].Key != "K" {
			return fmt.Errorf("unexpected merge conflicts %+v", set)
		}
		expectedCandidates := map[app.ConflictCandidate]bool{}
		for _, v := range headValues {
			expectedCandidates[app.ConflictCandidate{Value: v.Value, Deleted: !v.Present}] = true
		}
		actualCandidates := map[app.ConflictCandidate]bool{}
		for _, v := range set.Conflicts[0].Candidates {
			actualCandidates[v] = true
		}
		if !reflect.DeepEqual(actualCandidates, expectedCandidates) {
			return fmt.Errorf("merge candidates got %v want %v", actualCandidates, expectedCandidates)
		}
		if err := requireCode(a.ResolveSecrets(ctx, "default", set.Heads, nil), apperr.CodeSecretConflict); err != nil {
			return err
		}
		value = mergeDatum{Present: !c.DeleteChoice, Value: "resolved"}
		if c.DeleteChoice {
			value.Value = ""
		}
		if err := a.ResolveSecrets(ctx, "default", set.Heads, []app.SecretChoice{{Key: "K", Value: value.Value, Delete: !value.Present}}); err != nil {
			return err
		}
	} else {
		w.Model["default"] = mergeSnapshot(value)
		if err := w.Check(ctx, "default"); err != nil {
			return err
		}
		if err := a.SyncSecrets(ctx, "default"); err != nil {
			return err
		}
	}
	w.Model["default"] = mergeSnapshot(value)
	if err := w.Tape.Observe("merge-outcome", []any{c, clean, bases, headValues}, w.Model["default"]); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	dag, err = wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("default"))
	if err != nil {
		return err
	}
	if len(dag.Heads) != 1 {
		return fmt.Errorf("merge did not converge to one head")
	}
	slices.Sort(headRefs)
	if !slices.Equal(dag.Heads[0].Parents, headRefs) {
		return fmt.Errorf("merge revision did not name every input head")
	}
	return nil
}

func (w *World) twoKeyMerge(ctx context.Context) error {
	base := map[string]string{"A": "base-a", "B": "base-b", "UNRELATED": "kept"}
	root, err := w.publishMergeNode(ctx, 0, base)
	if err != nil {
		return err
	}
	left := map[string]string{"A": "left", "LEFT": "added", "UNRELATED": "kept"}
	right := map[string]string{"A": "right", "B": "edited", "RIGHT": "added", "UNRELATED": "kept"}
	if _, err := w.publishMergeNode(ctx, 0, left, root.Rev); err != nil {
		return err
	}
	if _, err := w.publishMergeNode(ctx, 1, right, root.Rev); err != nil {
		return err
	}
	a := w.Devices[0].App
	set, err := a.ListConflicts(ctx, "default")
	if err != nil {
		return err
	}
	if len(set.Conflicts) != 2 || set.Conflicts[0].Key != "A" || set.Conflicts[1].Key != "B" {
		return fmt.Errorf("lost independent key conflict: %+v", set)
	}
	if err := requireCode(a.ResolveSecrets(ctx, "default", set.Heads, []app.SecretChoice{{Key: "A", Value: "chosen"}}), apperr.CodeSecretConflict); err != nil {
		return err
	}
	for _, d := range w.Devices {
		if _, err := d.App.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeSecretConflict) != nil {
			return fmt.Errorf("partial resolution became readable: %v", err)
		}
	}
	choices := []app.SecretChoice{{Key: "A", Value: "chosen"}, {Key: "B", Delete: true}, {Key: "UNRELATED", Delete: true}, {Key: "UNKNOWN", Value: "must-not-appear"}}
	if err := a.ResolveSecrets(ctx, "default", set.Heads, choices); err != nil {
		return err
	}
	w.Model["default"] = map[string]string{"A": "chosen", "LEFT": "added", "RIGHT": "added", "UNRELATED": "kept"}
	return w.Check(ctx, "default")
}

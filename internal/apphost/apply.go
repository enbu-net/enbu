package apphost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/opencontainers/go-digest"
)

type graphMutationNode struct {
	opened      *engine.OpenedRevision
	actionDraft *host.DraftResource
	working     artifact.Revision
	before      artifact.SealedRef
	dirty       bool
	deleted     bool
	sealed      *engine.SealedRevision
}

type graphMutation struct {
	ctx       context.Context
	execution host.Execution
	state     *workspaceState
	base      engine.Graph
	policy    artifact.SealedRef
	nodes     map[artifact.UUID]*graphMutationNode
	visiting  map[artifact.UUID]bool
	changes   map[artifact.UUID]host.ResourceChangeKind
}

func (executor *Executor) apply(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.ApplyAction,
) (host.Outcome, error) {
	if err := execution.Report(host.PhaseDiscovering, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	dag, err := executor.completeDAG(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	if dag == nil {
		return host.Outcome{}, commitmodel.ErrCommitNotFound
	}
	baseCommit, ok := dag.Commit(action.BaseCommit)
	if !ok {
		return host.Outcome{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, action.BaseCommit)
	}
	if frontier := dag.Frontier(); len(frontier) != 1 || frontier[0] != action.BaseCommit {
		return conflictForFrontier(baseCommit, action.BaseCommit, frontier)
	}
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionApply, baseCommit.Root.Material); err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseDecrypting, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	source := fallbackSource{local: state.objects, remote: state.remote}
	graph, err := engine.OpenGraph(ctx, source, state.device, state.verifier, baseCommit.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	openedPolicy, err := engine.OpenRevision(ctx, source, state.device, state.verifier, baseCommit.Policy)
	if err != nil {
		return host.Outcome{}, fmt.Errorf("open pinned policy: %w", err)
	}
	mutation := &graphMutation{
		ctx: ctx, execution: execution, state: state, base: graph, policy: baseCommit.Policy,
		nodes:    make(map[artifact.UUID]*graphMutationNode, len(graph.ByUID)),
		visiting: make(map[artifact.UUID]bool), changes: make(map[artifact.UUID]host.ResourceChangeKind),
	}
	for uid, opened := range graph.ByUID {
		copy := opened
		mutation.nodes[uid] = &graphMutationNode{opened: &copy, working: cloneRevision(opened.Revision), before: opened.Ref}
	}
	if err := mutation.applyChanges(action.Changes); err != nil {
		return host.Outcome{}, err
	}
	rootUID := graph.ByRevision[graph.Root.Revision].Revision.UID
	if _, err := mutation.seal(rootUID); err != nil {
		return host.Outcome{}, err
	}
	rootNode := mutation.nodes[rootUID]
	if rootNode == nil || rootNode.deleted {
		return host.Outcome{}, errors.New("apphost: apply deleted the workspace root")
	}
	newRoot := rootNode.before
	if rootNode.sealed != nil {
		newRoot = rootNode.sealed.Ref
	}
	if newRoot == baseCommit.Root {
		return host.Outcome{}, errors.New("apphost: apply produced no graph change")
	}
	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	// Network I/O is deliberately outside any process-local state lock. A final
	// frontier check converts a concurrent writer into an explicit conflict.
	latestDAG, err := executor.completeDAG(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	if latestDAG == nil {
		return host.Outcome{}, commitmodel.ErrCommitNotFound
	}
	if frontier := latestDAG.Frontier(); len(frontier) != 1 || frontier[0] != action.BaseCommit {
		return conflictForFrontier(baseCommit, action.BaseCommit, frontier)
	}

	recipients, err := verifiedGrantRecipients(ctx, graph.ByRevision[graph.Root.Revision].Grant.Claims.Recipients, state.verifier)
	if err != nil {
		return host.Outcome{}, err
	}
	provenance, resultChanges, err := mutation.provenance()
	if err != nil {
		return host.Outcome{}, err
	}
	closure := mutation.closure(rootUID)
	closure = engine.MergeClosures(closure, closureForOpened(openedPolicy))
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: recipients, Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionApply, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: newRoot, Policy: baseCommit.Policy,
		Parents: []digest.Digest{action.BaseCommit}, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: provenance, Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{Commit: published.CommitID, Root: newRoot, Changes: resultChanges}}, nil
}

func conflictForFrontier(base commitmodel.Commit, baseID digest.Digest, frontier []digest.Digest) (host.Outcome, error) {
	conflicts := make([]host.ConflictSummary, 0, len(frontier))
	for _, head := range frontier {
		if head == baseID {
			continue
		}
		id, err := newUUID()
		if err != nil {
			return host.Outcome{}, err
		}
		conflicts = append(conflicts, host.ConflictSummary{
			ID: id, Target: baseCommitTarget(base), Schema: workspaceSchema(), Kind: host.ConflictConcurrentChange,
			Base: baseID, Ours: baseID, Theirs: head,
		})
	}
	if len(conflicts) == 0 {
		id, err := newUUID()
		if err != nil {
			return host.Outcome{}, err
		}
		conflicts = append(conflicts, host.ConflictSummary{ID: id, Target: baseCommitTarget(base), Schema: workspaceSchema(), Kind: host.ConflictConcurrentChange, Base: baseID})
	}
	return host.Outcome{Conflict: &host.ConflictResult{Conflicts: conflicts}}, nil
}

func baseCommitTarget(value commitmodel.Commit) artifact.UUID {
	// SealedRef intentionally has no UID. A valid placeholder must not leak a
	// guessed graph identity in a pre-decryption concurrency result.
	return value.WorkspaceID
}

func workspaceSchema() artifact.TypeRef {
	value, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Workspace")
	return value
}

func (mutation *graphMutation) applyChanges(changes []host.GraphChange) error {
	rootUID := mutation.base.ByRevision[mutation.base.Root.Revision].Revision.UID
	for _, change := range changes {
		switch {
		case change.Create != nil:
			draft := change.Create.Draft
			if _, exists := mutation.nodes[draft.UID]; exists {
				return errors.New("apphost: create UID already exists")
			}
			copy := cloneHostDraft(draft)
			mutation.nodes[draft.UID] = &graphMutationNode{actionDraft: &copy, working: revisionFromDraft(copy), dirty: true}
			mutation.changes[draft.UID] = host.ResourceCreated
			root := mutation.nodes[rootUID]
			if root == nil || root.deleted {
				return errors.New("apphost: missing workspace root")
			}
			edgeID, err := newUUID()
			if err != nil {
				return err
			}
			name := draft.Metadata.Name
			for _, edge := range root.working.Edges {
				if edge.Name == name {
					name = string(draft.UID)
					break
				}
			}
			empty := artifact.SealedRef{}
			root.working.Edges = append(root.working.Edges, artifact.Edge{
				ID: edgeID, Name: name, Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned,
				Target: draft.UID, Pinned: &empty,
			})
			root.dirty = true
		case change.Replace != nil:
			draft := change.Replace.Draft
			node := mutation.nodes[draft.UID]
			if node == nil || node.deleted || node.before != change.Replace.Expected {
				return errors.New("apphost: replace expected revision conflict")
			}
			copy := cloneHostDraft(draft)
			node.actionDraft = &copy
			node.working = revisionFromDraft(copy)
			node.dirty = true
			mutation.changes[draft.UID] = host.ResourceUpdated
		case change.Delete != nil:
			node := mutation.nodes[change.Delete.UID]
			if node == nil || node.deleted || node.before != change.Delete.Expected || change.Delete.UID == rootUID {
				return errors.New("apphost: delete expected revision conflict")
			}
			node.deleted = true
			node.dirty = true
			mutation.changes[change.Delete.UID] = host.ResourceDeleted
		case change.PutEdge != nil:
			node := mutation.nodes[change.PutEdge.Parent]
			if node == nil || node.deleted || node.before != change.PutEdge.ExpectedParent {
				return errors.New("apphost: put-edge expected parent conflict")
			}
			if change.PutEdge.Edge.Strength == artifact.EdgePinned {
				target := mutation.nodes[change.PutEdge.Edge.Target]
				if target == nil || target.deleted || change.PutEdge.Edge.Pinned == nil || target.before != *change.PutEdge.Edge.Pinned {
					return errors.New("apphost: put-edge target is not the exact visible revision")
				}
			}
			put := change.PutEdge.Edge
			replaced := false
			for index := range node.working.Edges {
				if node.working.Edges[index].ID == put.ID {
					node.working.Edges[index] = put
					replaced = true
					break
				}
			}
			if !replaced {
				node.working.Edges = append(node.working.Edges, put)
			}
			node.dirty = true
			mutation.changes[node.working.UID] = host.ResourceUpdated
		case change.DeleteEdge != nil:
			node := mutation.nodes[change.DeleteEdge.Parent]
			if node == nil || node.deleted || node.before != change.DeleteEdge.ExpectedParent {
				return errors.New("apphost: delete-edge expected parent conflict")
			}
			found := false
			edges := node.working.Edges[:0]
			for _, edge := range node.working.Edges {
				if edge.ID == change.DeleteEdge.EdgeID {
					found = true
					continue
				}
				edges = append(edges, edge)
			}
			if !found {
				return errors.New("apphost: delete-edge ID not found")
			}
			node.working.Edges = edges
			node.dirty = true
			mutation.changes[node.working.UID] = host.ResourceUpdated
		}
	}
	return nil
}

func (mutation *graphMutation) seal(uid artifact.UUID) (artifact.SealedRef, error) {
	node := mutation.nodes[uid]
	if node == nil || node.deleted {
		return artifact.SealedRef{}, errors.New("apphost: missing mutation node")
	}
	if node.sealed != nil {
		return node.sealed.Ref, nil
	}
	if mutation.visiting[uid] {
		return artifact.SealedRef{}, artifact.ErrStrongCycle
	}
	mutation.visiting[uid] = true
	edges := make([]artifact.Edge, 0, len(node.working.Edges))
	childChanged := false
	for _, edge := range node.working.Edges {
		if edge.Strength != artifact.EdgePinned {
			edges = append(edges, edge)
			continue
		}
		target := mutation.nodes[edge.Target]
		if target == nil {
			return artifact.SealedRef{}, artifact.ErrMissingPinnedRevision
		}
		if target.deleted {
			childChanged = true
			continue
		}
		ref, err := mutation.seal(edge.Target)
		if err != nil {
			return artifact.SealedRef{}, err
		}
		if edge.Pinned == nil || *edge.Pinned != ref {
			pinned := ref
			edge.Pinned = &pinned
			childChanged = true
		}
		edges = append(edges, edge)
	}
	mutation.visiting[uid] = false
	if !node.dirty && !childChanged {
		return node.before, nil
	}
	node.working.Edges = edges
	draft, closers, err := mutation.nodeDraft(node)
	if err != nil {
		return artifact.SealedRef{}, err
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	recipients := []artifact.VerifiedDevice{mutation.state.author}
	if node.opened != nil {
		recipients, err = verifiedGrantRecipients(mutation.ctx, node.opened.Grant.Claims.Recipients, mutation.state.verifier)
		if err != nil {
			return artifact.SealedRef{}, err
		}
	}
	sealed, err := (engine.Sealer{Sink: mutation.state.objects, Issuer: mutation.state.device, Recipients: recipients}).SealDraft(mutation.ctx, draft, mutation.policy.Revision)
	if err != nil {
		return artifact.SealedRef{}, err
	}
	node.sealed = &sealed
	if _, direct := mutation.changes[uid]; !direct {
		mutation.changes[uid] = host.ResourceUpdated
	}
	return sealed.Ref, nil
}

func (mutation *graphMutation) nodeDraft(node *graphMutationNode) (engine.Draft, []io.Closer, error) {
	if node.actionDraft != nil {
		draft, err := draftFromAction(mutation.execution, *node.actionDraft)
		draft.Edges = append([]artifact.Edge(nil), node.working.Edges...)
		return draft, nil, err
	}
	draft := engine.Draft{Kind: node.working.Kind, UID: node.working.UID, Schema: node.working.Schema, Metadata: node.working.Metadata, Edges: append([]artifact.Edge(nil), node.working.Edges...)}
	closers := make([]io.Closer, 0, len(node.working.Payloads))
	for _, payload := range node.working.Payloads {
		reader := newDecryptReader(mutation.ctx, *node.opened, payload.Name, fallbackSource{local: mutation.state.objects, remote: mutation.state.remote})
		closers = append(closers, reader)
		draft.Payloads = append(draft.Payloads, engine.PayloadSource{Name: payload.Name, MediaType: payload.MediaType, Reader: reader})
	}
	return draft, closers, nil
}

func (mutation *graphMutation) provenance() ([]commitmodel.MutationProvenance, []host.ResourceChange, error) {
	records := make([]commitmodel.MutationProvenance, 0, len(mutation.changes))
	changes := make([]host.ResourceChange, 0, len(mutation.changes))
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/Apply")
	for uid, kind := range mutation.changes {
		node := mutation.nodes[uid]
		id, err := newUUID()
		if err != nil {
			return nil, nil, err
		}
		record := commitmodel.MutationProvenance{ID: id, Action: actionType, Target: uid}
		change := host.ResourceChange{UID: uid, Kind: kind}
		if kind != host.ResourceCreated {
			before := node.before
			record.Before = &before
			change.Before = before.Revision
		}
		if kind != host.ResourceDeleted {
			if node.sealed == nil {
				return nil, nil, errors.New("apphost: changed node was not sealed")
			}
			after := node.sealed.Ref
			record.After = &after
			change.After = after.Revision
		}
		records = append(records, record)
		changes = append(changes, change)
	}
	return records, changes, nil
}

func (mutation *graphMutation) closure(root artifact.UUID) engine.Closure {
	seen := make(map[artifact.UUID]struct{})
	stack := []artifact.UUID{root}
	var closure engine.Closure
	for len(stack) > 0 {
		uid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := seen[uid]; exists {
			continue
		}
		seen[uid] = struct{}{}
		node := mutation.nodes[uid]
		if node == nil || node.deleted {
			continue
		}
		var revision artifact.Revision
		if node.sealed != nil {
			closure = engine.MergeClosures(closure, node.sealed.Closure)
			revision = node.sealed.Revision
		} else {
			closure = engine.MergeClosures(closure, closureForOpened(*node.opened))
			revision = node.opened.Revision
		}
		for _, edge := range revision.Edges {
			if edge.Strength == artifact.EdgePinned {
				stack = append(stack, edge.Target)
			}
		}
	}
	return closure
}

func closureForOpened(opened engine.OpenedRevision) engine.Closure {
	closure := engine.Closure{Materials: []artifact.Descriptor{opened.MaterialDescriptor}, Grants: []artifact.Descriptor{opened.GrantDescriptor}}
	for _, chunk := range opened.Manifest.Revision.Chunks {
		closure.Chunks = append(closure.Chunks, chunk.Ciphertext)
	}
	for _, payload := range opened.Manifest.Payloads {
		for _, chunk := range payload.Stream.Chunks {
			closure.Chunks = append(closure.Chunks, chunk.Ciphertext)
		}
	}
	return closure
}

func verifiedGrantRecipients(ctx context.Context, claims []artifact.GrantRecipient, verifier artifact.EnrollmentVerifier) ([]artifact.VerifiedDevice, error) {
	verified := make([]artifact.VerifiedDevice, 0, len(claims))
	for _, claim := range claims {
		device, err := artifact.VerifyEnrollment(ctx, verifier, claim.Enrollment)
		if err != nil {
			return nil, err
		}
		if device.DeviceID() != claim.DeviceID || device.Subject() != claim.Subject || device.RecipientString() != claim.X25519Recipient ||
			device.AssertionDigest() != claim.EnrollmentDigest || !bytes.Equal(device.SigningPublicKey(), ed25519.PublicKey(claim.Ed25519PublicKey)) {
			return nil, errors.New("apphost: Grant recipient assertion mismatch")
		}
		verified = append(verified, device)
	}
	return verified, nil
}

func cloneHostDraft(value host.DraftResource) host.DraftResource {
	cloned := value
	cloned.Payloads = append([]host.StagedPayload(nil), value.Payloads...)
	cloned.Edges = append([]artifact.Edge(nil), value.Edges...)
	cloned.Metadata.Labels = cloneStrings(value.Metadata.Labels)
	cloned.Metadata.Annotations = cloneStrings(value.Metadata.Annotations)
	return cloned
}

func revisionFromDraft(draft host.DraftResource) artifact.Revision {
	return artifact.Revision{APIVersion: artifact.APIVersion, Kind: draft.Kind, UID: draft.UID, Schema: draft.Schema, Metadata: draft.Metadata, Edges: append([]artifact.Edge(nil), draft.Edges...)}
}

func cloneRevision(value artifact.Revision) artifact.Revision {
	cloned := value
	cloned.Payloads = append([]artifact.PayloadRef(nil), value.Payloads...)
	cloned.Edges = append([]artifact.Edge(nil), value.Edges...)
	cloned.Metadata.Labels = cloneStrings(value.Metadata.Labels)
	cloned.Metadata.Annotations = cloneStrings(value.Metadata.Annotations)
	return cloned
}

func cloneStrings(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

type decryptReader struct {
	once   sync.Once
	reader *io.PipeReader
	start  func(*io.PipeWriter)
}

func newDecryptReader(ctx context.Context, opened engine.OpenedRevision, name string, source artifact.ObjectSource) *decryptReader {
	result := &decryptReader{}
	result.start = func(pipe *io.PipeWriter) {
		go func() {
			err := opened.WritePayload(ctx, source, name, pipe)
			_ = pipe.CloseWithError(err)
		}()
	}
	return result
}

func (reader *decryptReader) ensure() {
	reader.once.Do(func() {
		pipeReader, pipeWriter := io.Pipe()
		reader.reader = pipeReader
		reader.start(pipeWriter)
	})
}

func (reader *decryptReader) Read(value []byte) (int, error) {
	reader.ensure()
	return reader.reader.Read(value)
}

func (reader *decryptReader) Close() error {
	reader.ensure()
	return reader.reader.Close()
}

package apphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
)

// payloadPlan is an internal, single-use plaintext capability. It deliberately
// has no accessor which returns payload bytes to a host client.
type payloadPlan struct {
	name      string
	mediaType string
	opened    *engine.OpenedRevision
	fixed     []byte
}

func payloadPlansFromOpened(opened engine.OpenedRevision) []payloadPlan {
	result := make([]payloadPlan, 0, len(opened.Revision.Payloads))
	for _, payload := range opened.Revision.Payloads {
		copy := opened
		result = append(result, payloadPlan{name: payload.Name, mediaType: payload.MediaType, opened: &copy})
	}
	return result
}

func fixedPayloadPlan(name, mediaType string, value []byte) payloadPlan {
	return payloadPlan{name: name, mediaType: mediaType, fixed: append([]byte(nil), value...)}
}

func (plan *payloadPlan) open(ctx context.Context, source artifact.ObjectSource) (io.ReadCloser, error) {
	if plan == nil {
		return nil, errors.New("apphost: nil payload plan")
	}
	if plan.opened != nil {
		return newDecryptReader(ctx, *plan.opened, plan.name, source), nil
	}
	return io.NopCloser(bytes.NewReader(plan.fixed)), nil
}

func (plan *payloadPlan) clear() {
	for index := range plan.fixed {
		plan.fixed[index] = 0
	}
	plan.fixed = nil
}

type revisionPlan struct {
	revision   artifact.Revision
	payloads   []payloadPlan
	recipients []artifact.VerifiedDevice
	source     *engine.OpenedRevision
	forceSeal  bool
	rewrapOnly bool

	visiting bool
	done     bool
	result   artifact.SealedRef
	closure  engine.Closure
}

func revisionPlanFromOpened(opened engine.OpenedRevision, recipients []artifact.VerifiedDevice) *revisionPlan {
	copy := opened
	return &revisionPlan{
		revision:   cloneRevision(opened.Revision),
		payloads:   payloadPlansFromOpened(opened),
		recipients: append([]artifact.VerifiedDevice(nil), recipients...),
		source:     &copy,
	}
}

// graphResealer rebuilds exactly one selected strong closure. It reuses an
// authenticated source object only when its complete Revision, recipient set,
// and policy binding remain exact. Otherwise it streams every payload through
// a fresh per-material identity and propagates the new SealedRef to ancestors.
type graphResealer struct {
	ctx    context.Context
	state  *workspaceState
	policy artifact.SealedRef
	nodes  map[artifact.UUID]*revisionPlan
	source artifact.ObjectSource
}

func newGraphResealer(ctx context.Context, state *workspaceState, policy artifact.SealedRef, nodes map[artifact.UUID]*revisionPlan) *graphResealer {
	return &graphResealer{
		ctx: ctx, state: state, policy: policy, nodes: nodes,
		source: fallbackSource{local: state.objects, remote: state.remote},
	}
}

func (builder *graphResealer) seal(uid artifact.UUID) (artifact.SealedRef, error) {
	plan := builder.nodes[uid]
	if plan == nil {
		return artifact.SealedRef{}, fmt.Errorf("apphost: selected graph is missing pinned target %s", uid)
	}
	if plan.done {
		return plan.result, nil
	}
	if plan.visiting {
		return artifact.SealedRef{}, artifact.ErrStrongCycle
	}
	plan.visiting = true
	working := cloneRevision(plan.revision)
	for index := range working.Edges {
		edge := &working.Edges[index]
		if edge.Strength != artifact.EdgePinned {
			continue
		}
		child, err := builder.seal(edge.Target)
		if err != nil {
			plan.visiting = false
			return artifact.SealedRef{}, err
		}
		edge.Pinned = &child
	}
	plan.visiting = false

	if !plan.forceSeal && plan.source != nil && reflect.DeepEqual(working, plan.source.Revision) &&
		verifiedRecipientSetKey(plan.recipients) == grantRecipientSetKey(plan.source.Grant.Claims.Recipients) &&
		plan.source.Grant.Claims.Policy == builder.policy.Revision {
		plan.result = plan.source.Ref
		plan.closure = closureForOpened(*plan.source)
		plan.done = true
		return plan.result, nil
	}
	if plan.rewrapOnly && !plan.forceSeal && plan.source != nil && reflect.DeepEqual(working, plan.source.Revision) {
		grant, err := artifact.CreateAccessGrant(
			builder.ctx, plan.source.Ref.Material, builder.policy.Revision, plan.source.Grant.Identity,
			builder.state.device, append([]artifact.VerifiedDevice(nil), plan.recipients...),
		)
		if err != nil {
			return artifact.SealedRef{}, err
		}
		encoded, err := artifact.EncodeAccessGrant(grant)
		if err != nil {
			return artifact.SealedRef{}, err
		}
		grantDescriptor, err := builder.state.objects.Ingest(builder.ctx, artifact.MediaTypeAccessGrant, bytes.NewReader(encoded))
		for index := range encoded {
			encoded[index] = 0
		}
		if err != nil {
			return artifact.SealedRef{}, fmt.Errorf("store replacement access grant: %w", err)
		}
		plan.result = plan.source.Ref
		plan.result.Grant = grantDescriptor.Digest
		plan.closure = closureForOpened(*plan.source)
		plan.closure.Grants = []artifact.Descriptor{grantDescriptor}
		plan.done = true
		return plan.result, nil
	}

	draft := engine.Draft{
		Kind: working.Kind, UID: working.UID, Schema: working.Schema,
		Metadata: cloneMetadataForReseal(working.Metadata), Edges: append([]artifact.Edge(nil), working.Edges...),
	}
	closers := make([]io.Closer, 0, len(plan.payloads))
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
		for index := range plan.payloads {
			plan.payloads[index].clear()
		}
	}()
	for index := range plan.payloads {
		reader, err := plan.payloads[index].open(builder.ctx, builder.source)
		if err != nil {
			return artifact.SealedRef{}, err
		}
		closers = append(closers, reader)
		draft.Payloads = append(draft.Payloads, engine.PayloadSource{
			Name: plan.payloads[index].name, MediaType: plan.payloads[index].mediaType, Reader: reader,
		})
	}
	sealed, err := (engine.Sealer{
		Sink: builder.state.objects, Issuer: builder.state.device,
		Recipients: append([]artifact.VerifiedDevice(nil), plan.recipients...),
	}).SealDraft(builder.ctx, draft, builder.policy.Revision)
	if err != nil {
		return artifact.SealedRef{}, err
	}
	plan.revision = sealed.Revision
	plan.result = sealed.Ref
	plan.closure = sealed.Closure
	plan.done = true
	return plan.result, nil
}

func (builder *graphResealer) closure() engine.Closure {
	var result engine.Closure
	for _, plan := range builder.nodes {
		if plan.done {
			result = engine.MergeClosures(result, plan.closure)
		}
	}
	return result
}

func cloneMetadataForReseal(value artifact.Metadata) artifact.Metadata {
	return artifact.Metadata{
		Name: value.Name, Labels: cloneStrings(value.Labels), Annotations: cloneStrings(value.Annotations),
	}
}

func verifiedRecipientSetKey(values []artifact.VerifiedDevice) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, strings.Join([]string{
			string(value.DeviceID()), value.Subject(), value.RecipientString(), value.AssertionDigest().String(),
		}, "\x00"))
	}
	sort.Strings(items)
	return strings.Join(items, "\x01")
}

func grantRecipientSetKey(values []artifact.GrantRecipient) string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, strings.Join([]string{
			string(value.DeviceID), value.Subject, value.X25519Recipient, value.EnrollmentDigest.String(),
		}, "\x00"))
	}
	sort.Strings(items)
	return strings.Join(items, "\x01")
}

func containsRecipient(values []artifact.VerifiedDevice, target artifact.UUID) bool {
	for _, value := range values {
		if value.DeviceID() == target {
			return true
		}
	}
	return false
}

func sortRecipients(values []artifact.VerifiedDevice) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].DeviceID() == values[j].DeviceID() {
			return values[i].AssertionDigest().String() < values[j].AssertionDigest().String()
		}
		return string(values[i].DeviceID()) < string(values[j].DeviceID())
	})
}

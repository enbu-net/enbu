package apphost

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

type pendingFinalization struct {
	audit     engine.AuditTrail
	action    engine.AuditAction
	digest    digest.Digest
	operation artifact.UUID
}

func (executor *Executor) materialize(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.MaterializeAction,
) (host.Outcome, error) {
	if err := execution.Report(host.PhaseDiscovering, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	value, err := executor.resolveCommit(ctx, state, action.AtCommit)
	if err != nil {
		return host.Outcome{}, err
	}
	operation := execution.OperationID()
	if err := executor.beginFinalization(ctx, state.audit, operation, engine.AuditActionMaterialize, value.Root.Material); err != nil {
		return host.Outcome{}, err
	}

	if err := execution.Report(host.PhaseDecrypting, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	graph, err := engine.OpenGraph(ctx, fallbackSource{local: state.objects, remote: state.remote}, state.device, state.verifier, value.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	opened, exists := graph.ByUID[action.Target]
	if !exists || opened.Revision.Kind != artifact.KindResource {
		return host.Outcome{}, errors.New("apphost: materialization target is not a visible Resource")
	}
	if err := validateMaterializer(action.Format, opened.Revision.Schema); err != nil {
		return host.Outcome{}, err
	}
	destination, err := execution.OpenOutput(action.Destination)
	if err != nil {
		return host.Outcome{}, err
	}
	fileTreeTar, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/FileTreeTar")
	if action.Format == fileTreeTar {
		if action.Payload != "" {
			return host.Outcome{}, errors.New("apphost: FileTreeTar materializes the complete tree and does not accept a payload selector")
		}
		objects, materializedBytes, err := materializeFileTreeTar(ctx, execution, opened, fallbackSource{local: state.objects, remote: state.remote}, destination)
		if err != nil {
			return host.Outcome{}, err
		}
		return host.Outcome{Materialize: &host.MaterializeResult{Objects: objects, Bytes: materializedBytes}}, nil
	}
	payload, err := selectMaterializePayload(opened.Revision.Payloads, action.Payload)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseMaterializing, host.ProgressUnitBytes, 0, uint64(payload.Size)); err != nil {
		return host.Outcome{}, err
	}
	if err := opened.WritePayload(ctx, fallbackSource{local: state.objects, remote: state.remote}, payload.Name, destination); err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseMaterializing, host.ProgressUnitBytes, uint64(payload.Size), uint64(payload.Size)); err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Materialize: &host.MaterializeResult{Objects: 1, Bytes: uint64(payload.Size)}}, nil
}

func selectMaterializePayload(payloads []artifact.PayloadRef, requested string) (artifact.PayloadRef, error) {
	if requested == "" {
		if len(payloads) != 1 {
			return artifact.PayloadRef{}, errors.New("apphost: payload name is required for a multi-stream Resource")
		}
		return payloads[0], nil
	}
	for _, payload := range payloads {
		if payload.Name == requested {
			return payload, nil
		}
	}
	return artifact.PayloadRef{}, errors.New("apphost: selected payload does not exist")
}

func (executor *Executor) beginFinalization(
	ctx context.Context,
	auditTrail engine.AuditTrail,
	operation artifact.UUID,
	action engine.AuditAction,
	value digest.Digest,
) error {
	if err := auditTrail.Started(ctx, operation, action, value); err != nil {
		return fmt.Errorf("persist operation audit start: %w", err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if _, exists := executor.finalizations[operation]; exists {
		return errors.New("apphost: duplicate operation audit lifecycle")
	}
	executor.finalizations[operation] = pendingFinalization{
		audit: auditTrail, action: action, digest: value, operation: operation,
	}
	return nil
}

func validateMaterializer(format, schemaRef artifact.TypeRef) error {
	raw, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/Raw")
	dotenv, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/DotEnv")
	fileTreeTar, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/FileTreeTar")
	secretMap, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/SecretMap")
	fileTree, _ := artifact.ParseTypeRef(schema.SchemaFileTree)
	switch format {
	case raw:
		return nil
	case dotenv:
		if schemaRef != secretMap {
			return errors.New("apphost: DotEnv materializer requires SecretMap")
		}
		return nil
	case fileTreeTar:
		if schemaRef != fileTree {
			return errors.New("apphost: FileTreeTar materializer requires FileTree")
		}
		return nil
	default:
		return errors.New("apphost: unknown trusted materializer")
	}
}

func materializeFileTreeTar(
	ctx context.Context,
	execution host.Execution,
	opened engine.OpenedRevision,
	source artifact.ObjectSource,
	destination io.Writer,
) (uint64, uint64, error) {
	indexPayload, err := selectMaterializePayload(opened.Revision.Payloads, schema.FileTreeIndexPayloadName)
	if err != nil || indexPayload.MediaType != schema.FileTreeIndexMediaType || indexPayload.Size > schema.MaxFileTreeIndexBytes {
		return 0, 0, errors.New("apphost: FileTree has no valid canonical index payload")
	}
	var encoded bytes.Buffer
	encoded.Grow(int(indexPayload.Size))
	if err := opened.WritePayload(ctx, source, indexPayload.Name, &encoded); err != nil {
		return 0, 0, err
	}
	mapping, err := schema.DecodeFileTreeMapping(encoded.Bytes(), opened.Revision.Payloads)
	if err != nil {
		return 0, 0, err
	}
	files := mapping.Files()
	var total uint64
	for _, file := range files {
		total += uint64(file.Payload.Size)
	}
	if err := execution.Report(host.PhaseMaterializing, host.ProgressUnitBytes, 0, total); err != nil {
		return 0, 0, err
	}
	archive := tar.NewWriter(destination)
	for _, file := range files {
		header := &tar.Header{
			Name: file.Path, Mode: 0o600, Size: file.Payload.Size,
			Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}
		if err := archive.WriteHeader(header); err != nil {
			_ = archive.Close()
			return 0, 0, err
		}
		if err := opened.WritePayload(ctx, source, file.Payload.Name, archive); err != nil {
			_ = archive.Close()
			return 0, 0, err
		}
	}
	if err := archive.Close(); err != nil {
		return 0, 0, err
	}
	if err := execution.Report(host.PhaseMaterializing, host.ProgressUnitBytes, total, total); err != nil {
		return 0, 0, err
	}
	return uint64(len(files)), total, nil
}

func (executor *Executor) resolveCommit(ctx context.Context, state *workspaceState, id digest.Digest) (commitmodel.Commit, error) {
	dag, err := executor.completeDAG(ctx, state)
	if err != nil {
		return commitmodel.Commit{}, err
	}
	if dag == nil {
		return commitmodel.Commit{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, id)
	}
	value, ok := dag.Commit(id)
	if !ok {
		return commitmodel.Commit{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, id)
	}
	return value, nil
}

// Finalize runs after host has committed or aborted all transactional outputs.
// It is intentionally a no-op for operations whose audit lifecycle is already
// completed by the publication engine.
func (executor *Executor) Finalize(
	ctx context.Context,
	execution host.Execution,
	_ host.Action,
	_ host.Outcome,
	operationErr error,
) error {
	operation := execution.OperationID()
	executor.mu.Lock()
	pending, exists := executor.finalizations[operation]
	delete(executor.finalizations, operation)
	executor.mu.Unlock()
	if !exists {
		return nil
	}
	result := engine.AuditResultSucceeded
	if operationErr != nil {
		result = engine.AuditResultFailed
	}
	if err := pending.audit.Finished(ctx, pending.operation, pending.action, pending.digest, result); err != nil {
		return fmt.Errorf("persist materialization audit terminal event: %w", err)
	}
	return nil
}

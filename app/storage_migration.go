package app

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// ChangeStorage copies verified ciphertext and history before changing enbu.toml.
// The team must pause writes until every member has the new enbu.toml: immutable
// OCI objects provide no cross-registry lock or atomic redirect for old clients.
func (a *App) ChangeStorage(ctx context.Context, settings config.StorageConfig) (err error) {
	defer apperr.NormalizeInto(&err)
	if a.StorageURL != "" {
		return apperr.New(apperr.CodeInvalidArgument, "storage migration cannot use a storage override", nil)
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		return apperr.New(apperr.CodeAccessDenied, "only an admin can migrate storage", nil)
	}
	if settings == s.cfg.Storage {
		return nil
	}
	next := *s.cfg
	next.Storage = settings
	targetApp := *a
	targetApp.Storage = nil
	target, err := targetApp.openStorage(ctx, &next)
	if err != nil {
		return err
	}
	return a.migrateStorage(ctx, s, target, &next)
}

type migrationRef struct {
	kind  storage.Kind
	scope string
	rev   digest.Digest
}

func migrationRefs(ctx context.Context, s *session) ([]migrationRef, error) {
	refs := []migrationRef{}
	for _, rev := range s.view.Digests() {
		refs = append(refs, migrationRef{storage.KindControl, "", rev})
	}
	resources, unexamined, err := s.environmentResources(ctx)
	if err != nil {
		return nil, err
	}
	if unexamined != 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "too many storage scopes to migrate safely", nil)
	}
	for _, resource := range resources {
		scope := storage.StateScope(s.workspace, resource.resource)
		sv, err := s.loadResource(ctx, resource.resource)
		if apperr.Is(err, apperr.CodeArtifactNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(sv.MissingParents()) != 0 {
			return nil, wspError(wsp.ErrRollback)
		}
		for rev := range sv.States {
			refs = append(refs, migrationRef{storage.KindState, scope, rev})
		}
		records, err := wsp.LoadCompactions(ctx, s.store, s.view, s.workspace, resource.resource)
		if err != nil {
			return nil, wspError(err)
		}
		for _, record := range records {
			refs = append(refs, migrationRef{storage.KindCompaction, scope, record.Digest})
		}
	}
	requests, err := wsp.ListJoinRequests(ctx, s.store, s.workspace)
	if err != nil {
		return nil, wspError(err)
	}
	for _, request := range requests {
		refs = append(refs, migrationRef{storage.KindRequest, "", request.Rev})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].kind != refs[j].kind {
			return refs[i].kind < refs[j].kind
		}
		if refs[i].scope != refs[j].scope {
			return refs[i].scope < refs[j].scope
		}
		return refs[i].rev < refs[j].rev
	})
	return refs, nil
}

func (a *App) migrateStorage(ctx context.Context, s *session, target storage.Store, next *config.ProjectConfig) error {
	refs, err := migrationRefs(ctx, s)
	if err != nil {
		return err
	}
	// A retry may find the objects from an earlier partial copy, but must never
	// mix another workspace or new target-side writes into this migration.
	allowed := map[migrationRef]bool{}
	for _, ref := range refs {
		allowed[ref] = true
	}
	scopes, err := target.Scopes(ctx)
	if err != nil {
		return storageError(err)
	}
	if len(scopes) > maxExaminedScopes {
		return apperr.New(apperr.CodeInvalidArgument, "destination has too many scopes to inspect safely", nil)
	}
	for _, kind := range []storage.Kind{storage.KindControl, storage.KindRequest, storage.KindState, storage.KindCompaction} {
		buckets := []string{""}
		if kind == storage.KindState || kind == storage.KindCompaction {
			buckets = scopes
		}
		for _, scope := range buckets {
			revs, err := target.Discover(ctx, kind, scope)
			if err != nil {
				return storageError(err)
			}
			for _, rev := range revs {
				if !allowed[migrationRef{kind, scope, rev}] {
					return apperr.New(apperr.CodeInvalidArgument, "destination contains data outside this migration; choose an empty destination", nil)
				}
			}
		}
	}
	for _, ref := range refs {
		head, err := s.store.FetchHead(ctx, ref.kind, ref.scope, ref.rev)
		if err != nil {
			return storageError(err)
		}
		object := storage.Object{Kind: ref.kind, Scope: ref.scope, Rev: ref.rev, Head: head}
		if ref.kind == storage.KindState {
			workspace, resource, decodeErr := wsp.StateResource(head)
			if decodeErr != nil {
				return wspError(decodeErr)
			}
			state, verifyErr := wsp.VerifyRevision(s.view, workspace, resource, ref.rev, head)
			if verifyErr != nil {
				return wspError(verifyErr)
			}
			object.Payload, err = wsp.ReadCiphertext(ctx, s.store, state)
			if err != nil {
				return storageError(err)
			}
		}
		if err := target.Publish(ctx, object); err != nil {
			return storageError(err)
		}
		got, err := target.FetchHead(ctx, ref.kind, ref.scope, ref.rev)
		if err != nil {
			return storageError(err)
		}
		if !bytes.Equal(got, head) {
			return storageError(storage.ErrCorrupt)
		}
		if ref.kind == storage.KindState {
			got, err = storage.ReadPayload(ctx, target, ref.kind, ref.scope, ref.rev, storage.MaxPayloadBytes)
			if err != nil {
				return storageError(err)
			}
			if !bytes.Equal(got, object.Payload) {
				return storageError(storage.ErrCorrupt)
			}
		}
	}
	fresh, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	defer fresh.Close()
	after, err := migrationRefs(ctx, fresh)
	if err != nil {
		return err
	}
	if !slices.Equal(refs, after) {
		return apperr.New(apperr.CodeInvalidArgument, "source changed during migration; pause team writes and retry", nil)
	}
	current, err := a.loadProject()
	if err != nil {
		return err
	}
	if current.Storage != s.cfg.Storage || current.ControlGenesis != next.ControlGenesis || current.WorkspaceID != next.WorkspaceID {
		return apperr.New(apperr.CodeInvalidArgument, "workspace configuration changed during migration; retry", nil)
	}
	// Keep edits made to output names or environments while copying.
	current.Storage = next.Storage
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("migrating storage: %w", err)
	}
	return a.saveProject(current)
}

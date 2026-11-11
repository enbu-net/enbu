package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// reencryptAll re-signs and re-encrypts every environment for the recipient set
// of the current Control: the ones enbu.toml names and any other storage holds,
// so an environment another member created, whose enbu.toml this device has not
// pulled, does not stay encrypted for the old members.
func (a *App) reencryptAll(ctx context.Context) error {
	s, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	targets, unexamined, err := s.environmentResources(ctx)
	s.Close()
	if err != nil {
		return err
	}
	// Keep going after a failure: every environment left behind stays encrypted
	// for the old recipient set, and the error should name all of them.
	var errs []error
	if unexamined > 0 {
		errs = append(errs, fmt.Errorf("storage holds %d more scopes than the %d examined; any environment among them that enbu.toml does not list was not re-encrypted, so add it to enbu.toml and run enbu sync", unexamined, maxExaminedScopes))
	}
	for _, t := range targets {
		s, err := a.openSession(ctx)
		if err == nil {
			err = a.changeResource(ctx, s, t.resource, "sync", nil, nil, func(map[string]string) error { return nil })
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("re-encrypting %s: %w", t.name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// maxExaminedScopes bounds how many scopes missing from enbu.toml are examined
// for an environment. Examining one lists and fetches revisions, and anyone
// able to write to storage can create scopes, so the bound counts every scope
// examined, trusted or not, to keep a membership change bounded.
var maxExaminedScopes = 256

// maxResourceProbes bounds how many revisions of one listed scope are read to
// learn which resource it holds.
const maxResourceProbes = 16

type environmentResource struct {
	name     string // the environment's name, or the resource when enbu.toml lacks it
	resource string
}

// environmentResources lists the environments enbu.toml names, then any other
// secrets resource storage holds a trusted revision of. A scope that holds only
// revisions from non-members is skipped: anyone able to write to storage can
// make one, and it has no content to re-encrypt. At most maxExaminedScopes
// unlisted scopes are examined; unexamined counts the rest.
func (s *session) environmentResources(ctx context.Context) (out []environmentResource, unexamined int, err error) {
	known := map[string]bool{}
	for _, env := range s.cfg.EnvironmentNames() {
		r := s.resource(env)
		out = append(out, environmentResource{name: env, resource: r})
		known[storage.StateScope(s.workspace, r)] = true
	}
	scopes, err := s.store.Scopes(ctx)
	if err != nil {
		return nil, 0, storageError(err)
	}
	examined := 0
	for _, scope := range scopes {
		if known[scope] {
			continue
		}
		if examined >= maxExaminedScopes {
			unexamined++
			continue
		}
		examined++
		resource, err := s.scopeResource(ctx, scope)
		if err != nil {
			return nil, 0, err
		}
		if resource == "" {
			continue
		}
		trusted, err := s.hasTrustedHead(ctx, resource)
		if err != nil {
			return nil, 0, err
		}
		if trusted {
			out = append(out, environmentResource{name: resource, resource: resource})
		}
	}
	return out, unexamined, nil
}

// scopeResource learns which secrets resource of this workspace a listed scope
// holds, from the first revision that names one. The scope is derived from the
// workspace and resource, so a revision naming another resource cannot claim
// this scope. It returns "" when no revision says.
func (s *session) scopeResource(ctx context.Context, scope string) (string, error) {
	revs, err := s.store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return "", storageError(err)
	}
	for i, rev := range revs {
		if i >= maxResourceProbes {
			break
		}
		head, err := s.store.FetchHead(ctx, storage.KindState, scope, rev)
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrCorrupt) {
			continue
		}
		if err != nil {
			return "", storageError(err)
		}
		workspace, resource, err := wsp.StateResource(head)
		if err != nil || workspace != s.workspace || !strings.HasPrefix(resource, "secrets/") ||
			storage.StateScope(workspace, resource) != scope {
			continue
		}
		return resource, nil
	}
	return "", nil
}

// hasTrustedHead reports whether resource has a head this device may read as
// current, the same test reading it applies.
func (s *session) hasTrustedHead(ctx context.Context, resource string) (bool, error) {
	sv, err := wsp.LoadStates(ctx, s.store, s.view, s.workspace, resource)
	if err != nil {
		return false, wspError(err)
	}
	accepted, err := s.cps.Accepted(resource)
	if err != nil {
		return false, err
	}
	return len(s.trustedHeads(sv, accepted)) > 0, nil
}

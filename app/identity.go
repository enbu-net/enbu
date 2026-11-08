package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
)

func (a *App) CreateIdentity() (info identity.PublicInfo, warning string, err error) {
	defer apperr.NormalizeInto(&err)
	workspaceID, err := a.WorkspaceID()
	if err != nil {
		return info, "", err
	}
	d, info, warning, err := a.Identities.Create(workspaceID)
	if err != nil {
		return info, warning, identityError(err)
	}
	return info, warning, d.Close()
}

func (a *App) IdentityInfo() (info identity.PublicInfo, err error) {
	defer apperr.NormalizeInto(&err)
	workspaceID, err := a.WorkspaceID()
	if err != nil {
		return info, err
	}
	info, err = a.Identities.Info(workspaceID)
	if err != nil {
		return info, identityError(err)
	}
	return info, nil
}

func (a *App) DiagnoseIdentity(ctx context.Context) identity.Diagnosis {
	return a.Identities.Doctor(ctx)
}

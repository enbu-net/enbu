package app

import (
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
)

func (a *App) CreateIdentity() (info identity.PublicInfo, warning string, err error) {
	defer apperr.NormalizeInto(&err)
	workspaceID, err := a.WorkspaceID()
	if err != nil {
		return info, "", err
	}
	id, info, warning, err := a.Identities.Create(workspaceID)
	if err != nil {
		return info, warning, err
	}
	err = id.Close()
	return info, warning, err
}

func (a *App) IdentityInfo() (info identity.PublicInfo, err error) {
	defer apperr.NormalizeInto(&err)
	workspaceID, err := a.WorkspaceID()
	if err != nil {
		return info, err
	}
	return a.Identities.Info(workspaceID)
}

func (a *App) DiagnoseIdentity() identity.Diagnosis { return a.Identities.Doctor() }

func (a *App) LoadWorkspaceIdentities() (ids []agecrypto.Identity, err error) {
	defer apperr.NormalizeInto(&err)
	id, err := a.WorkspaceID()
	if err != nil {
		return nil, err
	}
	return LoadIdentities(a.Identities, id)
}

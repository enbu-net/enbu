package app

import (
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
)

func (a *App) CreateIdentity() (info identity.PublicInfo, warning string, err error) {
	defer apperr.NormalizeInto(&err)
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return info, "", err
	}
	id, info, warning, err := a.Identities.Create(owner, repo)
	if err != nil {
		return info, warning, err
	}
	err = id.Close()
	return info, warning, err
}

func (a *App) IdentityInfo() (info identity.PublicInfo, err error) {
	defer apperr.NormalizeInto(&err)
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return info, err
	}
	return a.Identities.Info(owner, repo)
}

func (a *App) DiagnoseIdentity() identity.Diagnosis { return a.Identities.Doctor() }

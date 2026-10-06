package app

import (
	"errors"
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"io/fs"
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
	if err := id.Close(); err != nil {
		return info, warning, err
	}
	signer, signerInfo, signerWarning, err := a.Identities.CreateSigner(workspaceID)
	if err != nil {
		return info, warning, err
	}
	info.DeviceID, info.Fingerprint = string(signerInfo.DeviceID), signerInfo.Fingerprint
	if warning == "" {
		warning = signerWarning
	}
	return info, warning, signer.Close()
}

func (a *App) IdentityInfo() (info identity.PublicInfo, err error) {
	defer apperr.NormalizeInto(&err)
	workspaceID, err := a.WorkspaceID()
	if err != nil {
		return info, err
	}
	info, err = a.Identities.Info(workspaceID)
	if err != nil {
		return info, err
	}
	signerInfo, err := a.Identities.SignerInfo(workspaceID)
	if errors.Is(err, fs.ErrNotExist) {
		// A workspace set up before signing keys existed has none yet.
		return info, nil
	}
	if err != nil {
		return info, err
	}
	info.DeviceID, info.Fingerprint = string(signerInfo.DeviceID), signerInfo.Fingerprint
	return info, nil
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

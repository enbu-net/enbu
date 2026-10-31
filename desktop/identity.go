package desktop

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

// GetIdentity describes this device's keys in the selected workspace, as
// `enbu identity show` does.
func (s *Service) GetIdentity() (identity.PublicInfo, error) {
	return withRepoResult(s, func() (identity.PublicInfo, error) { return s.app.IdentityInfo() })
}

// DiagnoseIdentity probes the hardware and the OS keyring, as `enbu doctor`
// does. It needs no repository.
func (s *Service) DiagnoseIdentity() identity.Diagnosis {
	return s.app.DiagnoseIdentity()
}

// UpgradeIdentity switches this device to a hybrid ML-KEM key. A member's new
// key waits for an admin's approval; an admin's own is switched at once.
func (s *Service) UpgradeIdentity() (app.KeyUpdateResult, error) {
	return withRepoResult(s, func() (app.KeyUpdateResult, error) {
		result, err := s.app.UpgradeIdentity(s.context())
		if err != nil {
			return app.KeyUpdateResult{}, err
		}
		return *result, nil
	})
}

// ImportSecrets adds every variable of a dotenv file's content to env, as
// `enbu import` does. The frontend reads the file the person chose.
func (s *Service) ImportSecrets(env, dotenv string, overwrite bool) (app.ImportResult, error) {
	return withRepoResult(s, func() (app.ImportResult, error) {
		secrets, err := secretmap.ImportDotenv([]byte(dotenv))
		if err != nil {
			return app.ImportResult{}, apperr.Wrap(apperr.CodeInvalidArgument, "not a valid dotenv file", err, nil)
		}
		result, err := s.app.ImportSecrets(s.context(), env, secrets, overwrite)
		if err != nil {
			return app.ImportResult{}, err
		}
		return *result, nil
	})
}

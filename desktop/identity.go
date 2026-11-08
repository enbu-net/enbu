package desktop

import (
	"log/slog"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/identity"
)

// GetIdentity describes this device's keys in the selected workspace, as
// `enbu identity show` does.
func (s *Service) GetIdentity() (identity.PublicInfo, error) {
	return withRepoResult(s, func() (identity.PublicInfo, error) { return s.app.IdentityInfo() })
}

// IdentityDiagnosis is what DiagnoseIdentity shows. The probes' reasons are OS
// error text, so they go to the log and never to the screen.
type IdentityDiagnosis struct {
	Backend           string `json:"backend"`
	Device            string `json:"device,omitempty"`
	Available         bool   `json:"available"`
	FallbackAvailable bool   `json:"fallback_available"`
	// Fallback is the software backend a new key would use: keyring or
	// systemd-creds.
	Fallback string `json:"fallback,omitempty"`
}

// DiagnoseIdentity probes the hardware and the software key storage, as `enbu doctor`
// does. It needs no repository.
func (s *Service) DiagnoseIdentity() IdentityDiagnosis {
	d := s.app.DiagnoseIdentity(s.context())
	slog.Info("DiagnoseIdentity", "backend", d.Backend, "available", d.Available, "reason", d.Reason,
		"fallback_available", d.FallbackAvailable, "fallback_reason", d.FallbackReason)
	return IdentityDiagnosis{
		Backend:           d.Backend,
		Device:            d.Device,
		Available:         d.Available,
		FallbackAvailable: d.FallbackAvailable,
		Fallback:          d.Fallback,
	}
}

// ImportSecrets adds every variable of a dotenv file's content to env, as
// `enbu import` does. The frontend reads the file the person chose.
func (s *Service) ImportSecrets(env, content string, overwrite bool) (app.ImportResult, error) {
	return withRepoResult(s, func() (app.ImportResult, error) {
		result, err := s.app.ImportDotenv(s.context(), env, []byte(content), overwrite)
		if err != nil {
			return app.ImportResult{}, err
		}
		return *result, nil
	})
}

package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/enbu-net/enbu/pkg/config"
)

// TeamMigration models an offline checkout across a production migration. Names
// are reused, but history and pending work belong to the original incarnation.
func (w *World) TeamMigration(ctx context.Context) error {
	a, b := w.Devices[0].App, w.Devices[1].App
	if err := a.CreateEnvironment("staging"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := b.SwitchEnvironment("staging"); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "staging", "ENDPOINT", "old-service"); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "staging", "RETIRED", "remove-me"); err != nil {
		return err
	}
	w.Model["staging"] = map[string]string{"ENDPOINT": "old-service", "RETIRED": "remove-me"}
	if err := w.Check(ctx, "staging"); err != nil {
		return err
	}
	output := filepath.Join(b.RepositoryDir, ".env.staging")
	if err := os.WriteFile(output, []byte("LOCAL_ONLY=developer\n"), 0600); err != nil {
		return err
	}
	if err := b.PullSecretsToFile(ctx, "staging"); err != nil {
		return err
	}
	// The offline laptop misses the shared configuration change entirely.
	w.Devices[1].Store.Arm(Fault{"*", 0, "partition"})
	if err := a.RenameEnvironment("staging", "production"); err != nil {
		return err
	}
	if err := a.CreateEnvironment("staging"); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "staging", "ENDPOINT", "new-sandbox"); err != nil {
		return err
	}
	if err := a.EditSecret(ctx, "production", "ENDPOINT", "released-service"); err != nil {
		return err
	}
	if err := a.DeleteSecret(ctx, "production", "RETIRED"); err != nil {
		return err
	}
	// Do not compact yet: returning developers need history to classify .env keys
	// removed by their colleagues, including values edited locally.
	w.Model["production"] = map[string]string{"ENDPOINT": "released-service"}
	w.Model["staging"] = map[string]string{"ENDPOINT": "new-sandbox"}
	w.Devices[1].Store.Arm(Fault{})
	w.Restart(1)
	b = w.Devices[1].App
	// An old name in an old checkout must still address the old incarnation.
	got, err := b.ListSecrets(ctx, "staging")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, w.Model["production"]) {
		return fmt.Errorf("stale checkout crossed environment incarnations: %v", got)
	}
	if err := b.AddSecret(ctx, "staging", "OFFLINE_WORK", "retained"); err != nil {
		return err
	}
	w.Model["production"]["OFFLINE_WORK"] = "retained"
	if err := w.Share(0); err != nil {
		return err
	}
	for _, env := range []string{"production", "staging"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	// The developer moves their local file along with the renamed deployment.
	productionOutput := filepath.Join(b.RepositoryDir, ".env.production")
	if err := os.Rename(output, productionOutput); err != nil {
		return err
	}
	output = productionOutput
	if err := b.PullSecretsToFile(ctx, "production"); err != nil {
		return err
	}
	if err := w.checkOutput("migration-file", output, map[string]string{"ENDPOINT": "released-service", "OFFLINE_WORK": "retained", "LOCAL_ONLY": "developer"}); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(b.RepositoryDir)
	if err != nil {
		return err
	}
	if cfg.Resource("production") == cfg.Resource("staging") {
		return fmt.Errorf("migration reused resource identity")
	}
	// Switch deliberately and replace the generated file so production credentials
	// are absent from the recreated sandbox. Personal selection stays per device.
	if err := b.SwitchEnvironment("staging"); err != nil {
		return err
	}
	if _, err := b.PullSecretsToFileWith(ctx, "staging", true); err != nil {
		return err
	}
	if err := w.checkOutput("migration-sandbox", filepath.Join(b.RepositoryDir, ".env.staging"), w.Model["staging"]); err != nil {
		return err
	}
	for _, env := range []string{"production", "staging"} {
		if _, err := a.CompactHistory(ctx, env, 1); err != nil {
			return err
		}
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	for _, env := range []string{"production", "staging", "default"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

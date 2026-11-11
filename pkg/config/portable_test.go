package config

import (
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestEnvironmentNamesCannotAliasPortableOutputs(t *testing.T) {
	for _, name := range []string{".", "..", "prod."} {
		t.Run(name, func(t *testing.T) {
			if ValidEnvironmentName(name) {
				t.Fatal("accepted a name whose output aliases another path on Windows")
			}
		})
	}
	for _, operation := range []string{"create", "rename"} {
		t.Run(operation, func(t *testing.T) {
			cfg := NewProjectWithEnvironment("prod")
			var err error
			if operation == "create" {
				err = cfg.AddEnvironment("PROD")
			} else {
				if err := cfg.AddEnvironment("staging"); err != nil {
					t.Fatal(err)
				}
				err = cfg.RenameEnvironment("staging", "PROD")
			}
			if !apperr.Is(err, apperr.CodeEnvironmentExists) {
				t.Fatalf("portable output collision accepted: %v", err)
			}
		})
	}
}

func TestParseProjectRejectsUnsafeEnvironmentConfiguration(t *testing.T) {
	for _, content := range []string{
		"[env.prod]\noutput = '../outside.env'\n",
		"[env.prod]\noutput = '/outside.env'\n",
		"[env.prod]\noutput = '/'\n",
		"[env.prod]\noutput = '//server/share/env'\n",
		"[env.prod]\noutput = '/./outside.env'\n",

		"[env.prod]\noutput = '..\\outside.env'\n",
		"[env.prod]\noutput = 'C:/outside.env'\n",
		"[env.prod]\noutput = '.env:private'\n",
		"[env.prod]\noutput = '.env.prod'\n[env.PROD]\noutput = '.env.PROD'\n",
		"[env.'prod.']\noutput = '.env.prod.'\n",
		"[env.prod]\noutput = ' .env'\n",
		"[env.prod]\noutput = '.env '\n",
		"[env.prod]\noutput = 'shared.env'\n[env.staging]\noutput = 'SHARED.env'\n",
		"[env.prod]\n[env.staging]\noutput = './.ENV.prod'\n",
		"[env.prod]\noutput = 'dir/../shared.env'\n[env.staging]\noutput = 'shared.env'\n",
		"[env.prod]\noutput = 'secrets/Σ.env'\n[env.staging]\noutput = 'secrets/ς.env'\n",
		"[env.K]\n[env.'K']\n",
	} {
		t.Run(content, func(t *testing.T) {
			if _, err := ParseProject("version = 'v1alpha2'\n" + content); err == nil {
				t.Fatal("hand-edited unsafe configuration was accepted")
			}
		})
	}
}

func TestSameNameRenamePreservesConfiguration(t *testing.T) {
	cfg := NewProjectWithEnvironment("prod")
	before, err := MarshalProject(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.RenameEnvironment("prod", "prod"); !apperr.Is(err, apperr.CodeEnvironmentExists) {
		t.Fatalf("same-name rename accepted: %v", err)
	}
	after, err := MarshalProject(cfg)
	if err != nil || string(before) != string(after) {
		t.Fatalf("rejected rename changed configuration: %v", err)
	}
}

func TestReservedEnvironmentNameHasPrefixedOutput(t *testing.T) {
	cfg, err := ParseProject("version = 'v1alpha2'\n[env.CON]\n[env.NUL]\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CON", "NUL"} {
		env, err := cfg.Environment(name)
		if err != nil || env.Output != ".env."+name {
			t.Fatalf("reserved environment name lacks safe output prefix: %v", err)
		}
	}
}

func TestCaseOnlyRenamePreservesEnvironmentLineage(t *testing.T) {
	cfg := NewProjectWithEnvironment("prod")
	incarnation := cfg.Environments["prod"].Incarnation
	if err := cfg.RenameEnvironment("prod", "PROD"); err != nil {
		t.Fatal(err)
	}
	if cfg.HasEnvironment("prod") || !cfg.HasEnvironment("PROD") || cfg.Environments["PROD"].Incarnation != incarnation {
		t.Fatal("case-only rename replaced the environment lineage")
	}
	data, err := MarshalProject(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProject(string(data)); err != nil {
		t.Fatalf("portable mixed-case configuration was rejected: %v", err)
	}
}

// Outputs may use Japanese and spaces: they are the same relative path on
// every OS.
func TestParseProjectAcceptsNonASCIIOutputs(t *testing.T) {
	cfg, err := ParseProject("version = 'v1alpha2'\n[env.prod]\noutput = '設定/本番 環境.env'\n[env.staging]\noutput = 'secrets/ステージング.env'\n")
	if err != nil {
		t.Fatal(err)
	}
	env, err := cfg.Environment("prod")
	if err != nil || env.Output != "設定/本番 環境.env" {
		t.Fatalf("prod = %+v, %v", env, err)
	}
}

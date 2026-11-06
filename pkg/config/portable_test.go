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
		"[env.prod]\noutput = '..\\outside.env'\n",
		"[env.prod]\noutput = 'C:/outside.env'\n",
		"[env.prod]\noutput = '.env:private'\n",
		"[env.prod]\noutput = '.env.prod'\n[env.PROD]\noutput = '.env.PROD'\n",
		"[env.'prod.']\noutput = '.env.prod.'\n",
	} {
		t.Run(content, func(t *testing.T) {
			if _, err := ParseProject("version = 'v1alpha2'\n" + content); err == nil {
				t.Fatal("hand-edited unsafe configuration was accepted")
			}
		})
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

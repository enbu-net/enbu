package main

import (
	"os"
	"regexp"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestCIShardsCoverEveryPRModelOnce keeps the formal job's matrix in step with
// checks.toml: a model no shard selects would silently stop being checked.
func TestCIShardsCoverEveryPRModelOnce(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/ci.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Models []struct {
						Name string `yaml:"name"`
						Run  string `yaml:"run"`
					} `yaml:"models"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	shards := wf.Jobs["formal"].Strategy.Matrix.Models
	if len(shards) == 0 {
		t.Fatal("ci.yaml has no formal job with a models matrix")
	}
	m, err := Load("../../spec/tla/checks.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, model := range m.Model {
		if model.Tier != "pr" {
			continue
		}
		var selected []string
		for _, s := range shards {
			if regexp.MustCompile(s.Run).MatchString(model.Name) {
				selected = append(selected, s.Name)
			}
		}
		if len(selected) != 1 {
			t.Errorf("model %q is selected by %d shards %v, want exactly one", model.Name, len(selected), selected)
		}
	}
}

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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

// TestEveryFuzzTargetIsListed keeps task fuzz/run (and the nightly fuzzing
// built on it) in step with the fuzz functions in the repository.
func TestEveryFuzzTargetIsListed(t *testing.T) {
	b, err := os.ReadFile("../../Taskfile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var tf struct {
		Vars map[string]string `yaml:"vars"`
	}
	if err := yaml.Unmarshal(b, &tf); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, item := range strings.Fields(tf.Vars["FUZZ_TARGETS"]) {
		listed[item] = true
	}
	found := map[string]bool{}
	err = filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && slices.Contains(skipDirs, d.Name()) {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("../..", filepath.Dir(path))
		for _, m := range regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`).FindAllStringSubmatch(string(src), -1) {
			found[filepath.ToSlash(rel)+":"+m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for f := range found {
		if !listed[f] {
			t.Errorf("fuzz target %s is missing from FUZZ_TARGETS in Taskfile.yaml", f)
		}
	}
	for l := range listed {
		if !found[l] {
			t.Errorf("FUZZ_TARGETS lists %s, which does not exist", l)
		}
	}
}

// TestNightlyFuzzMatrixMatchesTheTaskfile keeps the nightly fuzz jobs in step
// with FUZZ_TARGETS.
func TestNightlyFuzzMatrixMatchesTheTaskfile(t *testing.T) {
	b, err := os.ReadFile("../../Taskfile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var tf struct {
		Vars map[string]string `yaml:"vars"`
	}
	if err := yaml.Unmarshal(b, &tf); err != nil {
		t.Fatal(err)
	}
	w, err := os.ReadFile("../../.github/workflows/verification.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Target []string `yaml:"target"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(w, &wf); err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(tf.Vars["FUZZ_TARGETS"])
	got := wf.Jobs["fuzz"].Strategy.Matrix.Target
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Fatalf("nightly fuzz matrix %v differs from FUZZ_TARGETS %v", got, want)
	}
}

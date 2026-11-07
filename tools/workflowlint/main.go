// workflowlint validates native parallel groups before passing every contained
// step to actionlint. v1.7.12 predates Actions' June 2026 parallel syntax; remove
// this adapter when upstream supports it instead of suppressing syntax errors.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"go.yaml.in/yaml/v3"
)

func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// Inspect runner labels and matrix values, including include/exclude entries.
// This deliberately rejects ubuntu-latest so image upgrades remain explicit.
var ubuntuLabel = regexp.MustCompile(`ubuntu-[A-Za-z0-9.-]+`)

func validateUbuntu(n *yaml.Node) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		for _, label := range ubuntuLabel.FindAllString(n.Value, -1) {
			if label != "ubuntu-26.04" && label != "ubuntu-26.04-arm" {
				return fmt.Errorf("line %d: Ubuntu runner %q is forbidden; use ubuntu-26.04 or ubuntu-26.04-arm", n.Line, label)
			}
		}
	}
	for _, child := range n.Content {
		if err := validateUbuntu(child); err != nil {
			return err
		}
	}
	return nil
}

func normalize(data []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 {
		return nil, fmt.Errorf("expected one workflow document")
	}
	jobs := field(doc.Content[0], "jobs")
	if jobs != nil {
		for i := 1; i < len(jobs.Content); i += 2 {
			job := jobs.Content[i]
			for _, node := range []*yaml.Node{field(job, "runs-on"), field(field(job, "strategy"), "matrix")} {
				if err := validateUbuntu(node); err != nil {
					return nil, err
				}
			}
		}
	}
	changed := false
	if jobs != nil {
		for i := 1; i < len(jobs.Content); i += 2 {
			steps := field(jobs.Content[i], "steps")
			if steps == nil {
				continue
			}
			var flattened []*yaml.Node
			for _, step := range steps.Content {
				parallel := field(step, "parallel")
				if parallel == nil {
					flattened = append(flattened, step)
					continue
				}
				if len(step.Content) != 2 || parallel.Kind != yaml.SequenceNode || len(parallel.Content) < 1 {
					return nil, fmt.Errorf("line %d: parallel must be a standalone nonempty group", step.Line)
				}
				for _, child := range parallel.Content {
					if child.Kind != yaml.MappingNode || field(child, "parallel") != nil || field(child, "background") != nil || field(child, "wait") != nil || field(child, "wait-all") != nil || field(child, "cancel") != nil {
						return nil, fmt.Errorf("line %d: parallel children must be ordinary steps", child.Line)
					}
					flattened = append(flattened, child)
				}
				changed = true
			}
			steps.Content = flattened
		}
	}
	if !changed {
		return data, nil
	}
	return yaml.Marshal(&doc)
}

func run() error {
	paths, err := filepath.Glob(".github/workflows/*.yaml")
	if err != nil {
		return err
	}
	other, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil {
		return err
	}
	paths = append(paths, other...)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data, err = normalize(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		cmd := exec.Command("go", "run", "github.com/rhysd/actionlint/cmd/actionlint@v1.7.12", "-color", "-ignore", `specifying action "\$/\.github/actions/[^" ]+" in invalid format because ref is missing`, "-stdin-filename", path, "-")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

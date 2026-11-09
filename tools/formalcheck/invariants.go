package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Invariant is one row of the invariants table.
type Invariant struct {
	ID  string
	TLA []string // Model.Property
	Go  []string // test, fuzz or property function names
}

var (
	reRow     = regexp.MustCompile(`^\|\s*([A-Z]+-\d+)\s*\|[^|]*\|(?:[^|]*\|)?([^|]*)\|([^|]*)\|\s*$`)
	reID      = regexp.MustCompile(`\b((?:AUTH|FORK|CP|STATE|REJOIN|GEN|AVAIL|RCPT|SYNC|ERR|TRUST|CRYPTO|INPUT|MERGE)-\d+)\b`)
	reGoFunc  = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`)
	skipDirs  = []string{".git", "node_modules", ".tmp", "dist", "web", "vscode"}
	noneCheck = "—"
)

// ParseInvariants reads the table rows of an invariants file.
func ParseInvariants(text string) ([]Invariant, error) {
	var out []Invariant
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		m := reRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		inv := Invariant{ID: m[1], TLA: splitNames(m[2]), Go: splitNames(m[3])}
		if seen[inv.ID] {
			return nil, fmt.Errorf("invariant %s is listed twice", inv.ID)
		}
		seen[inv.ID] = true
		out = append(out, inv)
	}
	if len(out) == 0 {
		return nil, errors.New("no invariant rows found")
	}
	return out, nil
}

func splitNames(cell string) []string {
	cell = strings.TrimSpace(strings.ReplaceAll(cell, "`", ""))
	if cell == "" || cell == noneCheck || cell == "n/a" || strings.HasPrefix(cell, "assumed") {
		return nil
	}
	var out []string
	for _, n := range strings.Split(cell, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// CheckInvariants requires every invariant to have a check, every named TLA+
// property and Go test to exist, and every ID a model mentions to be listed.
func CheckInvariants(path, specDir, root string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	invs, err := ParseInvariants(string(b))
	if err != nil {
		return err
	}
	modules := map[string]string{}
	entries, err := os.ReadDir(specDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tla") {
			t, err := os.ReadFile(filepath.Join(specDir, e.Name()))
			if err != nil {
				return err
			}
			modules[strings.TrimSuffix(e.Name(), ".tla")] = string(t)
		} else if e.IsDir() {
			// Protocol models live in Model/Model.tla; refinement models
			// live directly under spec/conformance.
			path := filepath.Join(specDir, e.Name(), e.Name()+".tla")
			if b, err := os.ReadFile(path); err == nil {
				modules[e.Name()] = string(b)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	funcs, err := goTestFuncs(root)
	if err != nil {
		return err
	}
	var problems []string
	listed := map[string]bool{}
	for _, inv := range invs {
		listed[inv.ID] = true
		if len(inv.TLA) == 0 && len(inv.Go) == 0 {
			problems = append(problems, inv.ID+": no check")
		}
		for _, ref := range inv.TLA {
			model, prop, ok := strings.Cut(ref, ".")
			text, found := modules[model]
			if !ok || !found || !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(prop)+`\b.*==`).MatchString(text) {
				problems = append(problems, fmt.Sprintf("%s: TLA+ property %s does not exist", inv.ID, ref))
			}
		}
		for _, name := range inv.Go {
			if !funcs[name] {
				problems = append(problems, fmt.Sprintf("%s: Go test %s does not exist", inv.ID, name))
			}
		}
	}
	for model, text := range modules {
		for _, m := range reID.FindAllStringSubmatch(text, -1) {
			if !listed[m[1]] {
				problems = append(problems, fmt.Sprintf("%s.tla mentions %s, which %s does not list", model, m[1], path))
			}
		}
	}
	slices.Sort(problems)
	problems = slices.Compact(problems)
	if len(problems) > 0 {
		return fmt.Errorf("%d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

func goTestFuncs(root string) (map[string]bool, error) {
	funcs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range reGoFunc.FindAllStringSubmatch(string(b), -1) {
			funcs[m[1]] = true
		}
		return nil
	})
	return funcs, err
}

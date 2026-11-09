package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const passOutput = `Model checking completed. No error has been found.
<Init line 1, col 1 to line 1, col 4 of module M>: 1:1
<Act line 2, col 1 to line 2, col 3 of module M>: 5:9
<Idle line 3, col 1 to line 3, col 4 of module M>: 0:0
<x line 4, col 5 to line 4, col 5 of module M>: 3
12 states generated, 1,234 distinct states found, 0 states left on queue.`

func TestJudgePassRequiresCompletionCoverageAndStates(t *testing.T) {
	model := Model{Name: "m", Uncovered: []string{"Idle"}, MinStates: 1000}
	j := Job{Model: model, Expect: "pass", Coverage: true}
	if err := Judge(j, passOutput, nil); err != nil {
		t.Fatalf("a complete run with allowed dead actions should pass: %v", err)
	}
	for _, out := range []string{
		"Model checking completed. No error has been found.\n1,234 distinct states found",
		"Model checking completed. No error has been found.\n1,234 distinct states found\n<Act line malformed>: 1:2",
	} {
		if err := Judge(j, out, nil); err == nil || !strings.Contains(err.Error(), "action coverage") {
			t.Fatalf("missing or malformed coverage passed: %v", err)
		}
	}
	j.Model.Uncovered = nil
	if err := Judge(j, passOutput, nil); err == nil || !strings.Contains(err.Error(), "Idle") {
		t.Fatalf("a dead action must fail the run, got %v", err)
	}
	j.Model.Uncovered, j.Model.MinStates = []string{"Idle"}, 5000
	if err := Judge(j, passOutput, nil); err == nil || !strings.Contains(err.Error(), "min_states") {
		t.Fatalf("too few states must fail the run, got %v", err)
	}
	if err := Judge(Job{Model: Model{}, Expect: "pass"}, "Error: Parsing or semantic analysis failed.", errors.New("exit 150")); err == nil {
		t.Fatal("a run that did not complete must fail")
	}
	if err := Judge(Job{Model: Model{}, Expect: "pass"}, "Error: Invariant Safe is violated.", errors.New("exit 12")); err == nil || !strings.Contains(err.Error(), "Safe") {
		t.Fatalf("a violation must fail a passing model, got %v", err)
	}
}

func TestJudgeViolationNeedsTheNamedProperty(t *testing.T) {
	j := Job{Expect: "violation", Violates: []string{"Safe", "Other"}}
	if err := Judge(j, "Error: Invariant Other is violated.\n", errors.New("exit 12")); err != nil {
		t.Fatalf("a listed property caught it: %v", err)
	}
	if err := Judge(j, "Error: Invariant Unrelated is violated.\n", errors.New("exit 12")); err == nil {
		t.Fatal("a mutant caught by an unlisted property must fail")
	}
	if err := Judge(j, passOutput, nil); err == nil || !strings.Contains(err.Error(), "found no error") {
		t.Fatalf("a surviving mutant must fail, got %v", err)
	}
	if err := Judge(j, "Error: TLC threw an unexpected exception.", errors.New("exit 75")); err == nil || !strings.Contains(err.Error(), "without a property violation") {
		t.Fatalf("a crash is not a caught mutant, got %v", err)
	}
	if err := Judge(Job{Expect: "violation", Violates: []string{"temporal"}}, "Error: Temporal properties were violated.", errors.New("exit 13")); err != nil {
		t.Fatalf("temporal violations are recognised: %v", err)
	}
}

func TestPlanSeedsMutantsAndIsolatesWitnesses(t *testing.T) {
	cfg := "CONSTANTS\n    Witnessing = FALSE\n    Mutant = \"none\"\nSPECIFICATION Spec\nINVARIANT A\nINVARIANT B\nPROPERTY L\n"
	model := Model{Name: "m", Module: "M.tla", Config: "M.cfg",
		Mutant:  []Mutant{{Name: "bug", Violates: []string{"A"}}},
		Witness: []Witness{{Invariant: "W"}}}
	jobs, err := Plan(model, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("want model, mutant and witness runs, got %d", len(jobs))
	}
	if !jobs[0].Coverage || jobs[0].Expect != "pass" || jobs[0].Config != cfg {
		t.Fatalf("the model itself runs unchanged with coverage: %+v", jobs[0])
	}
	if !strings.Contains(jobs[1].Config, `Mutant = "bug"`) || strings.Contains(jobs[1].Config, `"none"`) {
		t.Fatalf("the mutant run must select the bug:\n%s", jobs[1].Config)
	}
	w := jobs[2].Config
	if strings.Contains(w, "INVARIANT A") || strings.Contains(w, "PROPERTY L") || !strings.Contains(w, "INVARIANT W") {
		t.Fatalf("a witness run checks only the witness:\n%s", w)
	}
	if !strings.Contains(w, "Witnessing = TRUE") {
		t.Fatalf("a witness run turns on the model's bookkeeping:\n%s", w)
	}
	if _, err := Plan(model, "SPECIFICATION Spec\n"); err == nil {
		t.Fatal("mutants need a Mutant constant in the config")
	}
}

func TestLoadRejectsIncompleteManifests(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"tier":      "[[model]]\nname='m'\nmodule='M.tla'\nconfig='M.cfg'\ntier='weekly'\n",
		"duplicate": "[[model]]\nname='m'\nmodule='M.tla'\nconfig='M.cfg'\ntier='pr'\n[[model]]\nname='m'\nmodule='M.tla'\nconfig='M.cfg'\ntier='pr'\n",
		"mutant":    "[[model]]\nname='m'\nmodule='M.tla'\nconfig='M.cfg'\ntier='pr'\n  [[model.mutant]]\n  name='bug'\n",
		"unknown":   "[[model]]\nname='m'\nmodule='M.tla'\nconfig='M.cfg'\ntier='pr'\nexpect='pass'\n",
	}
	for name, body := range cases {
		path := filepath.Join(dir, name+".toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s: manifest should be rejected", name)
		}
	}
}

func TestWitnessRemovesWholeMultilineDeclarations(t *testing.T) {
	cfg := `CONSTANTS
  Mutant = "none"
  Label = "INVARIANTS not a declaration"
INVARIANTS
  Safe
  (* PROPERTY Commented *) Other
PROPERTIES Live
  AlsoLive
\* INVARIANT CommentedOut
SPECIFICATION Spec
CHECK_DEADLOCK FALSE
`
	jobs, err := Plan(Model{Witness: []Witness{{Invariant: "Witness"}}}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := jobs[1].Config
	decls := propertyDeclarations(w)
	if len(decls) != 1 || strings.Join(decls[0].names, ",") != "Witness" {
		t.Fatalf("witness retained other properties:\n%s", w)
	}
	for _, keep := range []string{`Label = "INVARIANTS not a declaration"`, "SPECIFICATION Spec", "CHECK_DEADLOCK FALSE"} {
		if !strings.Contains(w, keep) {
			t.Errorf("lost %q from witness config:\n%s", keep, w)
		}
	}
}

func TestTheRepositoryManifestIsValid(t *testing.T) {
	m, err := Load("../../spec/conformance/checks.toml")
	if err != nil {
		t.Fatal(err)
	}
	tiers := map[string]int{}
	for _, model := range m.Model {
		tiers[model.Tier]++
		cfg, err := os.ReadFile(filepath.Join("../../spec/conformance", model.Config))
		if err != nil {
			t.Fatalf("%s: %v", model.Name, err)
		}
		if _, err := os.Stat(filepath.Join("../../spec/conformance", model.Module)); err != nil {
			t.Fatalf("%s: %v", model.Name, err)
		}
		if _, err := Plan(model, string(cfg)); err != nil {
			t.Fatalf("%s: %v", model.Name, err)
		}
	}
	if tiers["pr"] == 0 || tiers["nightly"] == 0 {
		t.Fatalf("both tiers need models: %v", tiers)
	}
}

func TestInvariantsTable(t *testing.T) {
	text := "| ID | Property | TLA+ | Go |\n|----|---|---|---|\n" +
		"| AUTH-1 | x | M.Safe | TestA, TestB |\n" +
		"| GEN-7 | y | — | TestC |\n"
	invs, err := ParseInvariants(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 2 || invs[0].TLA[0] != "M.Safe" || len(invs[0].Go) != 2 || invs[1].TLA != nil {
		t.Fatalf("parsed %+v", invs)
	}
	if _, err := ParseInvariants(text + "| AUTH-1 | again | M.Safe | TestA |\n"); err == nil {
		t.Fatal("duplicate IDs must be rejected")
	}

	dir := t.TempDir()
	spec := filepath.Join(dir, "spec")
	if err := os.MkdirAll(spec, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(spec, "M.tla"), "---- MODULE M ----\n\\* AUTH-1 and MERGE-1\nSafe == TRUE\n====\n")
	write(filepath.Join(dir, "a_test.go"), "package a\nfunc TestA(t *testing.T) {}\nfunc TestC(t *testing.T) {}\n")
	table := filepath.Join(dir, "INVARIANTS.md")
	write(table, text)
	err = CheckInvariants(table, spec, dir)
	if err == nil {
		t.Fatal("missing TestB and the unlisted MERGE-1 must be reported")
	}
	for _, want := range []string{"TestB does not exist", "mentions MERGE-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	write(table, text+"| MERGE-1 | z | M.Missing | — |\n")
	if err := CheckInvariants(table, spec, dir); err == nil || !strings.Contains(err.Error(), "M.Missing does not exist") {
		t.Fatalf("a missing TLA+ property must be reported, got %v", err)
	}
}

func TestProtocolInvariantTableHasEnforcementColumn(t *testing.T) {
	text := "| AUTH-1 | Parent authority | `VerifyChild` | `ControlDAG.AUTH_1` | TestA |\n" +
		"| CRYPTO-1 | PQ only | `ParseRecipient` | assumed (`signer` field) | TestB |\n"
	invs, err := ParseInvariants(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 2 || len(invs[0].TLA) != 1 || invs[0].TLA[0] != "ControlDAG.AUTH_1" || invs[0].Go[0] != "TestA" || len(invs[1].TLA) != 0 {
		t.Fatalf("protocol table parsed incorrectly: %+v", invs)
	}
}

func TestBothRepositoryInvariantTablesResolve(t *testing.T) {
	for _, layer := range []struct{ table, models string }{
		{"../../spec/INVARIANTS.md", "../../spec/tla"},
		{"../../spec/IMPLEMENTATION_INVARIANTS.md", "../../spec/conformance"},
	} {
		if err := CheckInvariants(layer.table, layer.models, "../.."); err != nil {
			t.Errorf("%s: %v", layer.table, err)
		}
	}
}

func TestIndexedPropertiesMustBeEnabledBySelectedConfigs(t *testing.T) {
	for _, layer := range []string{"protocol", "refinement"} {
		t.Run(layer, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, body string) {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			model, cfg := "M/M.tla", "M/M.cfg"
			if layer == "refinement" {
				model, cfg = "M.tla", "M.cfg"
				write("MC.tla", "---- MODULE MC ----\nEXTENDS M\n====\n")
				write("checks.toml", "[[model]]\nname='m'\nmodule='MC.tla'\nconfig='M.cfg'\ntier='pr'\n")
				write("orphan.cfg", "INVARIANT Safe\n")
			}
			write(model, "---- MODULE M ----\nSafe == TRUE\n====\n")
			write("INVARIANTS.md", "| AUTH-1 | x | M.Safe | — |\n")
			write(cfg, "SPECIFICATION Spec\n\\* INVARIANT Safe\n")
			table := filepath.Join(dir, "INVARIANTS.md")
			if err := CheckInvariants(table, dir, dir); err == nil || !strings.Contains(err.Error(), "not enabled") {
				t.Fatalf("defined but disabled property passed: %v", err)
			}
			write(cfg, "INVARIANTS\n  Safe\nSPECIFICATION Spec\n")
			if err := CheckInvariants(table, dir, dir); err != nil {
				t.Fatalf("enabled indexed property failed: %v", err)
			}
		})
	}
}

func TestRunExecutesEveryCheckOfATier(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs a POSIX shell for the fake TLC")
	}
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("M.tla", "---- MODULE M ----\n====\n", 0o600)
	write("M.cfg", "CONSTANTS\n    Mutant = \"none\"\nINVARIANT Safe\n", 0o600)
	write("checks.toml", `[[model]]
name = "m"
module = "M.tla"
config = "M.cfg"
tier = "pr"
  [[model.mutant]]
  name = "bug"
  violates = ["Safe"]
[[model]]
name = "deep"
module = "M.tla"
config = "M.cfg"
tier = "nightly"
`, 0o600)
	// The fake TLC passes the plain model and catches the mutant, and checks
	// it runs in a scratch copy of the models with the generated config.
	tlc := filepath.Join(dir, "fake-tlc")
	write("fake-tlc", `#!/bin/sh
test -f M.tla || { echo "no model copy"; exit 2; }
if grep -q '"bug"' run.cfg; then
  echo "Error: Invariant Safe is violated."; exit 12
fi
echo "Model checking completed. No error has been found."
echo "3 states generated, 3 distinct states found, 0 states left on queue."
echo "<Act line 2, col 1 to line 2, col 3 of module M>: 3:3"
`, 0o700)
	if err := Run(dir, "pr", "", tlc, 2, 1, time.Minute); err != nil {
		t.Fatalf("pr tier: %v", err)
	}
	t.Chdir(dir)
	if err := Run(dir, "pr", "", "./fake-tlc", 2, 1, time.Minute); err != nil {
		t.Fatalf("relative TLC path must survive scratch execution: %v", err)
	}
	if err := Run(dir, "pr", "^nothing$", tlc, 2, 1, time.Minute); err == nil {
		t.Fatal("selecting no model must fail")
	}
	write("fake-tlc", "#!/bin/sh\necho \"Model checking completed. No error has been found.\"\n", 0o700)
	if err := Run(dir, "pr", "", tlc, 2, 1, time.Minute); err == nil {
		t.Fatal("a surviving mutant must fail the tier")
	}
}

package simulation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func mutationSource(data []byte, old, replacement string) ([]byte, error) {
	// Windows checkouts can use CRLF; edit the disposable source with LF so
	// multi-line mutation anchors describe the same Go code on every platform.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !bytes.Contains(data, []byte(old)) {
		return nil, fmt.Errorf("mutation target disappeared: %q", old)
	}
	return bytes.Replace(data, []byte(old), []byte(replacement), 1), nil
}

// Keep recordings outside the disposable source tree, including when a child
// fails before the experiment can score its behavioral assertion.
func mutationArtifacts(name, phase string) (string, error) {
	root := os.Getenv("ENBU_SIM_ARTIFACTS")
	if root == "" {
		root = filepath.Join(os.TempDir(), "enbu-simulation-failures")
	}
	return filepath.Abs(filepath.Join(root, "mutations", name, phase))
}

func TestMutationArtifactsSurviveSourceCleanup(t *testing.T) {
	if os.Getenv("ENBU_SIM_ARTIFACT_CHILD") == "1" {
		dir := os.Getenv("ENBU_SIM_ARTIFACTS")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "recording.json"), []byte("recorded"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, phase := range []string{"control", "mutant"} {
		t.Run(phase, func(t *testing.T) {
			artifacts := t.TempDir()
			t.Setenv("ENBU_SIM_ARTIFACTS", artifacts)
			dir, err := mutationArtifacts("example", phase)
			if err != nil {
				t.Fatal(err)
			}
			source := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(t.Context(), executable, "-test.run=^TestMutationArtifactsSurviveSourceCleanup$")
			child.Dir = source
			child.Env = append(os.Environ(), "ENBU_SIM_ARTIFACT_CHILD=1", "ENBU_SIM_ARTIFACTS="+dir)
			if out, err := child.CombinedOutput(); err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(artifacts, "mutations", "example", phase, "recording.json"))
			if err != nil || string(raw) != "recorded" {
				t.Fatalf("recording lost after source cleanup: %q, %v", raw, err)
			}
		})
	}
}

func TestMutationTargetsMatchLFAndCRLF(t *testing.T) {
	for _, tc := range mutationCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../..", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
			crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
			left, err := mutationSource(lf, tc.old, tc.new)
			if err != nil {
				t.Fatal(err)
			}
			right, err := mutationSource(crlf, tc.old, tc.new)
			if err != nil || !bytes.Equal(left, right) {
				t.Fatalf("mutation differs across checkout line endings: %v", err)
			}
			if bytes.Equal(left, lf) {
				t.Fatal("mutation left source unchanged")
			}
		})
	}
	if _, err := mutationSource([]byte("source"), "missing target", "replacement"); err == nil {
		t.Fatal("missing mutation target was silently accepted")
	}
}

var mutationCases = []struct{ name, file, old, new, scenario string }{
	{"discard-accepted-retired-branch", "app/workspace.go", "slices.Contains(accepted.Heads, h.Digest) && s.view.MembershipUnbroken", "false && slices.Contains(accepted.Heads, h.Digest) && s.view.MembershipUnbroken", "TestRetainedObserverSmoke"},
	{"contact-fetches-before-root-check", "pkg/wsp/trust.go", "if pinned != (Root{}) && pinned != root {", "if false && pinned != (Root{}) && pinned != root {", "TestFirstContactSmoke"},
	{"control-view-forgets-checkpoint-witness", "pkg/wsp/checkpoint.go", "return f, nil", "f.Control = nil\n\treturn f, nil", "TestObserverControlEquivocationSmoke"},
	{"decrypt-before-checkpoint-check", "app/workspace.go", "err = s.cps.CheckStates(resource, sv.Graph, sv.Compacted.Excuses)", "err = nil", "TestObserverEquivocationSmoke/disjoint"},
	{"reader-view-excuses-missing-head", "pkg/wsp/checkpoint.go", "return func(d digest.Digest) bool { return g.Has(d) || excused != nil && excused(d) }", "return func(d digest.Digest) bool { return true }", "TestObserverEquivocationSmoke/disjoint"},
	{"lost-update", "app/secrets.go", "secrets[key] = value", "delete(secrets,key)", "TestScenarios/concurrent-keys"},
	{"missed-conflict", "app/secrets.go", "func conflictError(cs []merge.Conflict) error {", "func conflictError(cs []merge.Conflict) error { return nil;", "TestScenarios/conflicting-edits"},
	{"privilege-escalation", "app/members.go", "if p, _ := s.head.Principal(s.self()); !p.Admin {", "if p, _ := s.head.Principal(s.self()); !p.Admin && false {", "TestScenarios/membership"},
	{"missed-rollback", "app/workspace.go", "return nil, wspError(fmt.Errorf(\"%w: all previously accepted revisions are missing\", wsp.ErrRollback))", "return nil,storageError(storage.ErrNotFound)", "TestScenarios/adversarial-storage"},
	{"restored-store-misses-witness", "pkg/wsp/checkpoint.go", "return f, nil", "return checkpointFile{Version: checkpointVersion}, nil", "TestDisasterRecoverySmoke/witness"},
	{"history-drops-unreadable-ancestry", "app/history.go", "chronological(h.states)", "chronological(func() map[digest.Digest]*wsp.VerifiedState { out := map[digest.Digest]*wsp.VerifiedState{}; for d, r := range h.states { if known[d].Readable { out[d] = r } }; return out }())", "TestHistorySnapshotSmoke/backward/list/remove"},
	{"delete-late-valid-state", "app/compact.go", "return err != nil && !errors.Is(err, wsp.ErrRollback), nil", "return true, nil", "TestCompactionLatePublicationAndCrashRecovery"},
	{"delete-temporarily-unreachable-state", "app/compact.go", "case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):\n\t\treturn false, nil", "case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):\n\t\treturn true, nil", "TestCompactionLatePublicationAndCrashRecovery"},
	{"wrong-observer-acceptance-epoch", "app/workspace.go", "s.view.MembershipUnbroken(s.head.Digest, accepted.Control, s.self())", "s.view.MembershipUnbroken(s.head.Digest, h.Control, s.self())", "TestAcceptanceEpochSmoke"},
	{"revive-revoked-author", "pkg/wsp/state.go", "if !view.MembershipUnbroken(head.Digest, st.Control, st.Author) {", "if false && !view.MembershipUnbroken(head.Digest, st.Control, st.Author) {", "TestAcceptanceEpochSmoke"},
	{"skip-state-signature-verification", "pkg/wsp/state.go", "if err := signing.Verify(author.Signing, signing.DomainState, signed.Body, signed.Signature); err != nil {", "if err := signing.Verify(author.Signing, signing.DomainState, signed.Body, signed.Signature); err != nil && false {", "TestScenarios/forged-state-signature"},
	{"control-parent-admin-check", "pkg/wsp/control.go", "if !ok || !author.Admin {\n\t\t\treturn nil, invalid(\"control author", "if !ok {\n\t\t\treturn nil, invalid(\"control author", "TestAuthorityAttackSmoke/member-promotes-self"},
	{"compaction-admin-check", "pkg/wsp/compaction.go", "if !ok || !author.Admin {", "if !ok {", "TestAuthorityAttackSmoke/member-excuses-rollback"},
	{"fork-resolution-authority", "pkg/wsp/control.go", "if err := checkResolution(parents, c); err != nil {", "if err := checkResolution(parents, c); err != nil && false {", "TestAuthorityAttackSmoke/fork-promotes-member"},
	{"control-work-limit", "pkg/wsp/chain.go", "if len(revs) > maxControls {", "if len(revs) > maxControls && false {", "TestScenarios/metadata-control-count"},
	{"skip-head-recheck", "app/secrets.go", "if !sameHeads(s.trustedHeads(latest, accepted), cur.heads) {", "if false && !sameHeads(s.trustedHeads(latest, accepted), cur.heads) {", "TestScenarios/contention-edit-exhausted"},
	{"premature-retry-exhaustion", "app/secrets.go", "const maxRetries = 3", "const maxRetries = 1", "TestScenarios/contention-edit-yield"},
	{"unbounded-retries", "app/secrets.go", "attempt < attempts", "true", "TestScenarios/contention-edit-exhausted"},
	{"discard-pull-context", "app/secrets.go", "func (a *App) PullSecretsToFileWith(ctx context.Context, env string, replace bool) (written *WrittenFile, err error) {", "func (a *App) PullSecretsToFileWith(ctx context.Context, env string, replace bool) (written *WrittenFile, err error) { ctx = context.Background();", "TestActualContextCancellationRecovery/pull-file/blob-context-before"},
	{"permissive-wire-decoder", "pkg/wsp/codec.go", "func decodeCanonical(data []byte, v any) error {", "func decodeCanonical(data []byte, v any) error { if err := cbor.Unmarshal(data, v); err != nil { return invalid(\"decode: %v\", err) }; return nil;", "TestScenarios/wire-format-warm"},
	{"unsafe-output-overwrite", "app/secrets.go", "if err := writePrivateOutput(ctx, outputPath, dotenv); err != nil {", "if err := os.WriteFile(outputPath, dotenv, 0o600); err != nil {", "TestScenarios/output-boundary-hardlink"},
	{"skip-config-read-validation", "pkg/config/config.go", "if err := ValidateProjectOutputs(&cfg); err != nil {", "if err := ValidateProjectOutputs(&cfg); err != nil && false {", "TestScenarios/portable-config"},
	{"case-sensitive-environment-collision", "pkg/config/config.go", "existing != except && strings.EqualFold(existing, name)", "existing != except && existing == name", "TestScenarios/portable-config"},
	{"trailing-dot-environment", "pkg/config/config.go", " || strings.HasSuffix(name, \".\")", "", "TestScenarios/portable-config"},
	{"colliding-environment-outputs", "pkg/config/config.go", "if strings.EqualFold(previous, clean) {", "if strings.EqualFold(previous, clean) && false {", "TestScenarios/portable-config"},
	{"skip-project-save-validation", "app/app.go", "if err := config.ValidateProjectOutputs(cfg); err != nil {", "if err := config.ValidateProjectOutputs(cfg); err != nil && false {", "TestScenarios/portable-config"},
	{"control-rejected-ref-dedup", "pkg/wsp/chain.go", "if tried[rev] {", "if tried[rev] && false {", "TestScenarios/metadata-control-duplicate"},
	{"state-work-limit", "pkg/wsp/state.go", "if len(revs) > maxRevisions {", "if len(revs) > maxRevisions && false {", "TestScenarios/metadata-state-count"},
	{"compaction-work-limit", "pkg/wsp/compaction.go", "if len(revs) > maxCompactions {", "if len(revs) > maxCompactions && false {", "TestScenarios/metadata-compaction-count"},
	{"join-request-work-limit", "pkg/wsp/join.go", "if len(revs) > maxJoinRequestRefs {", "if len(revs) > maxJoinRequestRefs && false {", "TestScenarios/request-flood"},
	{"request-conflict-display-cap", "app/members.go", "out = append(out, p)", "out = append(out, p); if len(out) >= maxJoinRequests { break }", "TestScenarios/hidden-request-conflict"},
	{"join-request-signature", "pkg/wsp/join.go", "if err := signing.Verify(r.Signing, signing.DomainJoin, s.Body, s.Signature); err != nil {", "if err := signing.Verify(r.Signing, signing.DomainJoin, s.Body, s.Signature); err != nil && false {", "TestScenarios/request-signature-attack"},
}

// Mutation experiments edit only disposable copies. A compile error is not a
// killed mutant: the intended behavioral test must report an actual failure.
func TestOracleMutationExperiments(t *testing.T) {
	if os.Getenv("ENBU_SIM_MUTATION") != "1" {
		t.Skip("set ENBU_SIM_MUTATION=1 for isolated source mutation experiments")
	}

	for _, tc := range mutationCases {
		t.Run(tc.name, func(t *testing.T) {
			// Partition experiments, but run each experiment's complete control
			// and mutant scenario without inherited exploration partitions.
			shardCase(t)
			root := t.TempDir()
			for _, dir := range []string{"app", "pkg", "test/simulation"} {
				if e := os.CopyFS(filepath.Join(root, dir), os.DirFS(filepath.Join("../..", dir))); e != nil {
					t.Fatal(e)
				}
			}
			for _, name := range []string{"go.mod", "go.sum"} {
				b, e := os.ReadFile(filepath.Join("../..", name))
				if e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			controlArtifacts, err := mutationArtifacts(tc.name, "control")
			if err != nil {
				t.Fatal(err)
			}
			mutantArtifacts, err := mutationArtifacts(tc.name, "mutant")
			if err != nil {
				t.Fatal(err)
			}
			// Windows needs just over five minutes for the complete compaction
			// control matrix (run 42365186731). Keep all control cases and leave
			// headroom; a timeout still cannot count as killing the mutant.
			control := exec.CommandContext(t.Context(), "go", "test", "-json", "-p=1", "-count=1", "-timeout=10m", "-tags=fixture", "./test/simulation", "-run", "^"+tc.scenario+"$")
			control.Dir = root
			control.Env = append(os.Environ(), "GITHUB_SHA="+revision(t), "ENBU_SIM_MUTATION=0", "ENBU_SIM_EXPLORE=1", "ENBU_SIM_CASE_STRIDE=1", "ENBU_SIM_SHARDS=1", "ENBU_SIM_SHARD=0", "ENBU_SIM_ARTIFACTS="+controlArtifacts)
			if output, err := control.CombinedOutput(); err != nil {
				t.Fatalf("unmodified control failed; mutant cannot be scored: %v\n%s", err, output)
			}
			path := filepath.Join(root, tc.file)
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			b, e = mutationSource(b, tc.old, tc.new)
			if e != nil {
				t.Fatalf("%s: %v", tc.file, e)
			}
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.CommandContext(t.Context(), "go", "test", "-json", "-p=1", "-count=1", "-timeout=10m", "-tags=fixture", "./test/simulation", "-run", "^"+tc.scenario+"$")
			cmd.Dir = root
			cmd.Env = append(append([]string(nil), control.Env...), "ENBU_SIM_ARTIFACTS="+mutantArtifacts)
			out, e := cmd.CombinedOutput()
			if e == nil {
				t.Fatalf("mutant survived:\n%s", out)
			}
			killed := false
			for _, line := range bytes.Split(out, []byte("\n")) {
				var event struct{ Action, Test string }
				if json.Unmarshal(line, &event) == nil && event.Action == "fail" && event.Test == tc.scenario {
					killed = true
				}
			}
			if !killed {
				t.Fatalf("mutant did not fail the intended behavioral assertion:\n%s", out)
			}
		})
	}
}

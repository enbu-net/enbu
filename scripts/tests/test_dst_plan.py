import json
import re
import subprocess
from datetime import date

import pytest

import dst_plan


def selected(plan, name):
    return bool(re.fullmatch(plan["tests"], name))


@pytest.mark.parametrize(
    "path",
    [
        "app/app.go",
        "app/members.go",
        "pkg/auth/token.go",
        "pkg/storage/oci.go",
        "pkg/clock/clock.go",
        "test/simulation/session_http_test.go",
    ],
)
def test_native_session_team_follows_credentials_and_team_dependencies(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestNativeSessionTeamSmoke")
    assert selected(plan, "TestNativeSessionTeamClocks")
    assert selected(plan, "TestNativeReadOnlyTeamSmoke")
    assert selected(plan, "TestNativeTransientTeamSmoke")


def test_auth_changes_do_not_select_unrelated_merge_matrix():
    plan = dst_plan.select(["pkg/auth/token.go"])
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


@pytest.mark.parametrize(
    "path",
    [
        "app/members.go",
        "pkg/wsp/state.go",
        "pkg/wsp/checkpoint.go",
        "pkg/clock/clock.go",
        "test/simulation/retained_observer.go",
    ],
)
def test_retained_observer_follows_authority_and_checkpoint_changes(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestRetainedObserverSmoke")
    assert selected(plan, "TestRetainedObserverClocks")


@pytest.mark.parametrize(
    "path",
    [
        "app/history.go",
        "app/history_index.go",
        "app/members.go",
        "app/upgrade.go",
        "pkg/wsp/checkpoint.go",
        "pkg/wsp/state.go",
        "pkg/clock/clock.go",
        "pkg/identity/manager.go",
    ],
)
def test_team_history_and_recovery_follow_related_dependencies(path):
    plan = dst_plan.select([path])
    for name in (
        "TestHistorySnapshotSmoke",
        "TestHistorySnapshotClocks",
        "TestDisasterRecoverySmoke",
        "TestDisasterRecoveryClocks",
        "TestRecoveryProbeRejectsRecordedStorageWrites",
    ):
        assert selected(plan, name), (path, name)


def test_history_snapshot_driver_selects_its_family_without_unrelated_matrices():
    plan = dst_plan.select(["test/simulation/history_snapshot.go"])
    assert selected(plan, "TestHistorySnapshotSmoke")
    assert selected(plan, "TestHistorySnapshotClocks")
    assert selected(plan, "TestSimulation")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


@pytest.mark.parametrize(
    "path",
    [
        "app/secrets.go",
        "app/members.go",
        "pkg/wsp/state.go",
        "pkg/wsp/checkpoint.go",
        "pkg/clock/clock.go",
    ],
)
def test_larger_teams_follow_related_dependencies(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestLargerTeamClocks")
    assert selected(plan, "TestLargerTeamSmoke")


def test_larger_team_driver_selects_its_family_without_unrelated_matrices():
    plan = dst_plan.select(["test/simulation/larger_team_test.go"])
    assert selected(plan, "TestLargerTeamClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


@pytest.mark.parametrize(
    "path",
    [
        "app/secrets.go",
        "app/members.go",
        "pkg/wsp/state.go",
        "pkg/wsp/checkpoint.go",
        "pkg/clock/clock.go",
    ],
)
def test_observer_equivocation_follows_related_dependencies(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestObserverEquivocationClocks")
    assert selected(plan, "TestObserverEquivocationSmoke")
    assert selected(plan, "TestObserverControlEquivocationSmoke")
    assert selected(plan, "TestObserverControlEquivocationClocks")


def test_observer_equivocation_helper_selects_its_family():
    plan = dst_plan.select(["test/simulation/observer_equivocation.go"])
    assert selected(plan, "TestObserverEquivocationClocks")
    assert selected(plan, "TestObserverEquivocationSmoke")
    assert selected(plan, "TestObserverControlEquivocationSmoke")
    assert selected(plan, "TestObserverControlEquivocationClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_observer_control_helper_selects_its_family():
    plan = dst_plan.select(["test/simulation/observer_control.go"])
    assert selected(plan, "TestObserverControlEquivocationSmoke")
    assert selected(plan, "TestObserverControlEquivocationClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_full_run_discovers_all_tests_and_enables_security_checks():
    plan = dst_plan.select([], full=True)
    assert plan["run"] and plan["mutation"] and plan["merge"]
    assert plan["mode"] == "full"
    for path in dst_plan.SIM.glob("*_test.go"):
        for name in dst_plan.names(path) - {"TestOracleMutationExperiments"}:
            assert selected(plan, name), name


@pytest.mark.parametrize(
    "paths", [["web/src/routes/index.tsx"], ["README.md"], ["pkg/config/README.md"], []]
)
def test_unrelated_changes_skip_dst(paths):
    plan = dst_plan.select(paths)
    assert not plan["run"]
    assert plan["tests"] == "^$"


@pytest.mark.parametrize(
    ("path", "included", "excluded"),
    [
        (
            "app/secrets.go",
            "TestConcurrentOperationMatrix",
            "TestConcurrentAdminMatrix",
        ),
        (
            "app/members.go",
            "TestTeamMembershipWriteMatrix",
            "TestThreeWayMergeDAGMatrix",
        ),
        ("app/history.go", "TestConcurrentHistoryRestore", "TestConcurrentAdminMatrix"),
        (
            "pkg/merge/merge.go",
            "TestThreeWayMergeDAGMatrix",
            "TestConcurrentAdminMatrix",
        ),
        (
            "pkg/clock/clock.go",
            "TestMultiUserClockProfiles",
            "TestMultiUserSwarmMatrix",
        ),
        (
            "test/simulation/swarm.go",
            "TestMultiUserSwarmMatrix",
            "TestThreeWayMergeDAGMatrix",
        ),
    ],
)
def test_related_domains_are_selected_without_unrelated_matrices(
    path, included, excluded
):
    plan = dst_plan.select([path])
    assert plan["run"] and plan["mode"] == "incremental"
    assert selected(plan, included)
    assert not selected(plan, excluded)


@pytest.mark.parametrize(
    "path",
    [
        "go.mod",
        "pkg/wsp/new_shared_protocol.go",
        "app/workspace.go",
        "test/simulation/deleted_test.go",
    ],
)
def test_shared_or_unknown_code_conservatively_widens_selection(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestTeamMembershipWriteMatrix")
    assert selected(plan, "TestThreeWayMergeDAGMatrix")


def test_workflow_changes_only_run_regressions_for_the_execution_contract():
    plan = dst_plan.select([".github/workflows/simulation.yaml"])
    assert selected(plan, "TestSeedPartitionPreservesWorkload")
    assert selected(
        plan, "TestRestartReconstructsProcessDependenciesFromDurableFixtures"
    )
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_mutation_change_cannot_silently_skip_the_mutation_suite():
    plan = dst_plan.select(["test/simulation/mutation_test.go"])
    assert plan["run"] and plan["mutation"]
    assert not selected(plan, "TestOracleMutationExperiments")


def test_diff_uses_push_before_and_after(monkeypatch):
    def output(command, **_kwargs):
        assert command == ["git", "diff", "--name-only", "-z", "old", "new"]
        return b"app/secrets.go\0path with spaces\0"

    monkeypatch.setattr(dst_plan.subprocess, "check_output", output)
    assert dst_plan.changed({"before": "old", "after": "new"}) == [
        "app/secrets.go",
        "path with spaces",
    ]


def test_first_push_uses_default_branch_merge_base(monkeypatch):
    calls = []

    def output(command, **kwargs):
        calls.append(command)
        if kwargs.get("text"):
            return "base\n"
        return b"app/history.go\0"

    monkeypatch.setattr(dst_plan.subprocess, "check_output", output)
    assert dst_plan.changed(
        {"before": "0" * 40, "after": "new", "repository": {"default_branch": "main"}}
    ) == ["app/history.go"]
    assert calls[0] == ["git", "merge-base", "HEAD", "refs/remotes/origin/main"]
    assert calls[1][-2:] == ["base", "new"]


def test_missing_old_commit_never_skips_coverage(monkeypatch):
    def output(command, **_kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(dst_plan.subprocess, "check_output", output)
    assert dst_plan.changed({"before": "missing", "after": "new"}) == ["go.mod"]


@pytest.mark.parametrize("path", ["app/members.go", "pkg/wsp/checkpoint.go"])
def test_acceptance_epoch_matrix_runs_for_membership_and_checkpoint_changes(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestAcceptanceEpochSurvivesReadmissionAndAuthorRemoval")
    assert selected(plan, "TestAcceptanceEpochSmoke")


@pytest.mark.parametrize(
    "path",
    [
        "app/members.go",
        "app/secrets.go",
        "pkg/wsp/checkpoint.go",
        "test/simulation/team_incident.go",
    ],
)
def test_team_incident_workflow_is_selected(path):
    assert selected(dst_plan.select([path]), "TestTeamIncidentMatrix")


@pytest.mark.parametrize(
    "path",
    [
        "app/members.go",
        "pkg/wsp/control.go",
        "pkg/wsp/compaction.go",
        "test/simulation/authority_attack.go",
    ],
)
def test_authority_attacks_are_selected(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestAuthorityAttackSmoke")
    assert selected(plan, "TestAuthorityAttackMatrix")


@pytest.mark.parametrize("path", ["app/secrets.go", "test/simulation/workload.go"])
def test_workload_changes_select_generated_exploration(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestSimulation")
    assert selected(plan, "TestGeneratedTeamGroupsPreservePriorWork")
    assert selected(plan, "TestGeneratedTeamGroupNightlyRegressions")
    assert selected(plan, "TestGeneratedTeamGroupNightlyRegressionSmoke")


def test_nightly_corpus_changes_select_its_regressions():
    plan = dst_plan.select(["test/simulation/testdata/nightly-regressions.json"])
    assert selected(plan, "TestGeneratedTeamGroupNightlyRegressions")
    assert selected(plan, "TestGeneratedTeamGroupNightlyRegressionSmoke")


@pytest.mark.parametrize(
    "path",
    [
        "test/simulation/secret_formats.go",
        "test/simulation/request_attack.go",
        "test/simulation/scenarios.go",
    ],
)
def test_scenario_helpers_select_scenarios_without_unrelated_matrices(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestScenarios")
    assert selected(plan, "TestSimulation")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


@pytest.mark.parametrize(
    "path", ["app/secrets.go", "app/members.go", "pkg/wsp/checkpoint.go"]
)
def test_shared_user_and_workspace_journeys_are_selected(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestSameUserProcessClocks")
    assert selected(plan, "TestLostDeviceReplacementClocks")
    assert selected(plan, "TestPartialKeyRecoveryClocks")
    assert selected(plan, "TestRequestFloodClocks")
    assert selected(plan, "TestMetadataFloodClocks")
    assert selected(plan, "TestMultipleWorkspaceClocks")
    assert selected(plan, "TestGitWorktreeClocks")


def test_shared_concurrent_fixture_selects_restore_and_local_process_users():
    plan = dst_plan.select(["test/simulation/concurrent_matrix.go"])
    assert selected(plan, "TestConcurrentHistoryRestore")
    assert selected(plan, "TestSameUserProcessClocks")
    assert selected(plan, "TestScenarios")


def test_multi_workspace_helper_selects_its_clock_matrix():
    plan = dst_plan.select(["test/simulation/multi_workspace.go"])
    assert selected(plan, "TestMultipleWorkspaceClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_partial_key_helper_selects_recovery_matrix():
    plan = dst_plan.select(["test/simulation/partial_keys.go"])
    assert selected(plan, "TestPartialKeyRecoveryClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_git_worktree_helper_selects_its_clock_matrix():
    plan = dst_plan.select(["test/simulation/git_worktrees.go"])
    assert selected(plan, "TestGitWorktreeClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_request_flood_helper_selects_its_clock_matrix():
    plan = dst_plan.select(["test/simulation/request_flood.go"])
    assert selected(plan, "TestRequestFloodClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_metadata_flood_helper_selects_its_clock_matrix():
    plan = dst_plan.select(["test/simulation/metadata_flood.go"])
    assert selected(plan, "TestMetadataFloodClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


def test_contention_helper_and_secret_changes_select_progress_matrix():
    for path in ["test/simulation/contention.go", "app/secrets.go"]:
        plan = dst_plan.select([path])
        assert selected(plan, "TestContentionClocks")


@pytest.mark.parametrize(
    "path",
    [
        "pkg/storage/stream_cancellation_test.go",
        "pkg/wsp/state_test.go",
        "pkg/identity/partial_loss_test.go",
        "app/secrets_test.go",
    ],
)
def test_native_test_only_changes_do_not_repeat_dst(path):
    plan = dst_plan.select([path])
    assert not plan["run"]
    assert not plan["mutation"]
    assert not plan["merge"]
    assert plan["tests"] == "^$"


def test_native_test_changes_do_not_hide_implementation_changes_or_full_runs():
    paths = ["pkg/storage/stream_cancellation_test.go", "app/secrets.go"]
    plan = dst_plan.select(paths)
    assert plan["run"] and plan["mutation"]
    assert selected(plan, "TestContentionClocks")
    plan = dst_plan.select([paths[0]], full=True)
    assert plan["run"] and plan["mutation"] and plan["merge"]
    assert selected(plan, "TestOperationFaultMatrix")


@pytest.mark.parametrize("helper", ["partition_test.go", "simulation_test.go"])
def test_shared_simulation_test_helpers_select_every_matrix(helper):
    plan = dst_plan.select(["test/simulation/" + helper])
    assert plan["run"] and plan["mutation"]
    for name in [
        "TestContentionClocks",
        "TestPartialKeyRecoveryClocks",
        "TestThreeWayMergeDAGMatrix",
    ]:
        assert selected(plan, name)


def test_wire_attack_helper_and_protocol_changes_select_wire_matrix():
    for path in [
        "test/simulation/wire_attack.go",
        "pkg/wsp/control.go",
        "pkg/wsp/codec.go",
    ]:
        plan = dst_plan.select([path])
        assert selected(plan, "TestSignedWireAttackClocks")


def test_output_changes_select_team_filesystem_boundaries():
    for path in [
        "test/simulation/output_boundary.go",
        "app/output.go",
        "app/secrets.go",
        "app/environments.go",
    ]:
        assert selected(dst_plan.select([path]), "TestOutputBoundaryClocks")


def test_config_changes_select_portable_team_configuration():
    for path in [
        "test/simulation/portable_config.go",
        "app/config.go",
        "app/environments.go",
        "pkg/config/config.go",
    ]:
        assert selected(dst_plan.select([path]), "TestPortableConfigClocks")


@pytest.mark.parametrize("path", ["pkg/apperr/error.go", "pkg/new_dependency/new.go"])
def test_unclassified_dependencies_select_all_simulations(path):
    plan = dst_plan.select([path])
    assert plan["run"] and plan["mutation"]
    for source in dst_plan.SIM.glob("*_test.go"):
        for name in dst_plan.names(source) - {"TestOracleMutationExperiments"}:
            assert selected(plan, name)


@pytest.mark.parametrize(
    "path", ["app/secrets.go", "test/simulation/output_boundary.go"]
)
def test_incremental_plans_execute_configured_generated_seeds(path):
    assert selected(dst_plan.select([path]), "TestSimulation")


@pytest.mark.parametrize(
    "path",
    [
        "app/init.go",
        "app/members.go",
        "pkg/wsp/trust.go",
        "pkg/wsp/state.go",
        "pkg/clock/clock.go",
    ],
)
def test_first_contact_follows_related_dependencies(path):
    plan = dst_plan.select([path])
    assert selected(plan, "TestFirstContactSmoke")
    assert selected(plan, "TestFirstContactClocks")


def test_first_contact_helper_selects_its_family():
    plan = dst_plan.select(["test/simulation/first_contact.go"])
    assert selected(plan, "TestFirstContactSmoke")
    assert selected(plan, "TestFirstContactClocks")
    assert not selected(plan, "TestThreeWayMergeDAGMatrix")


@pytest.mark.parametrize(
    "path",
    [
        "app/secrets.go",
        "pkg/auth/token.go",
        "test/simulation/clock_test.go",
        ".github/workflows/simulation.yaml",
    ],
)
def test_full_signature_seed_is_retained_in_every_selected_native_exploration(path):
    plan = dst_plan.select([path])
    assert plan["run"]
    assert selected(plan, "TestFullSignatureAttackSeedRegressionSmoke")
    assert selected(plan, "TestStateSignatureAttackSmoke")


def targets(platforms):
    return [p["target"] for p in platforms]


def test_incremental_dst_runs_linux_amd64_only():
    assert targets(dst_plan.platforms("incremental", "push", date(2026, 11, 11))) == [
        "linux-amd64"
    ]


def test_manual_full_dst_explores_every_platform():
    assert dst_plan.platforms("full", "workflow_dispatch", date(2026, 11, 11)) == (
        dst_plan.PLATFORMS
    )


def test_nightly_dst_explores_linux_and_rotates_the_slower_platforms():
    seen = set()
    for offset in range(len(dst_plan.ROTATION)):
        day = date.fromordinal(date(2026, 11, 11).toordinal() + offset)
        tonight = targets(dst_plan.platforms("full", "schedule", day))
        assert tonight[:2] == ["linux-amd64", "linux-arm64"]
        assert len(tonight) == 3
        seen |= set(tonight)
    # Every platform gets the complete exploration within the rotation.
    assert seen == set(targets(dst_plan.PLATFORMS))


def test_main_hands_the_matrix_a_json_platform_list(tmp_path, monkeypatch):
    event = tmp_path / "event.json"
    event.write_text("{}")
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    dst_plan.main()
    lines = dict(line.split("=", 1) for line in output.read_text().splitlines())
    platforms = json.loads(lines["platforms"])
    assert len(platforms) == 3
    assert all(set(p) == {"target", "runner"} for p in platforms)


@pytest.mark.parametrize(
    ("split", "original"),
    [
        ("app/conflicts.go", "app/secrets.go"),
        ("app/write.go", "app/secrets.go"),
        ("app/join_requests.go", "app/members.go"),
        ("app/reencrypt.go", "app/members.go"),
    ],
)
def test_split_app_files_select_like_their_origin(split, original):
    assert dst_plan.select([split]) == dst_plan.select([original])

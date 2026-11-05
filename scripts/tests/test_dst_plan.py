import re
import subprocess

import pytest

import dst_plan


def selected(plan, name):
    return bool(re.fullmatch(plan["tests"], name))


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

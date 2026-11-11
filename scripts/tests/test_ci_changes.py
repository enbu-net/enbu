import pytest

import ci_changes


@pytest.mark.parametrize(
    "paths",
    [
        ["README.md"],
        ["README.ja.md", "AGENTS.md", "ROADMAP.md"],
        ["docs/storage.md", "docs/images/flow.svg"],
        ["LICENSE", ".coderabbit.yaml", ".github/pull_request_template.md"],
    ],
)
def test_docs_only_changes_skip_code_jobs(paths):
    assert ci_changes.select(paths) == {"code": False}


@pytest.mark.parametrize(
    "path",
    [
        # A test reads it, so it is not documentation for CI.
        "test/simulation/README.md",
        "vscode/README.md",
        "web/AGENTS.md",
        "app/app.go",
        "web/src/main.tsx",
        "renovate.json",
    ],
)
def test_any_other_path_runs_code_jobs(path):
    assert ci_changes.select(["README.md", path])["code"]


def test_pull_requests_select_from_their_diff(monkeypatch, tmp_path):
    output = tmp_path / "out"
    monkeypatch.setattr(
        ci_changes.subprocess,
        "check_output",
        lambda *a, **k: b"README.md\0docs/storage.md\0",
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    ci_changes.main()
    assert output.read_text().split() == ["code=false"]


@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch"])
def test_main_runs_everything(monkeypatch, tmp_path, event):
    output = tmp_path / "out"
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    ci_changes.main()
    assert output.read_text().split() == ["code=true"]


def test_unreadable_diff_runs_everything(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise ci_changes.subprocess.CalledProcessError(128, args[0])

    output = tmp_path / "out"
    monkeypatch.setattr(ci_changes.subprocess, "check_output", fail)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    ci_changes.main()
    assert output.read_text().split() == ["code=true"]

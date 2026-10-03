import json
import subprocess
from pathlib import Path

import pytest

import tobari as coverage


def test_discovers_all_packages_with_tests(monkeypatch):
    def run(command, **kwargs):
        assert command[-1] == "./..."
        return subprocess.CompletedProcess(command, 0, "\nb/a\nb/z\n\n")

    monkeypatch.setattr(coverage.subprocess, "run", run)
    assert coverage.packages({}) == ["b/a", "b/z"]


def test_collect_isolates_packages_and_preserves_failed_test_data(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(coverage, "OUTPUT", tmp_path)
    monkeypatch.setattr(
        coverage,
        "packages",
        lambda _: [coverage.MODULE + "/app", coverage.MODULE + "/cli"],
    )
    monkeypatch.setattr(
        coverage.subprocess, "check_output", lambda *_, **__: "-cover -toolexec=tobari"
    )
    stale = tmp_path / "unit" / "stale.json"
    stale.parent.mkdir()
    stale.write_text("stale")
    (tmp_path / "unit.json").write_text("stale merged suite")
    (tmp_path / "merged.json").write_text("stale combined report")
    destinations = []
    merged = []

    def run(command, **kwargs):
        env = kwargs["env"]
        destinations.append(env["TOBARI_COVERDIR"])
        assert "-coverpkg=" in env["GOFLAGS"]
        assert env["ENBU_TEST_COVERAGE_DIR"] == str(tmp_path / "unit" / "processes")
        report = Path(env["TOBARI_COVERDIR"]) / "tobari" / "tobari.json"
        report.parent.mkdir(parents=True)
        report.write_text("{}")
        return subprocess.CompletedProcess(command, int(command[-1].endswith("/app")))

    monkeypatch.setattr(coverage.subprocess, "run", run)
    monkeypatch.setattr(
        coverage,
        "merge",
        lambda directory, _: merged.extend(coverage.report_paths(directory)),
    )
    assert coverage.collect("unit") == 1
    assert len(set(destinations)) == 2
    assert len(merged) == 2
    assert not stale.exists()
    assert not (tmp_path / "unit.json").exists()
    assert not (tmp_path / "merged.json").exists()


def test_missing_report_fails_even_when_go_test_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(coverage, "OUTPUT", tmp_path)
    monkeypatch.setattr(coverage, "packages", lambda _: [coverage.MODULE])
    monkeypatch.setattr(coverage.subprocess, "check_output", lambda *_, **__: "-cover")
    monkeypatch.setattr(
        coverage.subprocess,
        "run",
        lambda command, **_: subprocess.CompletedProcess(command, 0),
    )
    monkeypatch.setattr(coverage, "merge", lambda *_: None)
    assert coverage.collect("unit") == 1


def test_merge_refuses_empty_reports(tmp_path):
    with pytest.raises(RuntimeError, match="No coverage reports"):
        coverage.merge(tmp_path, tmp_path / "merged.json")


def test_merge_copies_single_report_without_invoking_tobari(tmp_path, monkeypatch):
    directory = tmp_path / "suite"
    directory.mkdir()
    (directory / "report.json").write_text('{"metadata": {}}')
    monkeypatch.setattr(
        coverage.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("unexpected merge"),
    )
    destination = tmp_path / "merged.json"
    coverage.merge(directory, destination)
    assert destination.read_text() == '{"metadata": {}}'


def test_summarize_uses_statement_weights_and_global_counts(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "metadata": {"all": [[0, 1, 1, 2, 1, 3], [0, 3, 1, 4, 1, 1]]},
                "allcounts": [0, 4],
                "counts": [{"name": "test"}],
            }
        )
    )
    coverage.summarize(report)
    assert "1/4 statements; 1 named scopes" in capsys.readouterr().out

from pathlib import Path

import pytest

from generate_release_notes import (
    ReleaseNotesError,
    collect_assets,
    main,
    render_release_notes,
)


def create_assets(directory: Path, *names: str) -> None:
    directory.mkdir()
    for name in names:
        (directory / name).touch()


def test_collects_assets_and_renders_sorted_download_table(tmp_path: Path) -> None:
    assets_dir = tmp_path / "release-assets"
    create_assets(
        assets_dir,
        "enbu_v1.2.3_windows_arm64.zip",
        "enbu-desktop_v1.2.3_linux_arm64.tar.gz",
        "enbu_v1.2.3_darwin_arm64.tar.gz",
        "enbu-desktop_v1.2.3_windows_arm64.zip",
        "enbu_v1.2.3_linux_arm64.tar.gz",
        "enbu-desktop_v1.2.3_darwin_arm64.dmg",
        "enbu_v1.2.3_linux_amd64.tar.gz",
        "enbu-desktop_v1.2.3_linux_amd64.tar.gz",
        "enbu_v1.2.3_windows_amd64.zip",
        "enbu-desktop_v1.2.3_windows_amd64.zip",
        "enbu-vscode_v1.2.3_darwin_arm64.vsix",
        "enbu-vscode_v1.2.3_linux_amd64.vsix",
        "enbu-vscode_v1.2.3_linux_arm64.vsix",
        "enbu-vscode_v1.2.3_windows_amd64.vsix",
        "enbu-vscode_v1.2.3_windows_arm64.vsix",
        "enbu-vscode_v1.2.3_linux_amd64.vsix.sigstore.json",
        "checksums.txt",
        "enbu_v1.2.3_linux_amd64.tar.gz.sbom.spdx.json",
        "enbu_v1.2.3_linux_amd64.tar.gz.sigstore.json",
    )

    assets = collect_assets(assets_dir, "v1.2.3")
    result = render_release_notes(
        "yashikota/enbu",
        "v1.2.3",
        assets,
        "## What's Changed\n\n* Add a feature\n",
    )

    assert result.splitlines() == [
        "## Downloads",
        "",
        "| OS | Arch | CLI | Desktop | VS Code |",
        "| --- | --- | --- | --- | --- |",
        "| macOS | arm64 | [`enbu_v1.2.3_darwin_arm64.tar.gz`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu_v1.2.3_darwin_arm64.tar.gz) | [`enbu-desktop_v1.2.3_darwin_arm64.dmg`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-desktop_v1.2.3_darwin_arm64.dmg) | [`enbu-vscode_v1.2.3_darwin_arm64.vsix`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-vscode_v1.2.3_darwin_arm64.vsix) |",
        "| Linux | x64 | [`enbu_v1.2.3_linux_amd64.tar.gz`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu_v1.2.3_linux_amd64.tar.gz) | [`enbu-desktop_v1.2.3_linux_amd64.tar.gz`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-desktop_v1.2.3_linux_amd64.tar.gz) | [`enbu-vscode_v1.2.3_linux_amd64.vsix`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-vscode_v1.2.3_linux_amd64.vsix) |",
        "| Linux | arm64 | [`enbu_v1.2.3_linux_arm64.tar.gz`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu_v1.2.3_linux_arm64.tar.gz) | [`enbu-desktop_v1.2.3_linux_arm64.tar.gz`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-desktop_v1.2.3_linux_arm64.tar.gz) | [`enbu-vscode_v1.2.3_linux_arm64.vsix`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-vscode_v1.2.3_linux_arm64.vsix) |",
        "| Windows | x64 | [`enbu_v1.2.3_windows_amd64.zip`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu_v1.2.3_windows_amd64.zip) | [`enbu-desktop_v1.2.3_windows_amd64.zip`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-desktop_v1.2.3_windows_amd64.zip) | [`enbu-vscode_v1.2.3_windows_amd64.vsix`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-vscode_v1.2.3_windows_amd64.vsix) |",
        "| Windows | arm64 | [`enbu_v1.2.3_windows_arm64.zip`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu_v1.2.3_windows_arm64.zip) | [`enbu-desktop_v1.2.3_windows_arm64.zip`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-desktop_v1.2.3_windows_arm64.zip) | [`enbu-vscode_v1.2.3_windows_arm64.vsix`](https://github.com/yashikota/enbu/releases/download/v1.2.3/enbu-vscode_v1.2.3_windows_arm64.vsix) |",
        "",
        "## What's Changed",
        "",
        "* Add a feature",
    ]


def test_renders_missing_asset_as_dash_and_unknown_labels_verbatim() -> None:
    result = render_release_notes(
        "owner/repo",
        "release/1",
        {
            "cli": {("freebsd", "riscv64"): "enbu_release-1_freebsd_riscv64.tar.gz"},
            "desktop": {("linux", "amd64"): "enbu desktop.zip"},
        },
    )

    assert "| Linux | x64 | — | [`enbu desktop.zip`]" in result
    assert "/enbu%20desktop.zip) | — |" in result
    assert "| freebsd | riscv64 | [`enbu_release-1_freebsd_riscv64.tar.gz`]" in result
    assert "/release%2F1/enbu%20desktop.zip" in result


def test_rejects_directory_without_matching_assets(tmp_path: Path) -> None:
    assets_dir = tmp_path / "release-assets"
    create_assets(
        assets_dir,
        "checksums.txt",
        "enbu_v0.9.0_linux_amd64.tar.gz",
        "enbu_1.0.0_linux_amd64.tar.gz",
    )

    with pytest.raises(ReleaseNotesError, match="no release assets"):
        collect_assets(assets_dir, "v1.0.0")


def test_rejects_duplicate_asset_for_platform(tmp_path: Path) -> None:
    assets_dir = tmp_path / "release-assets"
    create_assets(
        assets_dir,
        "enbu_v1.0.0_linux_amd64.tar.gz",
        "enbu_v1.0.0_linux_amd64.zip",
    )

    with pytest.raises(ReleaseNotesError, match="multiple CLI assets found"):
        collect_assets(assets_dir, "v1.0.0")


def test_main_uses_explicit_inputs_and_appends_generated_notes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assets_dir = tmp_path / "assets"
    create_assets(assets_dir, "enbu_v2.0.0_linux_amd64.tar.gz")
    generated_notes = tmp_path / "generated.md"
    generated_notes.write_text(
        "## Changes\n\nEverything is automated.\n", encoding="utf-8"
    )

    exit_code = main(
        [
            "--assets-dir",
            str(assets_dir),
            "--repository",
            "owner/repo",
            "--tag",
            "v2.0.0",
            "--generated-notes",
            str(generated_notes),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "| Linux | x64 |" in captured.out
    assert captured.out.endswith("## Changes\n\nEverything is automated.\n")


def test_main_reports_missing_generated_notes_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assets_dir = tmp_path / "assets"
    create_assets(assets_dir, "enbu_v2.0.0_linux_amd64.tar.gz")

    exit_code = main(
        [
            "--assets-dir",
            str(assets_dir),
            "--repository",
            "owner/repo",
            "--tag",
            "v2.0.0",
            "--generated-notes",
            str(tmp_path / "missing.md"),
        ]
    )

    assert exit_code == 1
    assert "No such file or directory" in capsys.readouterr().err

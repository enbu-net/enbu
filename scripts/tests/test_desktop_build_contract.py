import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]


def task_dry_run(task_name: str) -> str:
    result = subprocess.run(
        ["task", "--dry", task_name],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def test_gui_tasks_enable_webkit2gtk_41() -> None:
    assert "-tags webkit2_41" in task_dry_run("gui/build")
    assert "-tags webkit2_41" in task_dry_run("gui/run")


def test_release_builds_linux_targets_with_webkit2gtk_41() -> None:
    workflow = (REPOSITORY_ROOT / ".github/workflows/release.yaml").read_text()

    assert (
        "- os: ubuntu-24.04\n"
        "            platform: linux/amd64\n"
        "            suffix: linux_amd64"
    ) in workflow
    assert (
        "- os: ubuntu-24.04-arm\n"
        "            platform: linux/arm64\n"
        "            suffix: linux_arm64"
    ) in workflow

    install = "sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev"
    build = 'run: task gui/build PLATFORM="$PLATFORM" EXTRA_FLAGS="$EXTRA_FLAGS"'
    assert install in workflow
    assert build in workflow
    assert workflow.index(install) < workflow.index(build)

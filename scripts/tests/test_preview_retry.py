"""A retried Pages job must select its own artifact, with old artifacts retained."""

import re
from pathlib import Path


def test_pages_retry_selects_exactly_the_current_artifact():
    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/preview.yaml"
    ).read_text()

    def action_input(action, key):
        step = workflow.split(f"uses: {action}@", 1)[1].split("\n      - ", 1)[0]
        match = re.search(rf"^          {key}: (.+)$", step, re.MULTILINE)
        return match.group(1).strip("\"'") if match else "github-pages"

    upload = action_input("actions/upload-pages-artifact", "name")
    deploy = action_input("actions/deploy-pages", "artifact_name")

    def render(expression, attempt):
        rendered = expression.replace("${{ github.run_attempt }}", str(attempt))
        assert "${{" not in rendered, (
            f"unsupported artifact-name expression {expression}"
        )
        return rendered

    artifacts = []
    for attempt in (1, 2, 3):
        artifacts.append({"name": render(upload, attempt), "attempt": attempt})
        matches = [
            artifact
            for artifact in artifacts
            if artifact["name"] == render(deploy, attempt)
        ]
        assert matches == [artifacts[-1]], (
            f"retry {attempt} selected artifacts from another attempt"
        )

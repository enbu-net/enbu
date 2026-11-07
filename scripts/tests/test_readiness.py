"""Exercise actual Task readiness commands against an interrupted HTTP startup."""

import http.server
import shlex
import subprocess
import threading
from pathlib import Path

import pytest


def readiness_commands():
    taskfile = Path(__file__).resolve().parents[2] / "Taskfile.yaml"
    commands = []
    for line in taskfile.read_text().splitlines():
        command = line.strip().removeprefix("- ")
        if command.startswith("curl --fail --silent --show-error "):
            args = shlex.split(command)
            if args[-1].startswith("http://localhost:"):
                commands.append(args)
    return commands


@pytest.mark.parametrize("command", readiness_commands())
def test_readiness_recovers_from_connection_closed_before_response(command):
    attempts = [0]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            attempts[0] += 1
            if attempts[0] == 1:
                self.close_connection = True
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready")

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        args = command[:-1] + [f"http://127.0.0.1:{server.server_port}/"]
        # Keep this local fixture independent of inherited proxy settings.
        args[1:1] = ["--noproxy", "*"]
        control = [arg for arg in args if arg != "--retry-all-errors"]
        result = subprocess.run(control, capture_output=True, timeout=10)
        assert result.returncode != 0, "fixture did not reproduce interrupted startup"
        assert attempts[0] == 1
        attempts[0] = 0
        result = subprocess.run(args, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b"ready"
        assert attempts[0] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

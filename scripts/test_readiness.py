"""Readiness probes retry a reset connection while the local registry starts."""

import http.server
import shlex
import socket
import subprocess
import threading
from pathlib import Path

import pytest


@pytest.mark.parametrize("port", [5000, 5001, 5002])
def test_registry_readiness_recovers_after_reset(port):
    taskfile = Path(__file__).resolve().parents[1] / "Taskfile.yaml"
    command = next(
        line.strip().removeprefix("- ")
        for line in taskfile.read_text().splitlines()
        if "curl --fail" in line and f"http://localhost:{port}/v2/" in line
    )

    class Registry(http.server.BaseHTTPRequestHandler):
        attempts = 0

        def do_GET(self):
            type(self).attempts += 1
            if self.attempts == 1:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        args = shlex.split(command)
        args[-1] = f"http://127.0.0.1:{server.server_port}/v2/"
        try:
            result = subprocess.run(args, capture_output=True, timeout=10, check=False)
        finally:
            server.shutdown()
            thread.join(timeout=5)
    assert result.returncode == 0, result.stderr.decode()
    assert Registry.attempts == 2

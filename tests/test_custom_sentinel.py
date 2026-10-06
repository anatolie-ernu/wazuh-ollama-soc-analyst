import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "custom-sentinel"


def test_custom_integration_posts_json_to_local_api(tmp_path):
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["path"] = self.path
            received["key"] = self.headers.get("X-API-Key")
            received["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    alert = {"rule": {"id": "100001", "level": 7}, "data": {"srcip": "192.0.2.9"}}
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps(alert), encoding="utf-8")
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(alert_file), "test-secret", f"http://127.0.0.1:{server.server_port}/api/v1/alerts"],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert result.returncode == 0, result.stderr
    assert received == {"path": "/api/v1/alerts", "key": "test-secret", "body": alert}


def test_custom_integration_rejects_plain_http_to_remote_host(tmp_path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text('{"rule":{"id":"1"}}', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(alert_file), "secret", "http://192.0.2.10/api/v1/alerts"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2

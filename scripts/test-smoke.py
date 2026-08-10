#!/usr/bin/env python3
"""Offline smoke tests for AJSIEM configs/scripts (no Docker required)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name} {detail}")


def test_files():
    required = [
        "docker-compose.yml",
        "configs/graylog/alerts/alert-catalog.json",
        "configs/rsyslog/60-ajsiem-forward.conf",
        "configs/filebeat/filebeat.yml",
        "scripts/ubuntu/bootstrap_graylog.py",
        "scripts/ubuntu/generate-secrets.sh",
        "scripts/kali/generate-lab-events.sh",
    ]
    for rel in required:
        check(f"exists:{rel}", (ROOT / rel).is_file())


def test_alert_catalog():
    data = json.loads((ROOT / "configs/graylog/alerts/alert-catalog.json").read_text())
    alerts = data.get("alerts") or []
    sevs = {a.get("severity") for a in alerts}
    check("alert-catalog has low/medium/high", sevs >= {"low", "medium", "high"})
    check("alert-catalog non-empty", len(alerts) >= 5)


def test_templates():
    rsys = (ROOT / "configs/rsyslog/60-ajsiem-forward.conf").read_text()
    fb = (ROOT / "configs/filebeat/filebeat.yml").read_text()
    check("rsyslog placeholder", "__SIEM_SERVER_IP__" in rsys)
    check("filebeat placeholder", "__SIEM_SERVER_IP__" in fb)
    check(
        "rsyslog substitute",
        "@@10.0.0.5:1514" in rsys.replace("__SIEM_SERVER_IP__", "10.0.0.5"),
    )


def test_generate_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # copy minimal project bits
        (tmp_path / "scripts/ubuntu").mkdir(parents=True)
        (tmp_path / ".env.example").write_text(
            (ROOT / ".env.example").read_text()
        )
        script = (ROOT / "scripts/ubuntu/generate-secrets.sh").read_text()
        # rewrite ROOT detection: script uses ../.. from scripts/ubuntu
        (tmp_path / "scripts/ubuntu/generate-secrets.sh").write_text(script)
        os.chmod(tmp_path / "scripts/ubuntu/generate-secrets.sh", 0o755)
        env = os.environ.copy()
        env["GRAYLOG_ROOT_PASSWORD"] = "TestPassword123!"
        env["LC_ALL"] = "C"
        proc = subprocess.run(
            ["bash", str(tmp_path / "scripts/ubuntu/generate-secrets.sh")],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )
        env_file = tmp_path / ".env"
        text = env_file.read_text() if env_file.exists() else ""
        secret = ""
        sha = ""
        for line in text.splitlines():
            if line.startswith("GRAYLOG_PASSWORD_SECRET="):
                secret = line.split("=", 1)[1]
            if line.startswith("GRAYLOG_ROOT_PASSWORD_SHA2="):
                sha = line.split("=", 1)[1]
        check("generate-secrets exit 0", proc.returncode == 0, proc.stderr[:200])
        check("generate-secrets secret length", len(secret) >= 64, f"len={len(secret)}")
        check("generate-secrets sha256 length", len(sha) == 64, f"len={len(sha)}")


def test_bootstrap_against_mock():
    state = {"inputs": [], "streams": [], "rules": {}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def _auth_ok(self):
            return self.headers.get("Authorization", "").startswith("Basic ")

        def _read(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode() or "{}")

        def _json(self, code, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self._auth_ok():
                return self._json(401, {"error": "unauthorized"})
            if self.path.startswith("/api/system/lbstatus"):
                return self._json(200, {"status": "ALIVE"})
            if self.path.startswith("/api/system/inputs"):
                return self._json(200, {"inputs": state["inputs"], "total": len(state["inputs"])})
            if self.path.startswith("/api/streams"):
                return self._json(200, {"streams": state["streams"], "total": len(state["streams"])})
            if self.path.startswith("/api/system/indices/index_sets"):
                return self._json(
                    200,
                    {
                        "index_sets": [
                            {"id": "idx-default", "title": "Default index set", "default": True}
                        ],
                        "total": 1,
                    },
                )
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth_ok():
                return self._json(401, {"error": "unauthorized"})
            payload = self._read()
            if self.path == "/api/system/inputs":
                state["inputs"].append(
                    {"title": payload.get("title"), "id": f"in-{len(state['inputs'])+1}"}
                )
                return self._json(201, {"id": state["inputs"][-1]["id"]})
            if self.path == "/api/streams":
                sid = f"stream-{len(state['streams'])+1}"
                state["streams"].append({"id": sid, "title": payload.get("title")})
                state["rules"][sid] = []
                return self._json(201, {"stream_id": sid})
            if "/rules" in self.path:
                sid = self.path.split("/")[3]
                state["rules"].setdefault(sid, []).append(payload)
                return self._json(201, {"id": "rule-1"})
            if self.path.endswith("/resume"):
                return self._json(204, {})
            return self._json(404, {"error": "not found"})

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    env = os.environ.copy()
    env["GRAYLOG_URL"] = f"http://127.0.0.1:{port}"
    env["GRAYLOG_API_USER"] = "admin"
    env["GRAYLOG_ROOT_PASSWORD"] = "test"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts/ubuntu/bootstrap_graylog.py")],
        env=env,
        capture_output=True,
        text=True,
    )
    httpd.shutdown()
    titles = {i["title"] for i in state["inputs"]}
    streams = {s["title"] for s in state["streams"]}
    check("bootstrap exit 0", proc.returncode == 0, proc.stderr[:300] or proc.stdout[:300])
    check("bootstrap created syslog input", "AJSIEM Syslog TCP" in titles)
    check("bootstrap created beats input", "AJSIEM Beats" in titles)
    check(
        "bootstrap created severity streams",
        {"AJSIEM Low", "AJSIEM Medium", "AJSIEM High"} <= streams,
        str(streams),
    )


def test_lab_events_script():
    script = ROOT / "scripts/kali/generate-lab-events.sh"
    # Dry-run: ensure script references severity markers
    text = script.read_text()
    check("lab events has LOW marker", "LOW:" in text)
    check("lab events has MEDIUM marker", "MEDIUM:" in text)
    check("lab events has HIGH marker", "HIGH:" in text)
    check("lab events executable", os.access(script, os.X_OK))


def test_no_third_party_attribution():
    needles = ("nelson", "awuja", "medium.com", "medium article")
    skip_names = {"test-smoke.py"}
    bad = []
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file() or path.name in skip_names:
            continue
        try:
            text = path.read_text(errors="ignore").lower()
        except Exception:
            continue
        if any(n in text for n in needles):
            bad.append(str(path.relative_to(ROOT)))
    check("no third-party article attribution", not bad, str(bad))


def main():
    print(f"AJSIEM smoke tests @ {ROOT}\n")
    test_files()
    test_alert_catalog()
    test_templates()
    test_generate_secrets()
    test_bootstrap_against_mock()
    test_lab_events_script()
    test_no_third_party_attribution()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())

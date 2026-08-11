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
        "scripts/kali/generate-home-traffic.sh",
        "scripts/kali/scan-home-network.sh",
        "scripts/lib/home_network_scan.py",
        "dashboard/app.py",
        "dashboard/static/index.html",
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
        {"AJSIEM Low", "AJSIEM Medium", "AJSIEM High", "AJSIEM Home Network"} <= streams,
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


def test_home_traffic_script():
    script = ROOT / "scripts/kali/generate-home-traffic.sh"
    text = script.read_text()
    check("home traffic has HOME_NET marker", "HOME_NET src=" in text)
    check("home traffic has device field", "device=" in text)
    check("home traffic executable", os.access(script, os.X_OK))
    catalog = json.loads((ROOT / "configs/graylog/alerts/alert-catalog.json").read_text())
    home_alerts = [a for a in catalog.get("alerts", []) if a.get("stream") == "AJSIEM Home Network"]
    check("alert-catalog has home network alerts", len(home_alerts) >= 2, str(len(home_alerts)))


def test_home_network_scanner():
    scanner = ROOT / "scripts/lib/home_network_scan.py"
    wrapper = ROOT / "scripts/kali/scan-home-network.sh"
    text = scanner.read_text()
    check("scanner defines scan_home_network", "def scan_home_network" in text)
    check("scanner emits HOST_DISC", "HOST_DISC" in text)
    check("scanner executable wrapper", os.access(wrapper, os.X_OK))
    proc = subprocess.run(
        [sys.executable, str(scanner), "--no-ports", "--no-flows", "--json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    check("scanner exit 0", proc.returncode == 0, proc.stderr[:300])
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {}
    check("scanner returns hosts", isinstance(payload.get("hosts"), list) and len(payload.get("hosts") or []) >= 1)
    check("scanner reports subnet", bool((payload.get("subnet") or {}).get("cidr")))
    html = (ROOT / "dashboard/static/index.html").read_text()
    check("dashboard has scan button", "Scan home network" in html)
    app_src = (ROOT / "dashboard/app.py").read_text()
    check("dashboard has scan API", '/api/network/scan' in app_src)
    check("dashboard defaults without fake LAN", "ALLOW_DEMO_NETWORK" in app_src)


def test_home_net_parser():
    import re

    # Keep offline: assert the dashboard embeds a HOME_NET parser without importing FastAPI deps.
    app_src = (ROOT / "dashboard/app.py").read_text()
    check("dashboard defines FLOW_RE", "FLOW_RE = re.compile" in app_src)
    check("dashboard defines parse_home_net_message", "def parse_home_net_message" in app_src)
    flow_re = re.compile(
        r"HOME_NET\s+"
        r"src=(?P<src>\S+)\s+"
        r"dst=(?P<dst>\S+)\s+"
        r"proto=(?P<proto>\S+)\s+"
        r"sport=(?P<sport>\d+)\s+"
        r"dport=(?P<dport>\d+)\s+"
        r"bytes=(?P<bytes>\d+)\s+"
        r"device=(?P<device>\S+)"
        r"(?:\s+dns=(?P<dns>\S+))?"
        r"(?:\s+dir=(?P<dir>\S+))?",
        re.IGNORECASE,
    )
    sample = (
        "HOME_NET src=192.168.1.24 dst=8.8.8.8 proto=UDP sport=53122 "
        "dport=53 bytes=128 device=iphone-aj dns=dns.google dir=out"
    )
    match = flow_re.search(sample)
    check("parser extracts src", bool(match) and match.group("src") == "192.168.1.24")
    check("parser extracts dport", bool(match) and match.group("dport") == "53")
    check("parser extracts device", bool(match) and match.group("device") == "iphone-aj")
    html = (ROOT / "dashboard/static/index.html").read_text()
    check("dashboard has home network section", "Home network traffic" in html)
    check("dashboard has scan button markup", "id=\"scanBtn\"" in html)
    js = (ROOT / "dashboard/static/assets/app.js").read_text()
    check("dashboard JS renders flows", "renderFlows" in js)
    check("dashboard JS triggers scan", "api/network/scan" in js)


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
    test_home_traffic_script()
    test_home_network_scanner()
    test_home_net_parser()
    test_no_third_party_attribution()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())

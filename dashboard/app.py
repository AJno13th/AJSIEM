"""AJSIEM live dashboard API — Graylog-backed with demo fallback."""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
load_dotenv(REPO / ".env")

GRAYLOG_URL = os.getenv("GRAYLOG_URL", os.getenv("GRAYLOG_HTTP_EXTERNAL_URI", "http://127.0.0.1:9000")).rstrip("/")
GRAYLOG_USER = os.getenv("GRAYLOG_API_USER", "admin")
GRAYLOG_PASS = os.getenv("GRAYLOG_ROOT_PASSWORD", "admin")
FORCE_DEMO = os.getenv("AJSIEM_DEMO", "auto")  # auto | always | never
POLL_SECONDS = float(os.getenv("AJSIEM_POLL_SECONDS", "2.5"))

STATIC = ROOT / "static"

app = FastAPI(title="AJSIEM Dashboard", version="1.0.0")
app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

# In-memory ring buffers for the live UI
_events: deque[dict[str, Any]] = deque(maxlen=200)
_throughput: deque[dict[str, Any]] = deque(maxlen=60)
_state = {
    "mode": "demo",
    "graylog_ok": False,
    "started_at": time.time(),
    "counts": {"low": 0, "medium": 0, "high": 0, "total": 0},
    "inputs": [
        {"name": "Syslog TCP", "port": 1514, "status": "unknown"},
        {"name": "GELF UDP", "port": 12201, "status": "unknown"},
        {"name": "Beats", "port": 5044, "status": "unknown"},
    ],
    "streams": [
        {"name": "AJSIEM Low", "severity": "low", "matches": 0},
        {"name": "AJSIEM Medium", "severity": "medium", "matches": 0},
        {"name": "AJSIEM High", "severity": "high", "matches": 0},
    ],
}

DEMO_TEMPLATES = [
    ("low", "sshd", "Accepted publickey for kali from 192.168.1.{ip} port {port} ssh2"),
    ("low", "sudo", "kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update"),
    ("low", "ajsiem", "LOW: routine package metadata refresh"),
    ("medium", "sshd", "Failed password for invalid user admin from 203.0.113.{ip} port 22 ssh2"),
    ("medium", "useradd", "new user: name=labattacker, UID=1005, GID=1005"),
    ("medium", "ajsiem", "MEDIUM: repeated authentication failures observed"),
    ("high", "sshd", "Accepted password for root from 198.51.100.{ip} port 22 ssh2"),
    ("high", "kernel", "possible SYN flood on eth0"),
    ("high", "nmap", "Nmap scan report for 192.168.1.0/24 — host discovery + port scan"),
    ("high", "sudo", "kali : 3 incorrect password attempts ; USER=root ; COMMAND=/bin/bash"),
    ("high", "ajsiem", "HIGH: root login + scan activity + privilege escalation attempts"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _push_event(severity: str, source: str, message: str, origin: str = "demo"):
    event = {
        "id": f"{int(time.time() * 1000)}-{random.randint(100, 999)}",
        "ts": _now_iso(),
        "severity": severity,
        "source": source,
        "message": message,
        "origin": origin,
    }
    _events.appendleft(event)
    _state["counts"][severity] = _state["counts"].get(severity, 0) + 1
    _state["counts"]["total"] += 1
    for stream in _state["streams"]:
        if stream["severity"] == severity:
            stream["matches"] += 1
    return event


def _tick_throughput(n: int):
    _throughput.append({"t": int(time.time()), "n": n})


async def graylog_reachable() -> bool:
    if FORCE_DEMO == "always":
        return False
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            res = await client.get(
                f"{GRAYLOG_URL}/api/system/lbstatus",
                auth=(GRAYLOG_USER, GRAYLOG_PASS),
                headers={"X-Requested-By": "ajsiem-dashboard", "Accept": "application/json"},
            )
            return res.status_code < 500
    except Exception:
        return False


async def pull_graylog_snapshot() -> list[dict[str, Any]]:
    """Fetch recent messages from Graylog absolute search."""
    new_events: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            headers = {
                "X-Requested-By": "ajsiem-dashboard",
                "Accept": "application/json",
            }
            auth = (GRAYLOG_USER, GRAYLOG_PASS)

            # Inputs
            try:
                inputs = (await client.get(f"{GRAYLOG_URL}/api/system/inputs", auth=auth, headers=headers)).json()
                mapped = []
                for item in inputs.get("inputs", []):
                    conf = item.get("attributes", {}).get("configuration") or item.get("configuration") or {}
                    mapped.append(
                        {
                            "name": item.get("title") or item.get("name") or "input",
                            "port": conf.get("port"),
                            "status": "up" if item.get("created_at") else "unknown",
                        }
                    )
                if mapped:
                    _state["inputs"] = mapped
            except Exception:
                pass

            # Recent messages
            query = {
                "query": "*",
                "timerange": {"type": "relative", "range": 300},
                "limit": 25,
                "sort": "timestamp:desc",
            }
            res = await client.post(
                f"{GRAYLOG_URL}/api/views/search/messages",
                auth=auth,
                headers={**headers, "Content-Type": "application/json"},
                json=query,
            )
            # Fallback older messages API
            if res.status_code >= 400:
                res = await client.get(
                    f"{GRAYLOG_URL}/api/search/universal/relative",
                    auth=auth,
                    headers=headers,
                    params={"query": "*", "range": 300, "limit": 25, "sort": "timestamp:desc"},
                )
            payload = res.json() if res.status_code < 400 else {}
            messages = payload.get("messages") or payload.get("data") or []
            for row in messages:
                msg = row.get("message") if isinstance(row, dict) else None
                if not isinstance(msg, dict):
                    msg = row if isinstance(row, dict) else {}
                text = str(msg.get("message") or msg.get("full_message") or "")
                severity = classify_severity(text)
                source = str(msg.get("source") or msg.get("facility") or "graylog")
                new_events.append(
                    {
                        "id": str(msg.get("_id") or msg.get("gl2_message_id") or random.randint(1, 1_000_000)),
                        "ts": str(msg.get("timestamp") or _now_iso()),
                        "severity": severity,
                        "source": source,
                        "message": text[:280],
                        "origin": "graylog",
                    }
                )
    except Exception:
        return []
    return new_events


def classify_severity(text: str) -> str:
    lower = text.lower()
    if any(k in lower for k in ("high:", "root from", "syn flood", "nmap", "incorrect password attempts")):
        return "high"
    if any(k in lower for k in ("medium:", "failed password", "invalid user", "new user:")):
        return "medium"
    return "low"


def demo_burst() -> list[dict[str, Any]]:
    produced = []
    # Weighted toward low, occasional high
    rolls = random.choices(["low", "medium", "high"], weights=[0.55, 0.3, 0.15], k=random.randint(1, 3))
    for sev in rolls:
        options = [t for t in DEMO_TEMPLATES if t[0] == sev]
        severity, source, template = random.choice(options)
        message = template.format(ip=random.randint(1, 254), port=random.randint(1024, 65535))
        produced.append(_push_event(severity, source, message, origin="demo"))
    _state["inputs"] = [
        {"name": "Syslog TCP", "port": 1514, "status": "up"},
        {"name": "GELF UDP", "port": 12201, "status": "up"},
        {"name": "Beats", "port": 5044, "status": "idle"},
    ]
    return produced


def snapshot() -> dict[str, Any]:
    return {
        "mode": _state["mode"],
        "graylog_ok": _state["graylog_ok"],
        "graylog_url": GRAYLOG_URL,
        "server_time": _now_iso(),
        "uptime_s": int(time.time() - _state["started_at"]),
        "counts": dict(_state["counts"]),
        "inputs": list(_state["inputs"]),
        "streams": list(_state["streams"]),
        "throughput": list(_throughput),
        "events": list(_events)[:80],
    }


@app.on_event("startup")
async def startup():
    # Seed demo so the UI is never empty on first paint
    for _ in range(8):
        demo_burst()
    _tick_throughput(len(_events))
    asyncio.create_task(live_loop())


async def live_loop():
    while True:
        try:
            reachable = await graylog_reachable()
            _state["graylog_ok"] = reachable
            if reachable and FORCE_DEMO != "always":
                _state["mode"] = "live"
                fresh = await pull_graylog_snapshot()
                seen = {e["id"] for e in _events}
                added = 0
                for event in reversed(fresh):
                    if event["id"] in seen:
                        continue
                    _events.appendleft(event)
                    sev = event["severity"]
                    _state["counts"][sev] = _state["counts"].get(sev, 0) + 1
                    _state["counts"]["total"] += 1
                    for stream in _state["streams"]:
                        if stream["severity"] == sev:
                            stream["matches"] += 1
                    added += 1
                _tick_throughput(added if added else random.randint(0, 2))
            else:
                _state["mode"] = "demo"
                produced = demo_burst()
                _tick_throughput(len(produced))
        except Exception:
            _state["mode"] = "demo"
            produced = demo_burst()
            _tick_throughput(len(produced))
        await asyncio.sleep(POLL_SECONDS)


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
async def health():
    return {"status": "ok", "mode": _state["mode"], "graylog_ok": _state["graylog_ok"]}


@app.get("/api/snapshot")
async def api_snapshot():
    return snapshot()


@app.get("/api/stream")
async def api_stream():
    async def gen():
        last = None
        while True:
            payload = snapshot()
            encoded = json.dumps(payload)
            if encoded != last:
                yield f"data: {encoded}\n\n"
                last = encoded
            else:
                yield ": keepalive\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.getenv("DASHBOARD_HOST", "0.0.0.0"),
        port=int(os.getenv("DASHBOARD_PORT", "8088")),
        reload=False,
    )

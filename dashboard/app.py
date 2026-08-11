"""AJSIEM live dashboard API — Graylog-backed with demo fallback."""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
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

app = FastAPI(title="AJSIEM Dashboard", version="1.1.0")
app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

# In-memory ring buffers for the live UI
_events: deque[dict[str, Any]] = deque(maxlen=200)
_flows: deque[dict[str, Any]] = deque(maxlen=120)
_throughput: deque[dict[str, Any]] = deque(maxlen=60)
_state = {
    "mode": "demo",
    "graylog_ok": False,
    "started_at": time.time(),
    "counts": {"low": 0, "medium": 0, "high": 0, "total": 0},
    "network": {
        "bytes_in": 0,
        "bytes_out": 0,
        "active_devices": 0,
        "flows_seen": 0,
        "protocols": {"TCP": 0, "UDP": 0, "DNS": 0, "Other": 0},
        "top_talkers": [],
        "devices": {},
    },
    "inputs": [
        {"name": "Syslog TCP", "port": 1514, "status": "unknown"},
        {"name": "GELF UDP", "port": 12201, "status": "unknown"},
        {"name": "Beats", "port": 5044, "status": "unknown"},
    ],
    "streams": [
        {"name": "AJSIEM Low", "severity": "low", "matches": 0},
        {"name": "AJSIEM Medium", "severity": "medium", "matches": 0},
        {"name": "AJSIEM High", "severity": "high", "matches": 0},
        {"name": "AJSIEM Home Network", "severity": "network", "matches": 0},
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

# Synthetic home LAN inventory for demo / offline visibility
HOME_DEVICES = [
    {"ip": "192.168.1.10", "name": "router-gateway", "role": "gateway"},
    {"ip": "192.168.1.20", "name": "laptop-aj", "role": "workstation"},
    {"ip": "192.168.1.24", "name": "iphone-aj", "role": "phone"},
    {"ip": "192.168.1.36", "name": "smart-tv", "role": "media"},
    {"ip": "192.168.1.42", "name": "nas-home", "role": "storage"},
    {"ip": "192.168.1.55", "name": "iot-cam-porch", "role": "iot"},
    {"ip": "192.168.1.66", "name": "kali-lab", "role": "lab"},
    {"ip": "192.168.1.80", "name": "tablet-kids", "role": "tablet"},
]

HOME_DESTS = [
    {"ip": "8.8.8.8", "port": 53, "proto": "UDP", "dns": "dns.google", "kind": "dns"},
    {"ip": "1.1.1.1", "port": 53, "proto": "UDP", "dns": "one.one.one.one", "kind": "dns"},
    {"ip": "142.250.190.14", "port": 443, "proto": "TCP", "dns": "www.google.com", "kind": "web"},
    {"ip": "151.101.1.140", "port": 443, "proto": "TCP", "dns": "www.reddit.com", "kind": "web"},
    {"ip": "13.107.42.14", "port": 443, "proto": "TCP", "dns": "www.microsoft.com", "kind": "update"},
    {"ip": "52.94.236.248", "port": 443, "proto": "TCP", "dns": "aws.amazon.com", "kind": "cloud"},
    {"ip": "104.16.132.229", "port": 443, "proto": "TCP", "dns": "cdn.cloudflare.net", "kind": "cdn"},
    {"ip": "23.246.0.1", "port": 443, "proto": "TCP", "dns": "netflix.com", "kind": "stream"},
    {"ip": "192.168.1.42", "port": 445, "proto": "TCP", "dns": "nas-home.lan", "kind": "lan"},
    {"ip": "192.168.1.10", "port": 53, "proto": "UDP", "dns": "router.lan", "kind": "dns"},
]

FLOW_RE = re.compile(
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


def _device_name(ip: str) -> str:
    for d in HOME_DEVICES:
        if d["ip"] == ip:
            return d["name"]
    return _state["network"]["devices"].get(ip, {}).get("name") or ip


def _proto_bucket(proto: str, dport: int) -> str:
    p = (proto or "").upper()
    if dport in (53, 853) or p == "DNS":
        return "DNS"
    if p in ("TCP", "UDP"):
        return p
    return "Other"


def _recompute_talkers():
    devices = _state["network"]["devices"]
    ranked = sorted(devices.values(), key=lambda d: d.get("bytes", 0), reverse=True)
    _state["network"]["top_talkers"] = [
        {
            "ip": d["ip"],
            "name": d["name"],
            "bytes": d["bytes"],
            "flows": d["flows"],
            "role": d.get("role", "host"),
        }
        for d in ranked[:6]
    ]
    _state["network"]["active_devices"] = len(devices)


def _push_flow(
    *,
    src: str,
    dst: str,
    proto: str,
    sport: int,
    dport: int,
    nbytes: int,
    device: str,
    dns: str = "",
    direction: str = "out",
    origin: str = "demo",
    severity: str = "low",
):
    flow = {
        "id": f"flow-{int(time.time() * 1000)}-{random.randint(100, 999)}",
        "ts": _now_iso(),
        "src": src,
        "dst": dst,
        "proto": proto.upper(),
        "sport": int(sport),
        "dport": int(dport),
        "bytes": int(nbytes),
        "device": device,
        "dns": dns,
        "direction": direction if direction in ("in", "out", "lan") else "out",
        "origin": origin,
        "severity": severity,
    }
    _flows.appendleft(flow)

    net = _state["network"]
    net["flows_seen"] += 1
    if flow["direction"] == "in":
        net["bytes_in"] += flow["bytes"]
    else:
        net["bytes_out"] += flow["bytes"]

    bucket = _proto_bucket(flow["proto"], flow["dport"])
    net["protocols"][bucket] = net["protocols"].get(bucket, 0) + 1

    ip = src if src.startswith("192.168.") else dst if dst.startswith("192.168.") else src
    devices = net["devices"]
    if ip not in devices:
        role = next((d["role"] for d in HOME_DEVICES if d["ip"] == ip), "host")
        devices[ip] = {"ip": ip, "name": device or _device_name(ip), "bytes": 0, "flows": 0, "role": role}
    devices[ip]["bytes"] += flow["bytes"]
    devices[ip]["flows"] += 1
    devices[ip]["name"] = device or devices[ip]["name"]
    _recompute_talkers()

    for stream in _state["streams"]:
        if stream["severity"] == "network":
            stream["matches"] += 1

    # Also surface notable network activity in the event feed
    if severity in ("medium", "high") or flow["dport"] in (22, 23, 445, 3389) or "scan" in (dns or "").lower():
        msg = (
            f"HOME_NET src={src} dst={dst} proto={flow['proto']} "
            f"sport={flow['sport']} dport={flow['dport']} bytes={flow['bytes']} "
            f"device={device}" + (f" dns={dns}" if dns else "")
        )
        _push_event(severity, "homenet", msg, origin=origin)
    return flow


def parse_home_net_message(text: str) -> dict[str, Any] | None:
    match = FLOW_RE.search(text or "")
    if not match:
        return None
    g = match.groupdict()
    return {
        "src": g["src"],
        "dst": g["dst"],
        "proto": g["proto"],
        "sport": int(g["sport"]),
        "dport": int(g["dport"]),
        "bytes": int(g["bytes"]),
        "device": g["device"],
        "dns": g.get("dns") or "",
        "direction": (g.get("dir") or "out").lower(),
    }


def classify_flow_severity(flow: dict[str, Any]) -> str:
    dport = int(flow.get("dport") or 0)
    dns = (flow.get("dns") or "").lower()
    dst = flow.get("dst") or ""
    if dport in (22, 23, 3389) and not dst.startswith("192.168."):
        return "high"
    if "scan" in dns or dport in (445, 139):
        return "medium"
    if int(flow.get("bytes") or 0) > 5_000_000:
        return "medium"
    return "low"


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


async def pull_graylog_snapshot() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch recent messages from Graylog absolute search."""
    new_events: list[dict[str, Any]] = []
    new_flows: list[dict[str, Any]] = []
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
                "limit": 40,
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
                    params={"query": "*", "range": 300, "limit": 40, "sort": "timestamp:desc"},
                )
            payload = res.json() if res.status_code < 400 else {}
            messages = payload.get("messages") or payload.get("data") or []
            for row in messages:
                msg = row.get("message") if isinstance(row, dict) else None
                if not isinstance(msg, dict):
                    msg = row if isinstance(row, dict) else {}
                text = str(msg.get("message") or msg.get("full_message") or "")
                parsed = parse_home_net_message(text)
                if parsed:
                    sev = classify_flow_severity(parsed)
                    new_flows.append(
                        {
                            **parsed,
                            "id": str(msg.get("_id") or msg.get("gl2_message_id") or random.randint(1, 1_000_000)),
                            "ts": str(msg.get("timestamp") or _now_iso()),
                            "origin": "graylog",
                            "severity": sev,
                        }
                    )
                    continue
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
        return [], []
    return new_events, new_flows


def classify_severity(text: str) -> str:
    lower = text.lower()
    if "home_net" in lower:
        parsed = parse_home_net_message(text)
        if parsed:
            return classify_flow_severity(parsed)
    if any(k in lower for k in ("high:", "root from", "syn flood", "nmap", "incorrect password attempts")):
        return "high"
    if any(k in lower for k in ("medium:", "failed password", "invalid user", "new user:")):
        return "medium"
    return "low"


def demo_network_burst() -> list[dict[str, Any]]:
    produced = []
    for _ in range(random.randint(2, 5)):
        device = random.choice(HOME_DEVICES)
        if device["role"] == "gateway":
            continue
        dest = random.choice(HOME_DESTS)
        # Bias IoT / media toward streaming & DNS
        if device["role"] == "iot":
            dest = random.choice([d for d in HOME_DESTS if d["kind"] in ("dns", "cloud", "cdn")])
        elif device["role"] == "media":
            dest = random.choice([d for d in HOME_DESTS if d["kind"] in ("stream", "dns", "cdn")])
        direction = "lan" if dest["ip"].startswith("192.168.") else "out"
        nbytes = {
            "dns": random.randint(64, 512),
            "web": random.randint(2_000, 80_000),
            "update": random.randint(50_000, 400_000),
            "cloud": random.randint(5_000, 120_000),
            "cdn": random.randint(20_000, 500_000),
            "stream": random.randint(200_000, 2_500_000),
            "lan": random.randint(8_000, 900_000),
        }.get(dest["kind"], random.randint(500, 20_000))
        # Occasional suspicious outbound
        if device["role"] == "lab" and random.random() < 0.18:
            dest = {"ip": "198.51.100.66", "port": 22, "proto": "TCP", "dns": "scan-target.lab", "kind": "scan"}
            nbytes = random.randint(120, 900)
            direction = "out"
        flow = {
            "src": device["ip"],
            "dst": dest["ip"],
            "proto": dest["proto"],
            "sport": random.randint(1024, 65535),
            "dport": dest["port"],
            "bytes": nbytes,
            "device": device["name"],
            "dns": dest.get("dns", ""),
            "direction": direction,
        }
        sev = classify_flow_severity(flow)
        produced.append(_push_flow(**flow, origin="demo", severity=sev))
    return produced


def demo_burst() -> list[dict[str, Any]]:
    produced = []
    # Weighted toward low, occasional high
    rolls = random.choices(["low", "medium", "high"], weights=[0.55, 0.3, 0.15], k=random.randint(1, 3))
    for sev in rolls:
        options = [t for t in DEMO_TEMPLATES if t[0] == sev]
        severity, source, template = random.choice(options)
        message = template.format(ip=random.randint(1, 254), port=random.randint(1024, 65535))
        produced.append(_push_event(severity, source, message, origin="demo"))
    produced.extend(demo_network_burst())
    _state["inputs"] = [
        {"name": "Syslog TCP", "port": 1514, "status": "up"},
        {"name": "GELF UDP", "port": 12201, "status": "up"},
        {"name": "Beats", "port": 5044, "status": "idle"},
        {"name": "Home net flows", "port": 1514, "status": "up"},
    ]
    return produced


def snapshot() -> dict[str, Any]:
    net = _state["network"]
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
        "network": {
            "bytes_in": net["bytes_in"],
            "bytes_out": net["bytes_out"],
            "active_devices": net["active_devices"],
            "flows_seen": net["flows_seen"],
            "protocols": dict(net["protocols"]),
            "top_talkers": list(net["top_talkers"]),
            "flows": list(_flows)[:40],
        },
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
                fresh_events, fresh_flows = await pull_graylog_snapshot()
                seen = {e["id"] for e in _events}
                seen_flows = {f["id"] for f in _flows}
                added = 0
                for event in reversed(fresh_events):
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
                for flow in reversed(fresh_flows):
                    if flow["id"] in seen_flows:
                        continue
                    _push_flow(
                        src=flow["src"],
                        dst=flow["dst"],
                        proto=flow["proto"],
                        sport=flow["sport"],
                        dport=flow["dport"],
                        nbytes=flow["bytes"],
                        device=flow["device"],
                        dns=flow.get("dns", ""),
                        direction=flow.get("direction", "out"),
                        origin="graylog",
                        severity=flow.get("severity", "low"),
                    )
                    added += 1
                # Keep home-net panel alive if Graylog has auth logs but no HOME_NET yet
                if not fresh_flows and random.random() < 0.35:
                    demo_network_burst()
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

"""AJSIEM live dashboard API — Graylog-backed with real home-LAN scanning."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from home_network_scan import scan_home_network  # noqa: E402

load_dotenv(REPO / ".env")

GRAYLOG_URL = os.getenv("GRAYLOG_URL", os.getenv("GRAYLOG_HTTP_EXTERNAL_URI", "http://127.0.0.1:9000")).rstrip("/")
GRAYLOG_USER = os.getenv("GRAYLOG_API_USER", "admin")
GRAYLOG_PASS = os.getenv("GRAYLOG_ROOT_PASSWORD", "admin")
POLL_SECONDS = float(os.getenv("AJSIEM_POLL_SECONDS", "2.5"))
SCAN_CIDR = os.getenv("AJSIEM_SCAN_CIDR") or None

STATIC = ROOT / "static"

app = FastAPI(title="AJSIEM Dashboard", version="1.2.0")
app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

# In-memory ring buffers for the live UI
_events: deque[dict[str, Any]] = deque(maxlen=200)
_flows: deque[dict[str, Any]] = deque(maxlen=120)
_throughput: deque[dict[str, Any]] = deque(maxlen=60)
_scan_lock = asyncio.Lock()
_state = {
    "mode": "waiting",
    "graylog_ok": False,
    "started_at": time.time(),
    "counts": {"low": 0, "medium": 0, "high": 0, "total": 0},
    "network": {
        "source": "none",  # none | scan | graylog
        "scan_status": "idle",  # idle | running | error
        "scan_error": "",
        "last_scan": None,
        "subnet": "",
        "methods": [],
        "bytes_in": 0,
        "bytes_out": 0,
        "active_devices": 0,
        "flows_seen": 0,
        "protocols": {"TCP": 0, "UDP": 0, "DNS": 0, "Other": 0},
        "top_talkers": [],
        "devices": {},
        "hosts": [],
    },
    "inputs": [
        {"name": "Syslog TCP", "port": 1514, "status": "unknown"},
        {"name": "GELF UDP", "port": 12201, "status": "unknown"},
        {"name": "Beats", "port": 5044, "status": "unknown"},
        {"name": "Home LAN scan", "port": None, "status": "idle"},
    ],
    "streams": [
        {"name": "AJSIEM Low", "severity": "low", "matches": 0},
        {"name": "AJSIEM Medium", "severity": "medium", "matches": 0},
        {"name": "AJSIEM High", "severity": "high", "matches": 0},
        {"name": "AJSIEM Home Network", "severity": "network", "matches": 0},
    ],
}

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

HOST_RE = re.compile(
    r"HOST_DISC\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"mac=(?P<mac>\S+)\s+"
    r"name=(?P<name>\S+)\s+"
    r"role=(?P<role>\S+)\s+"
    r"ports=(?P<ports>\S+)"
    r"(?:\s+source=(?P<source>\S+))?",
    re.IGNORECASE,
)

PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class ScanRequest(BaseModel):
    cidr: str | None = None
    with_ports: bool = True
    with_flows: bool = True


class IngestPayload(BaseModel):
    ok: bool = True
    scanned_at: str | None = None
    duration_s: float | None = None
    subnet: dict[str, Any] = Field(default_factory=dict)
    gateway_guess: str | None = None
    methods: list[str] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    flows: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS) and not addr.is_loopback


def _push_event(severity: str, source: str, message: str, origin: str = "live"):
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
    for host in _state["network"]["hosts"]:
        if host.get("ip") == ip and host.get("name"):
            return host["name"]
    return _state["network"]["devices"].get(ip, {}).get("name") or f"host-{ip.split('.')[-1]}"


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
        for d in ranked[:8]
    ]
    # Prefer discovered host count when available
    if _state["network"]["hosts"]:
        _state["network"]["active_devices"] = len(_state["network"]["hosts"])
    else:
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
    origin: str = "live",
    severity: str = "low",
):
    flow = {
        "id": f"flow-{int(time.time() * 1000)}-{random.randint(100, 999)}",
        "ts": _now_iso(),
        "src": src,
        "dst": dst,
        "proto": (proto or "TCP").upper(),
        "sport": int(sport or 0),
        "dport": int(dport or 0),
        "bytes": int(nbytes or 0),
        "device": device,
        "dns": "" if dns in ("", "-") else dns,
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

    if _is_private(src):
        ip = src
    elif _is_private(dst):
        ip = dst
    else:
        ip = src

    devices = net["devices"]
    if ip not in devices:
        role = next((h.get("role") for h in net["hosts"] if h.get("ip") == ip), None) or "host"
        devices[ip] = {
            "ip": ip,
            "name": device or _device_name(ip),
            "bytes": 0,
            "flows": 0,
            "role": role,
        }
    devices[ip]["bytes"] += max(flow["bytes"], 1)
    devices[ip]["flows"] += 1
    devices[ip]["name"] = device or devices[ip]["name"]
    _recompute_talkers()

    for stream in _state["streams"]:
        if stream["severity"] == "network":
            stream["matches"] += 1

    if severity in ("medium", "high") or flow["dport"] in (22, 23, 445, 3389) or "scan" in (dns or "").lower():
        msg = (
            f"HOME_NET src={src} dst={dst} proto={flow['proto']} "
            f"sport={flow['sport']} dport={flow['dport']} bytes={flow['bytes']} "
            f"device={device}" + (f" dns={dns}" if dns and dns != "-" else "")
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


def parse_host_disc_message(text: str) -> dict[str, Any] | None:
    match = HOST_RE.search(text or "")
    if not match:
        return None
    g = match.groupdict()
    ports_raw = g.get("ports") or "-"
    ports: list[int] = []
    if ports_raw not in ("-", "", "none"):
        for part in ports_raw.split(","):
            part = part.strip()
            if part.isdigit():
                ports.append(int(part))
    return {
        "ip": g["ip"],
        "mac": "" if g.get("mac") in (None, "-") else g["mac"],
        "name": "" if g.get("name") in (None, "-") else g["name"],
        "role": g.get("role") or "host",
        "ports": ports,
        "source": g.get("source") or "graylog",
        "state": "up",
    }


def classify_flow_severity(flow: dict[str, Any]) -> str:
    dport = int(flow.get("dport") or 0)
    dns = (flow.get("dns") or "").lower()
    dst = flow.get("dst") or ""
    if dport in (22, 23, 3389) and not _is_private(dst):
        return "high"
    if "scan" in dns or dport in (445, 139):
        return "medium"
    if int(flow.get("bytes") or 0) > 5_000_000:
        return "medium"
    return "low"


def _tick_throughput(n: int):
    _throughput.append({"t": int(time.time()), "n": n})


def _set_scan_input_status(status: str):
    for item in _state["inputs"]:
        if item.get("name") == "Home LAN scan":
            item["status"] = status
            return
    _state["inputs"].append({"name": "Home LAN scan", "port": None, "status": status})


def apply_scan_result(result: dict[str, Any], origin: str = "scan") -> dict[str, Any]:
    """Replace demo inventory with real scan hosts/flows."""
    net = _state["network"]
    hosts = result.get("hosts") or []
    flows = result.get("flows") or []
    subnet = (result.get("subnet") or {}).get("cidr") or net.get("subnet") or ""

    # Reset network counters when applying a fresh real scan
    if origin == "scan":
        _flows.clear()
        net["devices"] = {}
        net["protocols"] = {"TCP": 0, "UDP": 0, "DNS": 0, "Other": 0}
        net["bytes_in"] = 0
        net["bytes_out"] = 0
        net["flows_seen"] = 0

    net["source"] = origin
    net["scan_status"] = "idle"
    net["scan_error"] = ""
    net["last_scan"] = result.get("scanned_at") or _now_iso()
    net["subnet"] = subnet
    net["methods"] = list(result.get("methods") or [])
    net["hosts"] = hosts
    net["active_devices"] = len(hosts)

    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue
        net["devices"].setdefault(
            ip,
            {
                "ip": ip,
                "name": host.get("name") or _device_name(ip),
                "bytes": 0,
                "flows": 0,
                "role": host.get("role") or "host",
            },
        )
        net["devices"][ip]["name"] = host.get("name") or net["devices"][ip]["name"]
        net["devices"][ip]["role"] = host.get("role") or net["devices"][ip]["role"]

    for flow in flows:
        sev = classify_flow_severity(flow)
        _push_flow(
            src=str(flow.get("src")),
            dst=str(flow.get("dst")),
            proto=str(flow.get("proto") or "TCP"),
            sport=int(flow.get("sport") or 0),
            dport=int(flow.get("dport") or 0),
            nbytes=int(flow.get("bytes") or 0),
            device=str(flow.get("device") or _device_name(str(flow.get("src")))),
            dns=str(flow.get("dns") or ""),
            direction=str(flow.get("direction") or "out"),
            origin=origin,
            severity=sev,
        )

    # Hosts with open ports but no sampled sockets still show as talkers
    for host in hosts:
        ip = host["ip"]
        if ip in net["devices"] and net["devices"][ip]["flows"] == 0:
            net["devices"][ip]["flows"] = 1
            net["devices"][ip]["bytes"] = max(net["devices"][ip]["bytes"], 1)

    _recompute_talkers()
    _set_scan_input_status("up")

    summary = result.get("summary") or {}
    host_count = summary.get("hosts", len(hosts))
    flow_count = summary.get("flows", len(flows))
    _push_event(
        "low",
        "homenet",
        f"HOME_SCAN subnet={subnet or '?'} hosts={host_count} flows={flow_count} "
        f"methods={','.join(net['methods']) or 'arp'}",
        origin=origin,
    )
    if any(22 in (h.get("ports") or []) for h in hosts):
        _push_event("medium", "homenet", "HOME_SCAN: SSH (22/tcp) open on one or more LAN hosts", origin=origin)

    return {
        "ok": True,
        "hosts": host_count,
        "flows": flow_count,
        "subnet": subnet,
        "source": origin,
        "last_scan": net["last_scan"],
    }


async def graylog_reachable() -> bool:
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


async def pull_graylog_snapshot() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch recent messages from Graylog."""
    new_events: list[dict[str, Any]] = []
    new_flows: list[dict[str, Any]] = []
    new_hosts: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            headers = {
                "X-Requested-By": "ajsiem-dashboard",
                "Accept": "application/json",
            }
            auth = (GRAYLOG_USER, GRAYLOG_PASS)

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
                    # Preserve Home LAN scan status row
                    scan_row = next((i for i in _state["inputs"] if i.get("name") == "Home LAN scan"), None)
                    _state["inputs"] = mapped
                    if scan_row:
                        _state["inputs"].append(scan_row)
            except Exception:
                pass

            query = {
                "query": "*",
                "timerange": {"type": "relative", "range": 300},
                "limit": 50,
                "sort": "timestamp:desc",
            }
            res = await client.post(
                f"{GRAYLOG_URL}/api/views/search/messages",
                auth=auth,
                headers={**headers, "Content-Type": "application/json"},
                json=query,
            )
            if res.status_code >= 400:
                res = await client.get(
                    f"{GRAYLOG_URL}/api/search/universal/relative",
                    auth=auth,
                    headers=headers,
                    params={"query": "*", "range": 300, "limit": 50, "sort": "timestamp:desc"},
                )
            payload = res.json() if res.status_code < 400 else {}
            messages = payload.get("messages") or payload.get("data") or []
            for row in messages:
                msg = row.get("message") if isinstance(row, dict) else None
                if not isinstance(msg, dict):
                    msg = row if isinstance(row, dict) else {}
                text = str(msg.get("message") or msg.get("full_message") or "")
                host = parse_host_disc_message(text)
                if host:
                    new_hosts.append(host)
                    continue
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
        return [], [], []
    return new_events, new_flows, new_hosts


def classify_severity(text: str) -> str:
    lower = text.lower()
    if "home_net" in lower:
        parsed = parse_home_net_message(text)
        if parsed:
            return classify_flow_severity(parsed)
    if any(k in lower for k in ("high:", "root from", "syn flood", "nmap", "incorrect password attempts")):
        return "high"
    if any(k in lower for k in ("medium:", "failed password", "invalid user", "new user:", "home_scan")):
        return "medium" if "home_scan" not in lower else "low"
    return "low"


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
            "source": net["source"],
            "scan_status": net["scan_status"],
            "scan_error": net["scan_error"],
            "last_scan": net["last_scan"],
            "subnet": net["subnet"],
            "methods": list(net["methods"]),
            "bytes_in": net["bytes_in"],
            "bytes_out": net["bytes_out"],
            "active_devices": net["active_devices"],
            "flows_seen": net["flows_seen"],
            "protocols": dict(net["protocols"]),
            "top_talkers": list(net["top_talkers"]),
            "hosts": list(net["hosts"])[:64],
            "flows": list(_flows)[:40],
        },
    }


async def run_scan(cidr: str | None = None, with_ports: bool = True, with_flows: bool = True) -> dict[str, Any]:
    if _scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")
    async with _scan_lock:
        _state["network"]["scan_status"] = "running"
        _state["network"]["scan_error"] = ""
        _set_scan_input_status("idle")
        try:
            result = await asyncio.to_thread(
                scan_home_network,
                cidr or SCAN_CIDR,
                with_ports,
                with_flows,
            )
            return apply_scan_result(result, origin="scan")
        except Exception as exc:
            _state["network"]["scan_status"] = "error"
            _state["network"]["scan_error"] = str(exc)
            _set_scan_input_status("down")
            _push_event("medium", "homenet", f"HOME_SCAN failed: {exc}", origin="scan")
            raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.on_event("startup")
async def startup():
    # Real data only — no synthetic auth/network events.
    asyncio.create_task(live_loop())


async def live_loop():
    while True:
        try:
            reachable = await graylog_reachable()
            _state["graylog_ok"] = reachable
            if reachable:
                _state["mode"] = "live"
                fresh_events, fresh_flows, fresh_hosts = await pull_graylog_snapshot()
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
                if fresh_hosts and _state["network"]["source"] != "scan":
                    apply_scan_result(
                        {
                            "scanned_at": _now_iso(),
                            "subnet": {"cidr": _state["network"].get("subnet") or ""},
                            "methods": ["graylog"],
                            "hosts": fresh_hosts,
                            "flows": [],
                            "summary": {"hosts": len(fresh_hosts), "flows": 0},
                        },
                        origin="graylog",
                    )
                    added += len(fresh_hosts)
                for flow in reversed(fresh_flows):
                    if flow["id"] in seen_flows:
                        continue
                    if _state["network"]["source"] not in ("scan", "graylog"):
                        _state["network"]["source"] = "graylog"
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
                _tick_throughput(added if added else 0)
            else:
                _state["mode"] = "waiting"
                _tick_throughput(0)
        except Exception:
            _state["mode"] = "waiting"
            _tick_throughput(0)
        await asyncio.sleep(POLL_SECONDS)


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "mode": _state["mode"],
        "graylog_ok": _state["graylog_ok"],
        "network_source": _state["network"]["source"],
        "scan_status": _state["network"]["scan_status"],
    }


@app.get("/api/snapshot")
async def api_snapshot():
    return snapshot()


@app.get("/api/network")
async def api_network():
    return snapshot()["network"]


@app.post("/api/network/scan")
async def api_network_scan(body: ScanRequest | None = None):
    body = body or ScanRequest()
    return await run_scan(cidr=body.cidr, with_ports=body.with_ports, with_flows=body.with_flows)


@app.post("/api/network/ingest")
async def api_network_ingest(payload: IngestPayload):
    result = payload.model_dump()
    return apply_scan_result(result, origin="scan")


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

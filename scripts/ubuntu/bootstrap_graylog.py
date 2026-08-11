#!/usr/bin/env python3
"""Create AJSIEM Graylog inputs and Low/Medium/High streams."""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("GRAYLOG_URL", "http://127.0.0.1:9000").rstrip("/")
USER = os.environ.get("GRAYLOG_API_USER", "admin")
PASS = os.environ.get("GRAYLOG_ROOT_PASSWORD", "admin")
AUTH = base64.b64encode(f"{USER}:{PASS}".encode()).decode()


def api(method: str, path: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-By": "ajsiem",
            "Authorization": f"Basic {AUTH}",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore")
        raise RuntimeError(f"{method} {path} → {exc.code}: {detail[:400]}") from exc


def ensure_input(title: str, type_name: str, configuration: dict):
    existing = api("GET", "/api/system/inputs").get("inputs", [])
    if any(i.get("title") == title for i in existing):
        print(f"[=] Input exists: {title}")
        return
    api(
        "POST",
        "/api/system/inputs",
        {
            "title": title,
            "type": type_name,
            "global": True,
            "configuration": configuration,
            "node": None,
        },
    )
    print(f"[+] Created input: {title}")


def default_index_set_id() -> str:
    sets = api("GET", "/api/system/indices/index_sets?skip=0&limit=50")["index_sets"]
    for item in sets:
        if item.get("default"):
            return item["id"]
    return sets[0]["id"]


def ensure_stream(title: str, description: str, rules: list[dict]):
    streams = api("GET", "/api/streams").get("streams", [])
    by_title = {s["title"]: s["id"] for s in streams}
    if title in by_title:
        print(f"[=] Stream exists: {title}")
        sid = by_title[title]
    else:
        created = api(
            "POST",
            "/api/streams",
            {
                "title": title,
                "description": description,
                "matching_type": "OR",
                "remove_matches_from_default_stream": False,
                "index_set_id": default_index_set_id(),
            },
        )
        sid = created["stream_id"]
        print(f"[+] Created stream: {title}")
        for rule in rules:
            api("POST", f"/api/streams/{sid}/rules", rule)
    try:
        api("POST", f"/api/streams/{sid}/resume")
    except Exception:
        pass


def main():
    ensure_input(
        "AJSIEM Syslog TCP",
        "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
        {
            "bind_address": "0.0.0.0",
            "port": 1514,
            "recv_buffer_size": 1048576,
            "max_message_size": 2097152,
            "tcp_keepalive": False,
            "tls_enable": False,
            "use_null_delimiter": False,
            "number_worker_threads": 2,
        },
    )
    ensure_input(
        "AJSIEM Syslog UDP",
        "org.graylog2.inputs.syslog.udp.SyslogUDPInput",
        {
            "bind_address": "0.0.0.0",
            "port": 1514,
            "recv_buffer_size": 1048576,
            "locate_via_dns": False,
            "force_rdns": False,
            "allow_override_date": True,
            "store_full_message": True,
            "expand_structured_data": False,
            "number_worker_threads": 2,
        },
    )
    ensure_input(
        "AJSIEM GELF UDP",
        "org.graylog2.inputs.gelf.udp.GELFUDPInput",
        {
            "bind_address": "0.0.0.0",
            "port": 12201,
            "recv_buffer_size": 1048576,
            "decompress_size_limit": 8388608,
            "number_worker_threads": 2,
        },
    )
    ensure_input(
        "AJSIEM Beats",
        "org.graylog.plugins.beats.Beats2Input",
        {
            "bind_address": "0.0.0.0",
            "port": 5044,
            "recv_buffer_size": 1048576,
            "no_beats_prefix": False,
            "number_worker_threads": 2,
            "tcp_keepalive": False,
            "tls_enable": False,
        },
    )

    # Stream rule type 6 = contains
    ensure_stream(
        "AJSIEM Low",
        "Low severity / informational activity",
        [
            {"field": "message", "type": 6, "inverted": False, "value": "Accepted publickey"},
            {"field": "message", "type": 6, "inverted": False, "value": "LOW:"},
            {"field": "message", "type": 6, "inverted": False, "value": "COMMAND="},
        ],
    )
    ensure_stream(
        "AJSIEM Medium",
        "Suspicious but non-critical activity",
        [
            {"field": "message", "type": 6, "inverted": False, "value": "Failed password"},
            {"field": "message", "type": 6, "inverted": False, "value": "Invalid user"},
            {"field": "message", "type": 6, "inverted": False, "value": "new user:"},
            {"field": "message", "type": 6, "inverted": False, "value": "MEDIUM:"},
        ],
    )
    ensure_stream(
        "AJSIEM High",
        "Critical security events requiring response",
        [
            {"field": "message", "type": 6, "inverted": False, "value": "Accepted password for root"},
            {"field": "message", "type": 6, "inverted": False, "value": "SYN flood"},
            {"field": "message", "type": 6, "inverted": False, "value": "Nmap"},
            {"field": "message", "type": 6, "inverted": False, "value": "incorrect password attempts"},
            {"field": "message", "type": 6, "inverted": False, "value": "HIGH:"},
        ],
    )
    ensure_stream(
        "AJSIEM Home Network",
        "Home LAN flow telemetry (HOME_NET / HOST_DISC / HOME_SCAN)",
        [
            {"field": "message", "type": 6, "inverted": False, "value": "HOME_NET"},
            {"field": "message", "type": 6, "inverted": False, "value": "HOST_DISC"},
            {"field": "message", "type": 6, "inverted": False, "value": "HOME_SCAN"},
            {"field": "message", "type": 6, "inverted": False, "value": "homenet"},
        ],
    )

    print("[+] Bootstrap complete.")
    print(f"    UI: {BASE}")
    print("    Create Event Definitions from configs/graylog/alerts/alert-catalog.json")
    print("    Home network: emit flows with scripts/kali/generate-home-traffic.sh")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(1)

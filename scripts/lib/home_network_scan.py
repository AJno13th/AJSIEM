#!/usr/bin/env python3
"""Discover hosts and sample flows on the local (home) LAN.

Authorized / lab use only — scan networks you own or have permission to test.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE) and not addr.is_loopback


def _run(cmd: list[str], timeout: float = 60.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"missing binary: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def detect_local_subnet(preferred_cidr: str | None = None) -> dict[str, Any]:
    """Pick the primary private IPv4 interface + CIDR."""
    if preferred_cidr:
        net = ipaddress.ip_network(preferred_cidr, strict=False)
        return {
            "cidr": str(net),
            "interface": os.environ.get("AJSIEM_SCAN_IFACE") or "",
            "local_ip": str(next(net.hosts(), net.network_address)),
            "method": "override",
        }

    # ip -j addr (modern iproute2)
    code, out, _ = _run(["ip", "-j", "addr"], timeout=5)
    candidates: list[dict[str, Any]] = []
    if code == 0 and out.strip():
        try:
            for iface in json.loads(out):
                ifname = iface.get("ifname") or ""
                if ifname in ("lo",) or ifname.startswith(("docker", "br-", "veth", "virbr")):
                    continue
                for addr in iface.get("addr_info") or []:
                    if addr.get("family") != "inet":
                        continue
                    ip = addr.get("local")
                    prefix = int(addr.get("prefixlen") or 24)
                    if not ip or not _is_private(ip):
                        continue
                    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    # Prefer typical home /24 over huge clouds
                    score = 100 if prefix >= 24 else 40
                    if ifname.startswith(("eth", "en", "wl", "wlan")):
                        score += 20
                    candidates.append(
                        {
                            "cidr": str(network),
                            "interface": ifname,
                            "local_ip": ip,
                            "method": "iproute",
                            "score": score,
                        }
                    )
        except json.JSONDecodeError:
            pass

    if not candidates:
        # Fallback: hostname -I
        code, out, _ = _run(["hostname", "-I"], timeout=3)
        for token in out.split():
            if _is_private(token):
                network = ipaddress.ip_network(f"{token}/24", strict=False)
                candidates.append(
                    {
                        "cidr": str(network),
                        "interface": "",
                        "local_ip": token,
                        "method": "hostname",
                        "score": 10,
                    }
                )
                break

    if not candidates:
        raise RuntimeError(
            "No private LAN interface found. Set --cidr 192.168.1.0/24 explicitly."
        )
    best = sorted(candidates, key=lambda c: c["score"], reverse=True)[0]
    best.pop("score", None)
    return best


def read_arp_neighbors() -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}

    # ip neigh
    code, out, _ = _run(["ip", "neigh", "show"], timeout=5)
    if code == 0:
        for line in out.splitlines():
            # 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            parts = line.split()
            if len(parts) < 1:
                continue
            ip = parts[0]
            if not _is_private(ip):
                continue
            mac = ""
            state = parts[-1] if parts else ""
            if "lladdr" in parts:
                mac = parts[parts.index("lladdr") + 1]
            if state.upper() in ("FAILED", "INCOMPLETE"):
                continue
            hosts[ip] = {
                "ip": ip,
                "mac": mac.lower() if mac else "",
                "name": "",
                "source": "arp",
                "ports": [],
                "state": state,
            }

    # /proc/net/arp fallback
    arp_path = Path("/proc/net/arp")
    if arp_path.exists():
        for line in arp_path.read_text().splitlines()[1:]:
            cols = line.split()
            if len(cols) < 6:
                continue
            ip, mac = cols[0], cols[3]
            if mac == "00:00:00:00:00:00" or not _is_private(ip):
                continue
            hosts.setdefault(
                ip,
                {
                    "ip": ip,
                    "mac": mac.lower(),
                    "name": "",
                    "source": "proc-arp",
                    "ports": [],
                    "state": "REACHABLE",
                },
            )
            if not hosts[ip].get("mac"):
                hosts[ip]["mac"] = mac.lower()

    return list(hosts.values())


def resolve_names(hosts: list[dict[str, Any]]) -> None:
    for host in hosts:
        if host.get("name"):
            continue
        try:
            name = socket.gethostbyaddr(host["ip"])[0]
            host["name"] = name.split(".")[0]
        except (socket.herror, socket.gaierror, OSError):
            host["name"] = f"host-{host['ip'].split('.')[-1]}"


def nmap_ping_sweep(cidr: str, timeout: float = 90.0) -> list[dict[str, Any]]:
    if not shutil.which("nmap"):
        return []
    # Host discovery only — no port scan yet
    code, out, err = _run(
        ["nmap", "-sn", "-n", "--max-retries", "1", "--host-timeout", "3s", cidr],
        timeout=timeout,
    )
    if code not in (0, 1):
        return []
    found: list[dict[str, Any]] = []
    current_ip = ""
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (\S+)", line)
        if m:
            token = m.group(1)
            # Sometimes "name (ip)"
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", token)
            current_ip = ip_m.group(1) if ip_m else token
            if _is_private(current_ip):
                found.append(
                    {
                        "ip": current_ip,
                        "mac": "",
                        "name": "",
                        "source": "nmap-ping",
                        "ports": [],
                        "state": "up",
                    }
                )
            continue
        mac_m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{11,17})", line)
        if mac_m and found:
            found[-1]["mac"] = mac_m.group(1).lower()
    return found


def nmap_top_ports(ips: list[str], top: int = 20, timeout: float = 120.0) -> dict[str, list[int]]:
    if not ips or not shutil.which("nmap"):
        return {}
    # Cap targets for lab safety / runtime
    targets = ips[:48]
    code, out, _ = _run(
        [
            "nmap",
            "-Pn",
            "-n",
            "--top-ports",
            str(top),
            "--open",
            "--max-retries",
            "1",
            "--host-timeout",
            "8s",
            *targets,
        ],
        timeout=timeout,
    )
    if code not in (0, 1):
        return {}
    ports: dict[str, list[int]] = {}
    current = ""
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (\S+)", line)
        if m:
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", m.group(1))
            current = ip_m.group(1) if ip_m else m.group(1)
            ports.setdefault(current, [])
            continue
        pm = re.match(r"^(\d+)/tcp\s+open", line)
        if pm and current:
            ports.setdefault(current, []).append(int(pm.group(1)))
    return ports


def sample_local_flows(local_ip: str, limit: int = 40) -> list[dict[str, Any]]:
    """Sample established sockets via `ss` as real home-LAN traffic."""
    code, out, _ = _run(["ss", "-tanup"], timeout=5)
    if code != 0:
        code, out, _ = _run(["ss", "-tan"], timeout=5)
    flows: list[dict[str, Any]] = []
    if code != 0:
        return flows

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        if state not in ("ESTAB", "ESTABLISHED"):
            continue
        local = parts[4]
        peer = parts[5] if len(parts) > 5 else ""
        sport, sip = _split_endpoint(local)
        dport, dip = _split_endpoint(peer)
        if not sip or not dip:
            continue
        # Prefer flows involving this host or private LAN peers
        if not (_is_private(sip) or _is_private(dip) or sip == local_ip or dip == local_ip):
            continue
        direction = "lan" if _is_private(sip) and _is_private(dip) else "out"
        if _is_private(dip) and not _is_private(sip):
            direction = "in"
        device = f"local-{local_ip.split('.')[-1]}"
        if sip == local_ip or _is_private(sip):
            device = f"host-{sip.split('.')[-1]}"
        flows.append(
            {
                "src": sip,
                "dst": dip,
                "proto": "TCP",
                "sport": sport or 0,
                "dport": dport or 0,
                "bytes": 0,
                "device": device,
                "dns": "",
                "direction": direction,
                "origin": "scan",
            }
        )
        if len(flows) >= limit:
            break
    return flows


def _split_endpoint(endpoint: str) -> tuple[int | None, str | None]:
    # Formats: 192.168.1.10:443  or [fe80::1]:443  or *:53
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        m = re.match(r"\[([^\]]+)\]:(\d+)$", endpoint)
        if not m:
            return None, None
        return int(m.group(2)), m.group(1)
    if endpoint.count(":") == 1:
        ip, port = endpoint.rsplit(":", 1)
        if ip in ("*", "0.0.0.0"):
            return None, None
        try:
            return int(port), ip
        except ValueError:
            return None, None
    return None, None


def merge_hosts(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, dict[str, Any]] = {}
    for group in groups:
        for host in group:
            ip = host.get("ip")
            if not ip or not _is_private(ip):
                continue
            cur = by_ip.setdefault(
                ip,
                {
                    "ip": ip,
                    "mac": "",
                    "name": "",
                    "source": host.get("source") or "scan",
                    "ports": [],
                    "state": host.get("state") or "up",
                    "role": "host",
                },
            )
            if host.get("mac") and not cur.get("mac"):
                cur["mac"] = host["mac"]
            if host.get("name"):
                cur["name"] = host["name"]
            srcs = {cur.get("source"), host.get("source")}
            cur["source"] = "+".join(sorted(s for s in srcs if s))
            for p in host.get("ports") or []:
                if p not in cur["ports"]:
                    cur["ports"].append(p)
    return sorted(by_ip.values(), key=lambda h: tuple(int(x) for x in h["ip"].split(".")))


def classify_role(host: dict[str, Any], gateway_guess: str) -> str:
    ports = set(host.get("ports") or [])
    if host["ip"] == gateway_guess:
        return "gateway"
    if 445 in ports or 139 in ports:
        return "storage"
    if 80 in ports or 443 in ports:
        return "service"
    if 22 in ports:
        return "lab"
    return "host"


def scan_home_network(
    cidr: str | None = None,
    with_ports: bool = True,
    with_flows: bool = True,
) -> dict[str, Any]:
    started = time.time()
    local = detect_local_subnet(cidr)
    network = ipaddress.ip_network(local["cidr"], strict=False)
    gateway_guess = str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address)

    arp_hosts = read_arp_neighbors()
    # Keep ARP entries inside the target CIDR
    arp_hosts = [h for h in arp_hosts if ipaddress.ip_address(h["ip"]) in network]

    nmap_hosts = nmap_ping_sweep(local["cidr"])
    hosts = merge_hosts(arp_hosts, nmap_hosts)

    # Always include self
    if local["local_ip"] and _is_private(local["local_ip"]):
        hosts = merge_hosts(
            hosts,
            [
                {
                    "ip": local["local_ip"],
                    "mac": "",
                    "name": socket.gethostname().split(".")[0],
                    "source": "local",
                    "ports": [],
                    "state": "up",
                }
            ],
        )

    resolve_names(hosts)

    port_map: dict[str, list[int]] = {}
    if with_ports and hosts:
        port_map = nmap_top_ports([h["ip"] for h in hosts], top=20)
        for host in hosts:
            host["ports"] = sorted(set(port_map.get(host["ip"], []) + (host.get("ports") or [])))

    for host in hosts:
        host["role"] = classify_role(host, gateway_guess)
        if not host.get("name"):
            host["name"] = f"host-{host['ip'].split('.')[-1]}"

    flows: list[dict[str, Any]] = []
    if with_flows:
        flows = sample_local_flows(local["local_ip"])
        # Attach friendlier device names from inventory
        names = {h["ip"]: h["name"] for h in hosts}
        for flow in flows:
            if flow["src"] in names:
                flow["device"] = names[flow["src"]]
            elif flow["dst"] in names and flow["direction"] == "in":
                flow["device"] = names[flow["dst"]]

    methods = ["arp"]
    if nmap_hosts:
        methods.append("nmap-ping")
    if port_map:
        methods.append("nmap-ports")
    if flows:
        methods.append("ss-flows")

    return {
        "ok": True,
        "scanned_at": _now(),
        "duration_s": round(time.time() - started, 2),
        "subnet": local,
        "gateway_guess": gateway_guess,
        "methods": methods,
        "hosts": hosts,
        "flows": flows,
        "summary": {
            "hosts": len(hosts),
            "flows": len(flows),
            "with_mac": sum(1 for h in hosts if h.get("mac")),
            "with_ports": sum(1 for h in hosts if h.get("ports")),
        },
    }


def format_syslog_lines(result: dict[str, Any]) -> list[str]:
    lines = []
    subnet = result.get("subnet", {}).get("cidr", "?")
    lines.append(
        f"HOME_SCAN subnet={subnet} hosts={result['summary']['hosts']} "
        f"flows={result['summary']['flows']} methods={','.join(result.get('methods') or [])}"
    )
    for host in result.get("hosts") or []:
        ports = ",".join(str(p) for p in (host.get("ports") or [])[:12]) or "-"
        lines.append(
            f"HOST_DISC ip={host['ip']} mac={host.get('mac') or '-'} "
            f"name={host.get('name') or '-'} role={host.get('role') or 'host'} "
            f"ports={ports} source={host.get('source') or 'scan'}"
        )
    for flow in result.get("flows") or []:
        lines.append(
            f"HOME_NET src={flow['src']} dst={flow['dst']} proto={flow.get('proto', 'TCP')} "
            f"sport={flow.get('sport', 0)} dport={flow.get('dport', 0)} "
            f"bytes={flow.get('bytes', 0)} device={flow.get('device', 'scan')} "
            f"dns={flow.get('dns') or '-'} dir={flow.get('direction', 'out')}"
        )
    return lines


def post_to_dashboard(url: str, result: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    endpoint = url.rstrip("/") + "/api/network/ingest"
    body = json.dumps(result).encode()
    req = request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore")
        raise RuntimeError(f"POST {endpoint} → {exc.code}: {detail[:300]}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"POST {endpoint} failed: {exc}") from exc


def emit_logger(lines: list[str]) -> None:
    if not shutil.which("logger"):
        return
    for line in lines:
        _run(["logger", "-p", "local0.info", "-t", "homenet", line], timeout=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan the local home LAN for AJSIEM")
    parser.add_argument("--cidr", help="Override target CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--no-ports", action="store_true", help="Skip nmap top-ports probe")
    parser.add_argument("--no-flows", action="store_true", help="Skip ss flow sampling")
    parser.add_argument("--json", action="store_true", help="Print JSON result")
    parser.add_argument("--syslog", action="store_true", help="Emit HOME_SCAN/HOST_DISC/HOME_NET via logger")
    parser.add_argument(
        "--post",
        metavar="DASHBOARD_URL",
        help="POST results to dashboard ingest API (e.g. http://127.0.0.1:8088)",
    )
    args = parser.parse_args(argv)

    try:
        result = scan_home_network(
            cidr=args.cidr,
            with_ports=not args.no_ports,
            with_flows=not args.no_flows,
        )
    except Exception as exc:
        print(f"[!] scan failed: {exc}", file=sys.stderr)
        return 1

    lines = format_syslog_lines(result)
    if args.syslog:
        emit_logger(lines)

    if args.post:
        try:
            resp = post_to_dashboard(args.post, result)
            print(f"[+] posted to dashboard: hosts={resp.get('hosts')} flows={resp.get('flows')}")
        except Exception as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        sub = result["subnet"]
        print(f"[+] scanned {sub.get('cidr')} via {sub.get('interface') or 'auto'} in {result['duration_s']}s")
        print(f"    methods: {', '.join(result['methods'])}")
        print(f"    hosts={result['summary']['hosts']} flows={result['summary']['flows']}")
        for host in result["hosts"]:
            ports = ",".join(str(p) for p in host.get("ports") or []) or "-"
            print(
                f"    - {host['ip']:15}  {(host.get('name') or '-'):20}  "
                f"mac={host.get('mac') or '-':17}  ports={ports}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

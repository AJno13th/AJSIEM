#!/usr/bin/env bash
# Real home-LAN discovery for AJSIEM (ARP + optional nmap + ss flows).
# Authorized / lab use only — scan networks you own.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCANNER="${ROOT}/scripts/lib/home_network_scan.py"

DASHBOARD_URL="${AJSIEM_DASHBOARD_URL:-http://127.0.0.1:8088}"
CIDR="${AJSIEM_SCAN_CIDR:-}"
EXTRA=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [--cidr 192.168.1.0/24] [--no-ports] [--no-post] [--json]

Discovers live hosts on your home LAN and posts them to the AJSIEM dashboard.

Env:
  AJSIEM_DASHBOARD_URL   default ${DASHBOARD_URL}
  AJSIEM_SCAN_CIDR       optional CIDR override
EOF
}

POST=1
JSON=0
SYSLOG=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --cidr) CIDR="$2"; shift 2 ;;
    --no-ports) EXTRA+=(--no-ports); shift ;;
    --no-flows) EXTRA+=(--no-flows); shift ;;
    --no-post) POST=0; shift ;;
    --no-syslog) SYSLOG=0; shift ;;
    --json) JSON=1; shift ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

ARGS=()
[[ -n "${CIDR}" ]] && ARGS+=(--cidr "${CIDR}")
ARGS+=("${EXTRA[@]}")
[[ "${SYSLOG}" == "1" ]] && ARGS+=(--syslog)
[[ "${POST}" == "1" ]] && ARGS+=(--post "${DASHBOARD_URL}")
[[ "${JSON}" == "1" ]] && ARGS+=(--json)

echo "[*] AJSIEM real home-network scan"
echo "    dashboard: ${DASHBOARD_URL}"
[[ -n "${CIDR}" ]] && echo "    cidr: ${CIDR}"

# Prefer root for ARP/nmap accuracy, but allow unprivileged ARP/ss fallback.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] not root — ARP/nmap may be incomplete; re-run with sudo for best results"
fi

exec python3 "${SCANNER}" "${ARGS[@]}"

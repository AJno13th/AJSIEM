#!/usr/bin/env bash
# Same scanner as Kali — run on the Ubuntu SIEM host (bridged to home LAN).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec "${ROOT}/scripts/kali/scan-home-network.sh" "$@"

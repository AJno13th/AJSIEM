#!/usr/bin/env bash
# Configure Kali to ship logs to the Ubuntu SIEM host (rsyslog → Syslog TCP 1514).
# Usage: sudo ./setup-log-forwarding.sh <ubuntu-ip>
set -euo pipefail

SIEM_IP="${1:-}"
if [[ -z "${SIEM_IP}" ]]; then
  echo "Usage: sudo $0 <ubuntu-siem-ip>"
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0 ${SIEM_IP}"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="${ROOT}/configs/rsyslog/60-ajsiem-forward.conf"
DEST="/etc/rsyslog.d/60-ajsiem-forward.conf"

apt-get update
apt-get install -y rsyslog

sed "s/__SIEM_SERVER_IP__/${SIEM_IP}/g" "${TEMPLATE}" >"${DEST}"
systemctl restart rsyslog

# Helpful identity tags for Graylog streams
hostnamectl set-hostname kali-siem-lab 2>/dev/null || true

logger -t ajsiem "AJSIEM test: Kali log forwarding configured toward ${SIEM_IP}:1514"

echo "[+] rsyslog forwarding *.* @@${SIEM_IP}:1514"
echo "[*] Optional Filebeat/GELF: ./scripts/kali/setup-filebeat.sh ${SIEM_IP}"
echo "[*] Generate sample noise: ./scripts/kali/generate-lab-events.sh"

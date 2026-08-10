#!/usr/bin/env bash
# Optional: Filebeat → Graylog Beats input (TCP 5044) for richer Kali shipping.
set -euo pipefail
SIEM_IP="${1:-}"
if [[ -z "${SIEM_IP}" ]]; then
  echo "Usage: sudo $0 <ubuntu-siem-ip>"
  exit 1
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
  >/etc/apt/sources.list.d/elastic-8.x.list
apt-get update
apt-get install -y filebeat

sed "s/__SIEM_SERVER_IP__/${SIEM_IP}/g" "${ROOT}/configs/filebeat/filebeat.yml" >/etc/filebeat/filebeat.yml
systemctl enable --now filebeat
echo "[+] Filebeat shipping to ${SIEM_IP}:5044"

#!/usr/bin/env bash
# Start MongoDB + OpenSearch + Graylog on the Ubuntu SIEM host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

if [[ ! -f .env ]]; then
  echo "[!] Missing .env — run: ./scripts/ubuntu/generate-secrets.sh"
  exit 1
fi

# shellcheck disable=SC1091
source .env
if [[ -z "${GRAYLOG_PASSWORD_SECRET:-}" || -z "${GRAYLOG_ROOT_PASSWORD_SHA2:-}" ]]; then
  echo "[!] Secrets missing in .env — run generate-secrets.sh"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] Docker is required. Install Docker Engine on Ubuntu first."
  exit 1
fi

# OpenSearch needs vm.max_map_count
if [[ "$(uname -s)" == "Linux" ]]; then
  current="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [[ "${current}" -lt 262144 ]]; then
    echo "[*] Raising vm.max_map_count for OpenSearch"
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-ajsiem.conf >/dev/null
  fi
fi

docker compose pull
docker compose up -d

echo
echo "[+] Stack starting."
echo "    Graylog UI : ${GRAYLOG_HTTP_EXTERNAL_URI:-http://127.0.0.1:9000/}"
echo "    OpenSearch : http://127.0.0.1:9200"
echo "    Syslog     : TCP/UDP 1514"
echo "    GELF       : UDP/TCP 12201"
echo
echo "Next: ./scripts/ubuntu/bootstrap-graylog.sh"

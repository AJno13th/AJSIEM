#!/usr/bin/env bash
# Bootstrap Graylog inputs + Low/Medium/High streams via REST API.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

GRAYLOG_URL="${GRAYLOG_URL:-${GRAYLOG_HTTP_EXTERNAL_URI:-http://127.0.0.1:9000}}"
GRAYLOG_URL="${GRAYLOG_URL%/}"
export GRAYLOG_URL
export GRAYLOG_API_USER="${GRAYLOG_API_USER:-admin}"
export GRAYLOG_ROOT_PASSWORD="${GRAYLOG_ROOT_PASSWORD:-admin}"

echo "[*] Waiting for Graylog API at ${GRAYLOG_URL} ..."
for _ in $(seq 1 60); do
  if curl -sf -u "${GRAYLOG_API_USER}:${GRAYLOG_ROOT_PASSWORD}" \
      -H "X-Requested-By: ajsiem" \
      "${GRAYLOG_URL}/api/system/lbstatus" >/dev/null 2>&1; then
    echo "[+] Graylog is up"
    break
  fi
  sleep 5
done

python3 "${ROOT}/scripts/ubuntu/bootstrap_graylog.py"

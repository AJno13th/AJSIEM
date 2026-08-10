#!/usr/bin/env bash
# Start the AJSIEM live operations dashboard (demo mode if Graylog is down).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DASH="${ROOT}/dashboard"
cd "${DASH}"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

# shellcheck disable=SC1091
source .venv/bin/activate

export AJSIEM_DEMO="${AJSIEM_DEMO:-auto}"
export DASHBOARD_HOST="${DASHBOARD_HOST:-0.0.0.0}"
export DASHBOARD_PORT="${DASHBOARD_PORT:-8088}"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

echo "[+] AJSIEM dashboard → http://127.0.0.1:${DASHBOARD_PORT}"
echo "    Mode: ${AJSIEM_DEMO} (auto uses Graylog when reachable)"
exec python -m uvicorn app:app --host "${DASHBOARD_HOST}" --port "${DASHBOARD_PORT}"

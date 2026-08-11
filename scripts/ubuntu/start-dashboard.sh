#!/usr/bin/env bash
# Start the AJSIEM live operations dashboard (real Graylog + scan data only).
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

export DASHBOARD_HOST="${DASHBOARD_HOST:-0.0.0.0}"
export DASHBOARD_PORT="${DASHBOARD_PORT:-8088}"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

echo "[+] AJSIEM dashboard → http://127.0.0.1:${DASHBOARD_PORT}"
echo "    Real events only (Graylog ingest + home LAN scan) — no demo feed"
exec python -m uvicorn app:app --host "${DASHBOARD_HOST}" --port "${DASHBOARD_PORT}"

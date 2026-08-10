#!/usr/bin/env bash
# Generate Graylog secrets into .env for the Docker lab stack.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${ROOT}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${ROOT}/.env.example" "${ENV_FILE}"
  echo "[+] Created ${ENV_FILE} from .env.example"
fi

# head closes early; ignore SIGPIPE from tr under pipefail
SECRET="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 96 || true)"
if [[ ${#SECRET} -lt 64 ]]; then
  echo "[!] Failed to generate password_secret"
  exit 1
fi
PASSWORD="${GRAYLOG_ROOT_PASSWORD:-}"
if [[ -z "${PASSWORD}" ]]; then
  read -r -s -p "Enter Graylog admin password: " PASSWORD
  echo
fi
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(printf '%s' "${PASSWORD}" | sha256sum | awk '{print $1}')"
else
  SHA="$(printf '%s' "${PASSWORD}" | shasum -a 256 | awk '{print $1}')"
fi

# Portable in-place edit
tmp="$(mktemp)"
awk -v secret="${SECRET}" -v sha="${SHA}" -v pass="${PASSWORD}" '
  BEGIN { FS=OFS="=" }
  /^GRAYLOG_PASSWORD_SECRET=/ { print "GRAYLOG_PASSWORD_SECRET", secret; next }
  /^GRAYLOG_ROOT_PASSWORD_SHA2=/ { print "GRAYLOG_ROOT_PASSWORD_SHA2", sha; next }
  /^GRAYLOG_ROOT_PASSWORD=/ { print "GRAYLOG_ROOT_PASSWORD", pass; next }
  { print }
' "${ENV_FILE}" >"${tmp}"
mv "${tmp}" "${ENV_FILE}"

echo "[+] Wrote GRAYLOG_PASSWORD_SECRET and GRAYLOG_ROOT_PASSWORD_SHA2 to .env"
echo "[*] Set GRAYLOG_HTTP_EXTERNAL_URI to http://<ubuntu-bridged-ip>:9000/"

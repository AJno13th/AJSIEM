#!/usr/bin/env bash
# Generate Graylog secrets into .env for the Docker lab stack.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${ROOT}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${ROOT}/.env.example" "${ENV_FILE}"
  echo "[+] Created ${ENV_FILE} from .env.example"
fi

SECRET="$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 96)"
PASSWORD="${GRAYLOG_ROOT_PASSWORD:-}"
if [[ -z "${PASSWORD}" ]]; then
  read -r -s -p "Enter Graylog admin password: " PASSWORD
  echo
fi
SHA="$(printf '%s' "${PASSWORD}" | sha256sum | awk '{print $1}')"

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

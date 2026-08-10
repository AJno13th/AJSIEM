#!/usr/bin/env bash
# Bare-metal path (VirtualBox lab) — MongoDB, OpenSearch, Graylog on Ubuntu 22.04.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y gnupg curl wget ca-certificates lsb-release apt-transport-https

echo "[1/3] MongoDB 7.0"
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
  >/etc/apt/sources.list.d/mongodb-org-7.0.list
apt-get update
apt-get install -y mongodb-org
systemctl enable --now mongod

echo "[2/3] OpenSearch 2.x"
curl -o- https://artifacts.opensearch.org/publickeys/opensearch.pgp \
  | gpg --dearmor --batch --yes -o /usr/share/keyrings/opensearch-keyring
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" \
  >/etc/apt/sources.list.d/opensearch-2.x.list
apt-get update
# Single-node lab defaults
echo "OPENSEARCH_INITIAL_ADMIN_PASSWORD=AjSiemLab_ChangeMe1!" >/etc/default/opensearch
apt-get install -y opensearch
# Disable security plugin for lab simplicity (do NOT do this in production)
if [[ -f /etc/opensearch/opensearch.yml ]]; then
  grep -q 'plugins.security.disabled' /etc/opensearch/opensearch.yml \
    || echo 'plugins.security.disabled: true' >>/etc/opensearch/opensearch.yml
  grep -q 'discovery.type' /etc/opensearch/opensearch.yml \
    || echo 'discovery.type: single-node' >>/etc/opensearch/opensearch.yml
fi
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >/etc/sysctl.d/99-ajsiem.conf
systemctl enable --now opensearch

echo "[3/3] Graylog 5.0"
wget -q https://packages.graylog2.org/repo/packages/graylog-5.0-repository_latest.deb -O /tmp/graylog-repo.deb
dpkg -i /tmp/graylog-repo.deb
apt-get update
apt-get install -y graylog-server

CONF=/etc/graylog/server/server.conf
SECRET="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 96 || true)"
read -r -s -p "Enter Graylog root password: " ROOT_PASS
echo
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(printf '%s' "${ROOT_PASS}" | sha256sum | awk '{print $1}')"
else
  SHA="$(printf '%s' "${ROOT_PASS}" | shasum -a 256 | awk '{print $1}')"
fi
IP="$(hostname -I | awk '{print $1}')"

sed -i "s|^password_secret =.*|password_secret = ${SECRET}|" "${CONF}"
sed -i "s|^root_password_sha2 =.*|root_password_sha2 = ${SHA}|" "${CONF}"
sed -i "s|^#http_bind_address =.*|http_bind_address = ${IP}:9000|" "${CONF}"
sed -i "s|^http_bind_address =.*|http_bind_address = ${IP}:9000|" "${CONF}"
# OpenSearch without auth for lab
grep -q '^elasticsearch_hosts' "${CONF}" \
  || echo 'elasticsearch_hosts = http://127.0.0.1:9200' >>"${CONF}"

systemctl daemon-reload
systemctl enable --now graylog-server

echo
echo "[+] Bare-metal SIEM packages installed."
echo "    Graylog UI: http://${IP}:9000  (admin / password you set)"
echo "    Next: configure Kali forwarding with scripts/kali/setup-log-forwarding.sh ${IP}"

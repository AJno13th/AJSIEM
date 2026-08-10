#!/usr/bin/env bash
# Produce low / medium / high severity style events on Kali for alert testing.
set -euo pipefail

echo "[*] Emitting lab events (local syslog → forwarded to SIEM if configured)"

# LOW — informational / routine
logger -p auth.info -t sshd "Accepted publickey for kali from 192.168.1.20 port 51234 ssh2"
logger -p authpriv.info -t sudo "kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update"
logger -p user.notice -t ajsiem "LOW: routine package metadata refresh"

# MEDIUM — suspicious repetition / account activity
for i in 1 2 3 4 5; do
  logger -p auth.warning -t sshd "Failed password for invalid user admin from 203.0.113.${i} port 22 ssh2"
done
logger -p auth.notice -t useradd "new user: name=labattacker, UID=1005, GID=1005, home=/home/labattacker, shell=/bin/bash"
logger -p user.warning -t ajsiem "MEDIUM: repeated authentication failures and new local account"

# HIGH — critical signals
logger -p auth.crit -t sshd "Accepted password for root from 198.51.100.66 port 22 ssh2"
logger -p kern.warning -t kernel "possible SYN flood on eth0"
logger -p user.err -t nmap "Nmap scan report for 192.168.1.0/24 — host discovery + port scan"
logger -p auth.alert -t sudo "kali : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
logger -p user.crit -t ajsiem "HIGH: root login + scan activity + privilege escalation attempts"

echo "[+] Done. Check Graylog Search / Streams / Alerts within ~30s."

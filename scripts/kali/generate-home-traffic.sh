#!/usr/bin/env bash
# Emit structured HOME_NET flow logs for home-LAN traffic visibility in AJSIEM.
# Forwards via local syslog when rsyslog/Filebeat is configured to Graylog.
set -euo pipefail

echo "[*] Emitting home network traffic samples (HOME_NET flows → SIEM)"

emit() {
  # $1 message body
  logger -p local0.info -t homenet "$1"
  echo "    $1"
}

# Routine browsing / DNS from phones & laptops
emit "HOME_NET src=192.168.1.24 dst=8.8.8.8 proto=UDP sport=53122 dport=53 bytes=128 device=iphone-aj dns=dns.google dir=out"
emit "HOME_NET src=192.168.1.20 dst=142.250.190.14 proto=TCP sport=49811 dport=443 bytes=24576 device=laptop-aj dns=www.google.com dir=out"
emit "HOME_NET src=192.168.1.20 dst=1.1.1.1 proto=UDP sport=50112 dport=53 bytes=96 device=laptop-aj dns=one.one.one.one dir=out"
emit "HOME_NET src=192.168.1.80 dst=151.101.1.140 proto=TCP sport=44102 dport=443 bytes=81920 device=tablet-kids dns=www.reddit.com dir=out"

# Media streaming + NAS LAN transfer
emit "HOME_NET src=192.168.1.36 dst=23.246.0.1 proto=TCP sport=39001 dport=443 bytes=1850000 device=smart-tv dns=netflix.com dir=out"
emit "HOME_NET src=192.168.1.20 dst=192.168.1.42 proto=TCP sport=51200 dport=445 bytes=420000 device=laptop-aj dns=nas-home.lan dir=lan"

# IoT phone-home
emit "HOME_NET src=192.168.1.55 dst=52.94.236.248 proto=TCP sport=47011 dport=443 bytes=4096 device=iot-cam-porch dns=aws.amazon.com dir=out"
emit "HOME_NET src=192.168.1.55 dst=192.168.1.10 proto=UDP sport=5353 dport=53 bytes=180 device=iot-cam-porch dns=router.lan dir=lan"

# Suspicious lab / scan-style outbound (medium→high for dashboard + alerts)
emit "HOME_NET src=192.168.1.66 dst=198.51.100.66 proto=TCP sport=44444 dport=22 bytes=512 device=kali-lab dns=scan-target.lab dir=out"
emit "HOME_NET src=192.168.1.66 dst=203.0.113.50 proto=TCP sport=44445 dport=445 bytes=2048 device=kali-lab dns=smb-probe.lab dir=out"

logger -p user.notice -t ajsiem "LOW: home network flow sample batch ingested"
logger -p user.warning -t ajsiem "MEDIUM: unusual SMB/SSH egress from kali-lab on home LAN"

echo "[+] Done. Open the dashboard Home network traffic panel or Graylog stream AJSIEM Home Network."

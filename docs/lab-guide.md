# AJSIEM Lab Guide

Hands-on SIEM lab: **Kali Linux** ships logs to **Ubuntu Server** running **MongoDB**, **OpenSearch**, and **Graylog**.

## Live dashboard

```bash
./scripts/ubuntu/start-dashboard.sh
# http://127.0.0.1:8088
```

Uses Graylog when reachable; otherwise streams a demo auth severity feed. The **Home network traffic** panel stays empty until you run a **real LAN scan** (UI button or CLI). Set `AJSIEM_DEMO=always` only if you want a synthetic LAN for screenshots.

## Architecture

```text
┌─────────────────┐        syslog/GELF/beats         ┌──────────────────────────────┐
│   Kali Linux    │ ────────────────────────────────►│       Ubuntu Server           │
│  (attacker/lab) │   TCP 1514 / UDP 12201 / 5044    │  Graylog  ←→  OpenSearch     │
│  rsyslog/filebeat│                                 │       ↕                      │
└─────────────────┘                                  │     MongoDB                  │
                                                     │  UI :9000  Streams + Alerts  │
                                                     └──────────────────────────────┘
```

## VirtualBox networking

1. Create two VMs: Kali + Ubuntu Server (22.04+).
2. Set **both** NICs to **Bridged Adapter** (same physical network).
3. Confirm they can ping each other (`ip a` / `hostname -I`).

NAT alone will not let Kali reach Graylog on Ubuntu cleanly for this lab.

## Path A — Docker on Ubuntu (recommended)

On Ubuntu (with Docker Engine + Compose plugin):

```bash
git clone https://github.com/AJno13th/AJSIEM.git
cd AJSIEM
./scripts/ubuntu/generate-secrets.sh
# Edit .env → GRAYLOG_HTTP_EXTERNAL_URI=http://<ubuntu-ip>:9000/
./scripts/ubuntu/start-stack.sh
./scripts/ubuntu/bootstrap-graylog.sh
```

Open `http://<ubuntu-ip>:9000` (user `admin`, password from `.env`).

## Path B — Bare metal on Ubuntu

```bash
sudo ./scripts/ubuntu/install-baremetal.sh
```

Then create Syslog/GELF inputs in the Graylog UI (or adapt `bootstrap-graylog.sh` to the bare-metal URL).

## Configure Kali log shipping

```bash
# On Kali — replace with Ubuntu bridged IP
sudo ./scripts/kali/setup-log-forwarding.sh 192.168.1.50
# Optional richer shipping
sudo ./scripts/kali/setup-filebeat.sh 192.168.1.50
# Emit low/medium/high sample events
./scripts/kali/generate-lab-events.sh
# Real home LAN discovery (ARP + optional nmap + ss flows)
sudo ./scripts/kali/scan-home-network.sh --post http://192.168.1.50:8088
```

## Home network traffic (real scan)

AJSIEM discovers devices on the LAN the scanner host is attached to:

```bash
# From Ubuntu SIEM (bridged) or Kali
sudo ./scripts/ubuntu/scan-home-network.sh
# or click "Scan home network" on http://<ubuntu-ip>:8088
```

What it does:

1. Detects the private IPv4 subnet (or uses `--cidr` / `AJSIEM_SCAN_CIDR`)
2. Reads ARP / `ip neigh` neighbors
3. Optional `nmap -sn` ping sweep + top-ports probe
4. Samples established sockets via `ss` as live flows
5. Posts results to `POST /api/network/ingest` and emits `HOME_SCAN` / `HOST_DISC` / `HOME_NET` syslog for Graylog

Flow / host line formats:

```text
HOME_SCAN subnet=192.168.1.0/24 hosts=12 flows=8 methods=arp,nmap-ping,ss-flows
HOST_DISC ip=192.168.1.24 mac=aa:bb:cc:dd:ee:ff name=iphone role=host ports= - source=arp+nmap-ping
HOME_NET src=192.168.1.20 dst=8.8.8.8 proto=UDP sport=53122 dport=53 bytes=0 device=laptop-aj dns=- dir=out
```

- Bootstrap creates stream **AJSIEM Home Network** (matches `HOME_NET` / `HOST_DISC` / `HOME_SCAN`).
- Dashboard shows discovered hosts, open ports, talkers, and sampled flows.
- Demo mode no longer pretends to be your home network.

Authorized / lab use only — only scan networks you own.

## Filtering & presentation

- **OpenSearch** stores and indexes messages Graylog writes.
- **Graylog streams** `AJSIEM Low` / `AJSIEM Medium` / `AJSIEM High` / `AJSIEM Home Network` filter auth and home-LAN discovery/flow activity.
- Search, dashboards, and alerts are managed in the **Graylog web interface**; the AJSIEM live dashboard mirrors severity + home traffic.

## Alert tiers

| Severity | Examples |
|----------|----------|
| Low | Successful SSH, routine sudo |
| Medium | Failed password bursts, new local user |
| High | Root login, Nmap/SYN flood indicators, sudo failure storms |

Catalog: `configs/graylog/alerts/alert-catalog.json`

In Graylog: **Alerts → Event Definitions → Create**, copy query + condition from each catalog entry, attach a notification (email/HTTP as available in your edition).

## Validation checklist

- [ ] Kali ping Ubuntu
- [ ] Graylog UI loads
- [ ] Inputs show received messages after `generate-lab-events.sh`
- [ ] Messages appear in Low / Medium / High streams
- [ ] `scan-home-network.sh` (or dashboard **Scan**) lists real LAN hosts
- [ ] Dashboard `http://<ubuntu-ip>:8088` Home network panel shows `source=scan`
- [ ] At least one High event definition fires

## Safety

Lab-only defaults disable OpenSearch security and use plaintext admin passwords in `.env`. Do not expose this stack to the public internet without hardening (TLS, auth, firewall, non-default secrets).

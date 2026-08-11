# AJSIEM Lab Guide

Hands-on SIEM lab: **Kali Linux** ships logs to **Ubuntu Server** running **MongoDB**, **OpenSearch**, and **Graylog**.

## Live dashboard

```bash
./scripts/ubuntu/start-dashboard.sh
# http://127.0.0.1:8088
```

Uses Graylog when reachable; otherwise streams a demo low/medium/high feed **plus home network flows** so the UI stays live during lab setup.

The dashboard **Home network traffic** panel shows LAN devices, live `HOME_NET` flows, top talkers, and protocol mix.

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
# Emit structured home LAN flow logs (HOME_NET)
./scripts/kali/generate-home-traffic.sh
```

## Home network traffic

Flow lines use a parseable format so OpenSearch/Graylog and the live dashboard can render them:

```text
HOME_NET src=192.168.1.24 dst=8.8.8.8 proto=UDP sport=53122 dport=53 bytes=128 device=iphone-aj dns=dns.google dir=out
```

- Bootstrap creates stream **AJSIEM Home Network** (matches `HOME_NET`).
- Dashboard parses these messages into the Home network traffic table (devices, bytes, protocols).
- Alert catalog includes DNS baseline, SMB egress, and external SSH egress from the home LAN.

## Filtering & presentation

- **OpenSearch** stores and indexes messages Graylog writes.
- **Graylog streams** `AJSIEM Low` / `AJSIEM Medium` / `AJSIEM High` / `AJSIEM Home Network` filter auth and home-LAN flow activity by content rules.
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
- [ ] `generate-home-traffic.sh` populates stream **AJSIEM Home Network**
- [ ] Dashboard `http://<ubuntu-ip>:8088` shows the Home network traffic panel
- [ ] At least one High event definition fires

## Safety

Lab-only defaults disable OpenSearch security and use plaintext admin passwords in `.env`. Do not expose this stack to the public internet without hardening (TLS, auth, firewall, non-default secrets).

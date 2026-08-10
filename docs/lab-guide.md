# AJSIEM Lab Guide

Hands-on SIEM lab: **Kali Linux** ships logs to **Ubuntu Server** running **MongoDB**, **OpenSearch**, and **Graylog**.

## Live dashboard

```bash
./scripts/ubuntu/start-dashboard.sh
# http://127.0.0.1:8088
```

Uses Graylog when reachable; otherwise streams a demo low/medium/high feed so the UI stays live during lab setup.

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
```

## Filtering & presentation

- **OpenSearch** stores and indexes messages Graylog writes.
- **Graylog streams** `AJSIEM Low` / `AJSIEM Medium` / `AJSIEM High` filter network/auth activity by content rules.
- Search, dashboards, and alerts are managed in the **Graylog web interface**.

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
- [ ] At least one High event definition fires

## Safety

Lab-only defaults disable OpenSearch security and use plaintext admin passwords in `.env`. Do not expose this stack to the public internet without hardening (TLS, auth, firewall, non-default secrets).

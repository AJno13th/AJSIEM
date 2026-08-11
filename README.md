# AJSIEM

Security Information and Event Management lab built with **Ubuntu Server**, **OpenSearch**, **MongoDB**, **Graylog**, and **Kali Linux**.

This repository packages the end-to-end SIEM workflow described in portfolio form:

- Set up and implement a robust SIEM leveraging Ubuntu Server, OpenSearch, MongoDB, Graylog, and Kali Linux
- Orchestrate Kali Linux so it seamlessly transmits logs to the Ubuntu server for optimized collection
- Use OpenSearch to filter/index network and host telemetry, presented through the Graylog web UI
- Implement a comprehensive alert system stratified from **low → high** to identify and respond to specific network activity

## Stack

| Component | Role |
|-----------|------|
| **Kali Linux** | Log source / lab endpoint (rsyslog or Filebeat) |
| **Ubuntu Server** | SIEM host |
| **MongoDB** | Graylog metadata / buffer |
| **OpenSearch** | Indexed log storage & search backend |
| **Graylog** | Ingest, streams, search UI, alerts |

```mermaid
flowchart LR
  Kali[Kali Linux<br/>rsyslog / Filebeat] -->|Syslog 1514 / Beats 5044 / GELF 12201| Graylog
  Graylog --> MongoDB[(MongoDB)]
  Graylog --> OpenSearch[(OpenSearch)]
  Analyst[Analyst Browser] -->|:9000| Graylog
  Dashboard[AJSIEM Live Dashboard :8088] -->|API / SSE| Graylog
  Dashboard -->|scan + live events| Analyst
```

## Live dashboard

AJSIEM ships a live operations frontend that streams severity counts, **home network traffic**, collector health, and a scrolling event feed.

```bash
./scripts/ubuntu/start-dashboard.sh
# open http://127.0.0.1:8088
```

- **Real data only**: no synthetic demo events. The feed stays empty until Graylog has messages or you run a home-network scan.
- **Live mode**: when Graylog is reachable, the dashboard pulls recent messages (including `HOME_NET` / `HOST_DISC`) and flips the badge to `LIVE GRAYLOG`.
- **Home network panel**: click **Scan home network** (or run the CLI scanner) for real ARP/nmap/`ss` discovery on the LAN the SIEM host is bridged to.

## Quick start (Docker on Ubuntu)

```bash
./scripts/ubuntu/generate-secrets.sh
# set GRAYLOG_HTTP_EXTERNAL_URI=http://<ubuntu-bridged-ip>:9000/
./scripts/ubuntu/start-stack.sh
./scripts/ubuntu/bootstrap-graylog.sh
```

On Kali (same bridged network):

```bash
sudo ./scripts/kali/setup-log-forwarding.sh <ubuntu-ip>
./scripts/kali/generate-lab-events.sh
# Real home-LAN discovery → dashboard + syslog
sudo ./scripts/kali/scan-home-network.sh --post http://<ubuntu-ip>:8088
```

Or from the Ubuntu SIEM host / dashboard UI:

```bash
./scripts/ubuntu/start-dashboard.sh
# open http://127.0.0.1:8088 → Scan home network
sudo ./scripts/ubuntu/scan-home-network.sh
```

Full steps: [docs/lab-guide.md](docs/lab-guide.md)

## Repository layout

```text
AJSIEM/
├── dashboard/                  # Live ops UI (FastAPI + SSE)
├── docker-compose.yml          # MongoDB + OpenSearch + Graylog
├── configs/
│   ├── rsyslog/                # Kali → Ubuntu forwarder
│   ├── filebeat/               # Optional Beats shipper
│   └── graylog/alerts/         # Low / medium / high alert catalog
├── scripts/
│   ├── ubuntu/                 # Secrets, stack, dashboard, bootstrap, bare-metal
│   └── kali/                   # Log forwarding + sample event generator
└── docs/lab-guide.md
```

## Alerts (low → high)

| Level | Intent |
|-------|--------|
| **Low** | Baseline successful auth / routine sudo |
| **Medium** | Brute-force style failures, new accounts |
| **High** | Root login, scan indicators, priv-esc storms, SSH egress from home LAN |
| **Home Network** | DNS baseline, SMB/SSH egress from LAN devices (`HOME_NET` flows) |

See `configs/graylog/alerts/alert-catalog.json`.

## Requirements

- Host with **≥ 8 GB RAM** and **≥ 50 GB** disk for the VM lab
- VirtualBox (or similar) with **Bridged** networking on both VMs
- Docker Engine on Ubuntu for Path A, **or** bare-metal packages via `install-baremetal.sh`

## License

Lab material for authorized / educational use only. Harden before any production exposure.

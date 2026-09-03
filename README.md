#   BACKROOMS

```
  ____                       _     ____                           _
 | __ )  ___  __ _ _   _  __| |___| __ )  ___  _   _ _ __ ___   (_)___
 |  _ \ / _ \/ _` | | | |/ _` / __|  _ \ / _ \| | | | '_ ` _ \  | / __|
 | |_) |  __/ (_| | |_| | (_| \__ \ |_) | (_) | |_| | | | | | | | \__ \
 |____/ \___|\__,_|\__,_|\__,_|___/____/ \___/ \__,_|_| |_| |_|_|_|___/
```

**A red team network toolkit that turns your infrastructure into a trap.**

Backrooms deploys a labyrinth of decoy machines around your real network.
An attacker who connects gets lost in fake services, fake data, and fake
systems -- while every command they type, every credential they try, and
every lateral move they attempt is logged, correlated, and analyzed in
real time.

---

## Architecture

```
backrooms/
  cli.py                   Typer-based CLI with 20+ subcommands
  core/
    config.py              YAML config loading with Pydantic validation
    database.py            SQLite persistence for scans, hosts, ports, events
    models.py              Shared data models (Host, Port, ScanTarget, enums)
    exceptions.py          9-level exception hierarchy
  modules/
    scanner/               SYN, CONNECT, ACK, UDP port scanning
      host_discovery.py    ARP sweep + TCP ping with auto-fallback
      port_scan.py         Async scan engine with semaphore-based concurrency
      service_detect.py    Banner-based service identification
      os_fingerprint.py    TTL + window size passive OS detection
    mitm/
      core.py              ARP spoofing, TCP forwarding, credential capture
    smb/
      enumerator.py        SMB2 negotiation, NetBIOS NBSTAT lookups
    wireless/
      core.py              Monitor mode, AP beacon scanning, 802.11 deauth
  honeypot/
    manager.py             Docker container lifecycle for decoy deployment
    labyrinth.py           Session tracking, loop detection, hop budgeting
    ingest.py              Container log ingestion pipeline
    ids/
      logger.py            SQLite event persistence + command classification
      detector.py          Cross-decoy lateral movement correlation
  utils/
    network.py             IP resolution, interface discovery, checksums
    ui.py                  Rich console output (tables, banners, progress)
  tui/
    app.py                 Textual interactive dashboard
```

---

## Modules

### Network Scanner

Async-first scan engine with four techniques. Automatically falls back when
raw sockets are unavailable.

| Technique | Description |
|-----------|-------------|
| **SYN** | Half-open scan via Scapy (requires root) |
| **CONNECT** | Full TCP connect, no privileges needed |
| **ACK** | Firewall rule detection |
| **UDP** | ICMP unreachable-based state detection |

```bash
backrooms scan hosts 192.168.1.0/24
backrooms scan ports 10.0.0.5 -p 1-1024 --type connect
backrooms scan full 192.168.1.0/24 --ports "22,80,443,445,3389"
```

### MITM

ARP spoofing with real MAC resolution and proper ARP cache restoration on
shutdown. Transparent TCP forwarding with automatic credential extraction
from HTTP/FTP/SMTP/SSH traffic.

```bash
sudo backrooms mitm arp --target 10.0.0.5 --gateway 10.0.0.1
sudo backrooms mitm forward --target 10.0.0.5 --gateway 10.0.0.1 --ports 80,443
```

### SMB Enumeration

SMB2 negotiation with struct-based frame builder. NetBIOS name service
(NBSTAT) lookups for hostname and workgroup extraction. No heavy SMB client
dependencies.

```bash
backrooms smb enum 192.168.1.0/24
```

### Wireless

802.11 reconnaissance and attack helpers. Monitor mode activation, beacon
scanning, and deauthentication bursts. Degrades gracefully without
privileged hardware.

```bash
backrooms wireless interfaces
backrooms wireless monitor wlan0
backrooms wireless scan wlan0mon
backrooms wireless deauth --bssid AA:BB:CC:DD:EE:FF --count 10
```

### Honeypot Labyrinth

The core concept. Deploy isolated Docker containers running fake SSH, HTTP,
SMB, MySQL, FTP, Telnet services. Each decoy has fake users, fake hostnames,
and realistic service banners. When an attacker connects to one decoy, the
labyrinth tracker records the hop. Reaching multiple decoys triggers lateral
movement alerts.

```yaml
# config/honeypot.example.yaml
network: "172.28.0.0/16"
subnet: "172.28.0.0/24"
gateway: "172.28.0.1"

decoys:
  - name: dc01
    hostname: DC01-CORP
    services: [ssh, http, smb, rdp]
    fake_users:
      - username: admin
        password: admin123
      - username: backup_svc
        password: Backup#2024

  - name: db01
    hostname: db-primary
    services: [mysql, postgres, ssh]

labyrinth:
  max_hops: 5
  redirect_delay: 2.0

ids:
  enabled: true
  alert_on:
    - privilege_escalation
    - lateral_movement
    - credential_dumping
```

```bash
backrooms honeypot deploy --config config/honeypot.example.yaml
backrooms honeypot status
backrooms honeypot logs --follow
backrooms honeypot track --source-ip 10.0.0.99
```

### IDS

Cross-decoy correlation engine. A single source IP touching multiple decoys
is flagged as lateral movement. Commands are classified by risk level
(credential dumping, privilege escalation, enumeration).

---

## Installation

```bash
git clone https://github.com/s1d9e/Backrooms.git
cd Backrooms
pip install -e ".[dev]"
```

### Requirements

- Python 3.11+
- Docker (for honeypot deployment)
- Root privileges (for SYN scan, ARP spoofing, wireless monitor mode)

---

## Configuration

Default config location: `~/.config/backrooms/config.yaml`

```yaml
scan:
  threads: 100
  timeout: 1.0
  retries: 1
```

---

## Development

```bash
# Lint
ruff check .

# Type check
mypy backrooms/ --ignore-missing-imports

# Tests
pytest tests/ -v
```

Built with Ruff (linting), mypy (strict mode), and pytest.

---

## Tech Stack

| Component | Library |
|-----------|---------|
| CLI | Typer |
| Terminal UI | Rich |
| TUI Dashboard | Textual |
| Config / Models | Pydantic v2 |
| Packet Crafting | Scapy |
| Persistence | SQLite |
| Containers | Docker SDK |
| Logging | structlog |
| Network | netifaces |

---

## License

MIT -- see [LICENSE](LICENSE).

---

## About the author

Backrooms is designed, engineered, and maintained by **s1d9e**.

---

## Disclaimer

This tool is intended for authorized security assessments, educational
purposes, and CTF competitions. Unauthorized use against networks you do
not own or have permission to test is illegal. You are solely responsible
for how you use this software.

# Trap House: Multi-Layer Deception Honeypot

A deception honeypot system designed as a cybersecurity portfolio piece. It simulates a fake company network that draws attackers into an infinite maze of decoy credentials and services. All attacker behavior is logged, mapped to MITRE ATT&CK techniques, and visualized on a threat intelligence dashboard.

## Why This Project

Most student honeypot projects do one thing: deploy Cowrie, collect some logs, write a report. This project goes further. It builds a multi-layer deception environment that keeps attackers engaged for as long as possible while producing professional-grade threat intelligence.

### Differentiators

- **Custom deception middleware**: Not just deployed Cowrie. A purpose-built FastAPI fake corporate web app with 5 deception layers that route attackers in circles.
- **MITRE ATT&CK mapping**: Two-layer detection. Static event-type mapping (11 techniques across 15 event mappings) plus regex pattern matching (10 patterns) that catches behavioral indicators like credential dumping, system discovery, and account enumeration.
- **Attacker profiling with risk scoring**: Per-IP profiles tracking tools detected, MITRE techniques used, session count, and a weighted risk score.
- **Custom SOC dashboard**: Dark-themed security operations center interface with a Leaflet attack map, MITRE heatmap, session replay showing attacker journey through deception layers, and a filterable event timeline.
- **Sandboxed webshell**: File upload accepts webshells but executes against an in-memory fake filesystem. No real code execution, no subprocess, no eval. Every command is logged.
- **Legal by design**: Built for the Norwegian legal context. Detection and intelligence only. No hack-back, no offensive capabilities. See [LEGAL.md](LEGAL.md).

## Architecture

8 Docker containers across 2 isolated networks:

```
                        Internet
                           |
                    +------+------+
                    |             |
              trap-external       |
                    |             |
           +--------+--+--+------+--------+
           |           |  |              |
       endlessh    cowrie  deception-gw
       (tarpit)    (honeypot)  (FastAPI)
           |           |  |              |
           +-----+-----+--+--------------+
                 |
          trap-logs (bind mounts)
                 |
         +-------+--------+
         |               |
    log-shipper      mitre-mapper
         |               |
         v               v
    SQLite DB      techniques table
    events table   attackers table
         |
    +----+----+
    |         |
  frontend   grafana+loki
  (SOC UI)   (metrics)
```

### External Network (attacker-facing)
- **endlessh**: SSH tarpit. Accepts connections and drip-feeds a fake banner at 1 byte/second.
- **cowrie**: SSH/Telnet honeypot. Accepts credentials, provides fake shell, logs all interaction as JSON. Serves a custom honeyfs with decoy `.env` files containing credentials that work on the web app.
- **deception-gw**: FastAPI fake corporate web app ("NordTech Solutions"). 5-layer deception maze with login, admin panel, SQL injection, sandboxed webshell, and fake AWS keys.

### Internal Network (no external access)
- **log-shipper**: Reads JSONL logs from all honeypot services, normalizes to a shared event schema, writes to SQLite.
- **mitre-mapper**: Reads events from SQLite, maps to MITRE ATT&CK techniques using static and regex pattern matching, builds attacker profiles with risk scoring.
- **frontend**: Custom FastAPI SOC dashboard with Leaflet attack map, MITRE heatmap, session replay, and event timeline.
- **loki**: Grafana Loki log aggregation.
- **grafana**: Grafana dashboard for log-based metrics.

## The Deception Maze

Attackers follow a path that looks like real network compromise but leads in circles:

1. **SSH Entry (Cowrie)**: Attacker brute-forces SSH, gets in with weak credentials. Finds a fake filesystem with `/home/admin/.env` containing database and web app credentials.

2. **Web Login (deception-gw)**: Decoy credentials from the `.env` file work on the fake NordTech Solutions corporate portal. Progressive authentication delay slows brute force attempts (2^n seconds, capped at 30).

3. **Admin Panel and SQL Injection**: Dashboard leads to admin panel with user search. The search endpoint has an intentional (safe) SQL injection vulnerability. Injection returns 10,000 fake users with canarytoken-laced emails.

4. **Webshell Upload**: Admin panel accepts file uploads including `.php` webshells. The webshell "works" but executes against an in-memory fake filesystem. Commands like `whoami`, `uname -a`, `cat /etc/passwd` return believable fake output. No real execution.

5. **Fake AWS Keys and Maze Loop**: Admin config page shows fake AWS access keys. Admin backup page shows database credentials that lead back to the login page. The attacker goes in circles.

Every interaction at every layer is logged as JSONL, normalized to the shared event schema, and mapped to MITRE ATT&CK techniques.

## MITRE ATT&CK Coverage

### Static Event-Type Mapping (11 techniques, 15 event mappings)
| Technique | Name | Tactic |
|-----------|------|--------|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1078 | Valid Accounts | Defense Evasion |
| T1059 | Command and Scripting Interpreter | Execution |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1505.003 | Server Software Component: Web Shell | Persistence |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access |
| T1083 | File and Directory Discovery | Discovery |
| T1049 | System Network Connections Discovery | Discovery |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1021 | Remote Services | Lateral Movement |
| T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance |

### Regex Pattern Matching (10 patterns)
| Technique | Trigger |
|-----------|---------|
| T1110.004 | Credential stuffing tools (hydra, medusa, ncrack) |
| T1190 | Exploitation tools (sqlmap, nikto, nuclei, metasploit) |
| T1059.004 | Shell invocation (/bin/sh, powershell) |
| T1003.008 | Credential file access (cat /etc/passwd, /etc/shadow) |
| T1087 | Account discovery (whoami, id, net user) |
| T1082 | System info discovery (uname, hostname, arch) |
| T1083 | File discovery (ls, find, tree) |
| T1046 | Network scanning (nmap, masscan, netcat) |
| T1105 | Tool transfer (wget, curl, scp) |
| T1071.001 | HTTP C2 (curl/wget with http) |

## Tech Stack

- **Docker Compose**: 8-container orchestration, 2 isolated networks
- **Cowrie**: SSH/Telnet honeypot with custom honeyfs
- **Endlessh**: SSH tarpit
- **Python / FastAPI**: Deception middleware, log shipper, MITRE mapper, frontend API
- **SQLite**: Intel store (events, sessions, techniques, attackers)
- **Grafana + Loki**: Log aggregation and time-series metrics
- **Leaflet.js 1.9.4**: Attack map with CartoDB Dark Matter tiles
- **Vanilla JS**: No frontend framework, no build step
- **itsdangerous**: Signed session cookies for the deception maze
- **PyYAML**: MITRE technique configuration

## Project Structure

```
trap-house/
  docker-compose.yml          # Dev configuration (8 containers)
  docker-compose.prod.yml     # Production override (Hetzner)
  verify.sh                   # Phase 1 verification script
  Makefile                    # up, down, logs, test, clean
  .env.example                # Dev environment config
  .env.hetzner.example        # Production environment config
  CLAUDE.md                   # Project context for AI coding agents
  ARCHITECTURE.md             # System topology and data flow
  EVENT_SCHEMA.md             # Shared JSONL event schema
  LEGAL.md                    # Norwegian legal framework
  config/
    mitre-techniques.yaml     # MITRE ATT&CK technique mappings
    grafana/
      provisioning/           # Grafana datasource and dashboard provisioning
  deploy/
    harden.sh                 # Host hardening script (firewall, SSH, fail2ban)
    deploy.sh                 # Production deployment script
  docs/
    PHASE2_DESIGN.md          # Deception middleware design spec
    PHASE4_DESIGN.md          # Dashboard design spec
  services/
    cowrie/
      cowrie.cfg              # Cowrie configuration overrides
      honeyfs/home/admin/     # Decoy .env and README files
    deception-gw/
      main.py                 # FastAPI app with 14 routes
      config.py               # Decoy credentials, AWS keys, session config
      maze.py                 # Session management and progressive delay
      logger.py               # JSONL event logger with MITRE mapping
      fake_fs.py              # In-memory webshell sandbox
      templates/              # 8 Jinja2 templates
    log-shipper/
      shipper.py              # Log normalizer, SQLite writer, Endlessh poller
    mitre-mapper/
      mapper.py               # MITRE mapping service, attacker profiler
    frontend/
      app.py                  # FastAPI serving 10 API endpoints + dashboard
      templates/              # Dashboard HTML
      static/css/             # Dark SOC theme
      static/js/              # Attack map, heatmap, session replay, timeline
```

## Quick Start (Development)

```bash
# Clone and configure
git clone <repo-url> trap-house
cd trap-house
cp .env.example .env

# Start all 8 containers
make up

# Verify honeypot services are running
make test

# Access the SOC dashboard
open http://localhost:8001

# Access Grafana
open http://localhost:3000
```

## Production Deployment (Hetzner)

```bash
# 1. Provision a Hetzner VPS (Ubuntu 24.04, CX22 or larger)

# 2. SSH in and clone the repo
ssh root@your-vps-ip
apt-get update && apt-get install -y git
git clone https://github.com/sssafeman/trap-house /opt/trap-house

# 3. Run host hardening (moves SSH to port 65022, configures firewall, installs Docker)
cd /opt/trap-house
bash deploy/harden.sh your_username

# 4. Reconnect on the new SSH port
ssh -p 65022 your_username@your-vps-ip

# 5. Configure production environment
cp .env.hetzner.example .env.hetzner
# Edit .env.hetzner: set SESSION_SECRET and GRAFANA_ADMIN_PASSWORD
nano .env.hetzner

# 6. Deploy
bash deploy/deploy.sh

# 7. Access internal dashboards via SSH tunnel
ssh -p 65022 -L 8001:localhost:8001 -L 3000:localhost:3000 your_username@your-vps-ip
# Then open:
#   http://localhost:8001  (SOC Dashboard)
#   http://localhost:3000  (Grafana)
```

## Production Deployment (Oracle Cloud Free Tier)

Oracle Cloud offers a permanently free tier with ARM instances (Ampere A1, up to 24GB RAM). This is sufficient for the full 8-container stack.

### Oracle Cloud Setup

1. Sign up at cloud.oracle.com (requires credit card for verification, not charged)

2. Create a compute instance:
   - Shape: VM.Standard.A1.Flex (ARM, Ampere A1)
   - Image: Ubuntu 24.04 (Canonical)
   - OCPUs: 2, Memory: 8GB (within free tier limits)
   - Save your SSH private key

3. Open ports in Oracle's Security List (VCN > Security Lists):
   - Port 22: Endlessh tarpit
   - Port 2222: Cowrie SSH
   - Port 2223: Cowrie Telnet
   - Port 80: Deception-gw HTTP
   - Port 65022: Host SSH (admin access)
   Oracle's cloud firewall blocks all ports by default. UFW on the host is not enough.

4. SSH into the instance (Oracle uses `ubuntu` as the default user):
```bash
ssh ubuntu@your-oracle-ip
```

5. Clone and harden:
```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/sssafeman/trap-house /opt/trap-house
cd /opt/trap-house
sudo bash deploy/harden.sh ubuntu
```

6. Reconnect on the new SSH port:
```bash
ssh -p 65022 ubuntu@your-oracle-ip
```

7. Configure and deploy:
```bash
cd /opt/trap-house
cp .env.hetzner.example .env.hetzner
# Edit .env.hetzner: set SESSION_SECRET and GRAFANA_ADMIN_PASSWORD
# Generate SESSION_SECRET: python3 -c "import secrets; print(secrets.token_hex(32))"
nano .env.hetzner
bash deploy/deploy.sh
```

8. Access dashboards via SSH tunnel:
```bash
ssh -p 65022 -L 8001:localhost:8001 -L 3000:localhost:3000 ubuntu@your-oracle-ip
# Then open:
#   http://localhost:8001  (SOC Dashboard)
#   http://localhost:3000  (Grafana)
```

### Oracle Cloud Notes
- All Docker images in this project support ARM64 (Ampere A1). No architecture changes needed.
- Oracle may reclaim idle free tier instances. A honeypot receiving traffic should stay active.
- Bandwidth limit: 10 TB/month outbound. Honeypot log traffic will not approach this.
- If Oracle rejects your signup, try a different browser or card. The process is known to be finicky.

### Production Port Mapping

| Port | Service | Exposure |
|------|---------|----------|
| 22 | Endlessh tarpit | External |
| 2222 | Cowrie SSH honeypot | External |
| 2223 | Cowrie Telnet honeypot | External |
| 80 | Deception-gw (fake web app) | External |
| 65022 | Host SSH | External (moved from 22) |
| 3000 | Grafana | Internal (SSH tunnel) |
| 8001 | SOC Dashboard | Internal (SSH tunnel) |

## Security Posture

### Container Security
- All containers drop ALL Linux capabilities
- `no-new-privileges` on every container
- Cowrie runs as UID 999 (non-root)
- Deception-gw, frontend, log-shipper, mitre-mapper run as UID 1000 (non-root)
- Internal network has `internal: true` (no external internet access)
- No subprocess, eval, exec, or os.system in any custom code
- Webshell sandbox is pure in-memory dict lookup, no real execution

### Host Security (Production)
- UFW firewall: only honeypot ports and host SSH open
- SSH moved to port 65022, root login disabled, password auth disabled
- fail2ban on SSH (3 retries, 2 hour ban)
- Unattended security upgrades enabled
- Grafana and frontend accessible only via SSH tunnel

### Legal
Norway. Detection and intelligence only. No hack-back, no offensive capabilities. See [LEGAL.md](LEGAL.md).

## Building This Project

This project was built in 5 phases, each producing a deployable artifact:

1. **Phase 1**: Docker Compose skeleton, Cowrie, Endlessh, log-shipper to SQLite
2. **Phase 2**: Deception middleware (FastAPI 5-layer maze, sandboxed webshell, SQL injection)
3. **Phase 3**: MITRE mapper with regex patterns and attacker profiling
4. **Phase 4**: SOC dashboard with Leaflet map, MITRE heatmap, session replay, timeline, Grafana/Loki
5. **Phase 5**: Hetzner deployment config, host hardening, portfolio writeup

Each phase was verified before moving to the next. The verify.sh script runs 8 automated checks against the running stack.

## License

MIT. See [LEGAL.md](LEGAL.md) for usage guidelines and legal framework.
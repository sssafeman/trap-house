# Trap House: Architecture

## System Topology

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
           |    +------+  |              |
           |    |         |              |
           +----+---------+              |
                |                        |
         trap-logs (shared volume)       |
                |                        |
         +------+--------+               |
         |               |               |
    log-shipper      (JSON files)        |
         |                               |
    +----+----+----+                      |
    |    |    |                          |
    v    v    v                          |
  mitre  loki  intel-store <-------------+
  mapper       (SQLite)
    |           |
    v           v
  grafana    frontend
  (dashboard) (FastAPI + Leaflet)
```

## Networks

### trap-external
Attacker-facing. Services here accept inbound connections from the internet.
Containers: endlessh, cowrie, deception-gw
No internal flag. These are the only services reachable from outside.

### trap-internal
Backend. Services here cannot reach the internet.
Containers: log-shipper, mitre-mapper, intel-store, loki, grafana, frontend
Set internal: true in docker-compose.yml.

### trap-logs (volume, not a network)
Shared Docker volume mounted at /var/log/trap-house in each honeypot container.
All honeypot services write JSON log files here. log-shipper reads from this volume.

## Container Specifications

### endlessh
Image: ghcr.io/linuxserver/endlessh (pinned by digest)
Ports: ${ENDLESSH_PORT}:2222 (container listens on 2222 internally)
Network: trap-external
Capabilities: drop ALL
Read-only rootfs: yes (tmpfs for /tmp and /config)
Purpose: Accept SSH connections and drip-feed banner at 1 byte/second. Wastes attacker time.

### cowrie
Image: cowrie/cowrie:latest (pin to specific tag in Phase 1)
Ports: ${COWRIE_SSH_PORT}:2222, ${COWRIE_TELNET_PORT}:2223
Network: trap-external + trap-logs volume
Capabilities: drop ALL
Read-only rootfs: no (Cowrie needs writable filesystem for fake shell, but mount specific volumes)
Purpose: SSH/Telnet honeypot. Accepts credentials, provides fake shell, logs all interaction as JSON.

### deception-gw
Image: custom build (services/deception-gw/Dockerfile)
Ports: ${DECEPTION_PORT}:8000
Network: trap-external + trap-logs volume
Capabilities: drop ALL
Read-only rootfs: yes (tmpfs for /tmp, volume for /app/data)
Purpose: FastAPI fake corporate web app. Serves fake login pages, fake admin panel, fake API endpoints. Plants decoy credentials. Maze logic routes attackers in circles.

### log-shipper
Image: custom build (services/log-shipper/Dockerfile)
Network: trap-internal + trap-logs volume
Capabilities: drop ALL
Read-only rootfs: yes (except for small state dir)
Purpose: Reads JSON logs from trap-logs volume, normalizes to shared event schema, writes to intel-store and forwards to Loki.

### mitre-mapper
Image: custom build (services/mitre-mapper/Dockerfile)
Network: trap-internal
Capabilities: drop ALL
Read-only rootfs: yes
Purpose: Loads MITRE ATT&CK technique YAML, matches events to T-codes via regex/heuristics, writes mappings to intel-store.

### intel-store
Image: python:3.12-slim (or sqlite3 CLI image)
Network: trap-internal
Capabilities: drop ALL
Read-only rootfs: no (needs writable data volume for SQLite)
Purpose: SQLite database storing sessions, events, techniques, attackers. Queryable by frontend and Grafana.

### loki
Image: grafana/loki:3.0.0 (pin by digest)
Network: trap-internal
Capabilities: drop ALL
Read-only rootfs: no (needs writable data volume)
Purpose: Log aggregation. Receives logs from log-shipper. Queried by Grafana.

### grafana
Image: grafana/grafana:11.0.0 (pin by digest)
Ports: ${GRAFANA_PORT}:3000 (dev only, SSH tunnel in prod)
Network: trap-internal
Capabilities: drop ALL
Read-only rootfs: no (needs writable data volume for dashboards)
Purpose: Dashboard. Visualizes metrics, attack timelines, attacker statistics.

### frontend
Image: custom build (services/frontend/Dockerfile)
Ports: ${FRONTEND_PORT}:8001 (dev only, SSH tunnel in prod)
Network: trap-internal
Capabilities: drop ALL
Read-only rootfs: yes (tmpfs for /tmp)
Purpose: Custom FastAPI frontend serving HTML/JS dashboard. Attack map (Leaflet), MITRE heatmap, session replay, attack timeline.

## Port Mapping

| Service    | Container Port | Dev Host Port | Prod Host Port |
|------------|----------------|---------------|-----------------|
| endlessh   | 2222           | 22222         | 22              |
| cowrie SSH | 2222           | 2222          | 2222            |
| cowrie Telnet | 2223        | 2223          | 2223            |
| deception-gw | 8000         | 8080          | 80              |
| grafana    | 3000           | 3000          | (SSH tunnel)    |
| frontend   | 8001           | 8001          | (SSH tunnel)    |

## Data Flow

1. Attacker connects to endlessh, cowrie, or deception-gw
2. Honeypot service logs interaction as JSON to /var/log/trap-house/
3. log-shipper reads JSON logs, normalizes to event schema, writes to:
   a. intel-store (SQLite: sessions, events, attackers)
   b. Loki (via HTTP push)
4. mitre-mapper reads new events from intel-store, matches to ATT&CK techniques, writes mappings back
5. grafana queries Loki for log-based metrics
6. frontend queries intel-store for attack map, MITRE heatmap, session replay, timeline

## Deception Layers (Phase 2)

### Layer 1: SSH Entry (Cowrie)
Attacker brute-forces SSH, gets in with weak credentials. Finds a fake filesystem with decoy .env files, config files, and SSH keys.

### Layer 2: Web App (deception-gw)
Decoy credentials from Layer 1 work on the fake corporate web app. Attacker logs in, finds admin panel with fake user database.

### Layer 3: Database (deception-gw)
Admin panel has SQL injection vulnerability (intentional). Attacker injects, gets "database dump" of 10,000 fake users with canarytoken-laced emails.

### Layer 4: Webshell (deception-gw)
Admin panel has file upload. Attacker uploads webshell. Webshell "works" but operates on a fake filesystem. Every command logged.

### Layer 5: API Keys (deception-gw)
Fake AWS keys planted in .env. When used (outside the honeypot), canarytokens.org triggers an alert. This is the only outbound connection and is toggleable.

## MITRE ATT&CK Mapping Approach

Static YAML file (config/mitre-techniques.yaml) maps event patterns to T-codes:
- SSH brute force -> T1110 (Brute Force)
- Credential dumping from files -> T1003 (OS Credential Dumping)
- SQL injection -> T1190 (Exploit Public-Facing Application)
- Webshell deployment -> T1505.003 (Server Software Component: Web Shell)
- Data exfiltration attempt -> T1041 (Exfiltration Over C2 Channel)

Matching is regex/heuristic based. No ML. No admin UI for mapping management.
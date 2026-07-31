# Trap House Index

Multi-layer deception honeypot system. Cybersecurity portfolio piece. 9 Docker containers across 2 networks. All phases complete. Final live collection completed on a Hetzner VPS, which is now powered off.

## Directory Map
- **services/**: Docker Compose service definitions and app code.
  - cowrie/: SSH/Telnet honeypot (ports 2222/2223)
  - endlessh/: SSH tarpit (port 22222)
  - deception-gw/: FastAPI fake corporate web app
  - log-shipper/: Normalizes honeypot logs to shared JSON schema
  - mitre-mapper/: Maps events to MITRE ATT&CK T-codes
  - intel-store/: SQLite store (sessions, events, techniques, attackers)
  - grafana/: Dashboard provisioning
  - frontend/: Custom SOC dashboard (Leaflet.js attack map, MITRE heatmap)
- **config/grafana/**: Grafana dashboard JSON configs.
- **data/**: Runtime data (gitignored). db/ (SQLite), logs/, loki/, grafana/.
- **scripts/**: Operational scripts. vps/ (VPS deployment helpers). digest.sh (daily digest generator).
- **digests/**: Generated daily digests.
- **evidence/**: Captured attacker artifacts.
- **animations/**: Dashboard animation assets.
- **deploy/**: Production deployment config (Hetzner).
- **docs/**: Documentation. img/ (screenshots for writeup).

## Key Entry Points
- docker compose up -d: Start all services
- docker compose down: Stop all services
- scripts/digest.sh: Generate daily honeypot digest (SSHes to VPS)
- CLAUDE.md: Full architecture and constraints

## Data Flow
attacker -> honeypot service -> JSON log -> log-shipper -> mitre-mapper + loki -> intel-store -> grafana + frontend

## Networks
- External (attacker-facing): endlessh, cowrie, deception-gw
- Internal (no external access): socket-proxy, log-shipper, mitre-mapper, loki, grafana, frontend
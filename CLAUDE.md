# Trap House: Multi-Layer Deception Honeypot

## What This Is
A deception honeypot system designed as a cybersecurity portfolio piece. It simulates a fake company network that draws attackers into an infinite maze of decoy credentials and services. All attacker behavior is logged, mapped to MITRE ATT&CK techniques, and visualized on a threat intelligence dashboard.

## Legal Posture
Norway. Detection and intelligence only. No hack-back, no offensive capabilities, no malware deployment. See LEGAL.md for full details. "Active antagonism" means defensive deception, detection, and delay. It does NOT mean attacking the attacker.

## Architecture Overview
8 containers across 2 Docker networks:

External (attacker-facing):
- endlessh: SSH tarpit (port 22 in prod, 22222 in dev)
- cowrie: SSH/Telnet honeypot (ports 2222/2223)
- deception-gw: FastAPI fake corporate web app (port 80/443 in prod, 8080 in dev)

Internal (no external access, internal: true):
- log-shipper: normalizes honeypot logs to shared JSON schema
- mitre-mapper: maps events to ATT&CK T-codes
- intel-store: SQLite database (sessions, events, techniques, attackers)
- loki: log aggregation
- grafana: dashboard (internal only, accessed via SSH tunnel)

Data flow: attacker -> honeypot service -> JSON log -> log-shipper -> mitre-mapper + loki -> intel-store -> grafana + frontend

## Tech Stack
- Docker Compose orchestration
- Cowrie (SSH/Telnet honeypot, not self-built)
- Endlessh (SSH tarpit)
- Python/FastAPI (deception middleware, log shipper, MITRE mapper, frontend)
- SQLite (intel store)
- Grafana + Loki (dashboard and log aggregation)
- Leaflet.js (attack map, not D3)
- Canarytokens.org (optional, toggleable)

## Phased Build Plan
Phase 1: Docker Compose skeleton + Cowrie + Endlessh + baseline JSON logging
Phase 2: Deception middleware (FastAPI fake corporate app, maze, canarytokens, sandboxed webshell)
Phase 3: Intel store + MITRE mapper + attacker fingerprinting
Phase 4: Dashboard (Grafana metrics + custom FastAPI frontend with Leaflet map, MITRE heatmap, session replay)
Phase 5: Hetzner deployment config + host hardening + portfolio writeup

Each phase produces a deployable artifact. Do not skip ahead.

## Event Schema
All services log to the shared schema defined in EVENT_SCHEMA.md. Read it before writing any logging code.

## Security Constraints (non-negotiable)
- No container runs as root unless absolutely necessary
- Cowrie has no outbound internet except to canarytokens (toggleable)
- Internal network has internal: true (no external access)
- Use read_only: true on container rootfs where possible
- Drop all capabilities. No NET_ADMIN, no SYS_ADMIN
- Pin all Docker image versions by digest. Never use :latest
- Log rotation and retention policy from day 1
- .gitignore excludes data/, logs/, db/, secrets

## Code Style
- No em dashes or double hyphens in any output. Use periods, commas, colons.
- Python: type hints on all public functions, 4-space indent
- YAML: 2-space indent
- Comments and docs in English
- American English spelling

## Key Commands
- `make up` or `docker compose up -d` (start all services)
- `make down` or `docker compose down` (stop all services)
- `make test` or `./verify.sh` (run verification script)
- `make logs` or `docker compose logs -f` (tail all logs)

## Environment
Local dev uses high ports to avoid conflicts with host SSH (port 22) and Tailscale (port 443).
Production (Hetzner) uses real ports. See .env.example for details.

## Current Phase: Phase 2 (Deception Middleware)
Read docs/PHASE2_DESIGN.md for the full spec. Key non-negotiables:
- No real exec in webshell (no subprocess, eval, exec, os.system, __import__)
- No LLM, no WebSocket, no real database
- Canarytokens disabled by default (ENABLE_CANARYTOKENS=false)
- JSONL logging to /var/log/trap-house/deception-gw.json per EVENT_SCHEMA.md
- Signed session cookies (itsdangerous)
- In-memory fake filesystem only
- Runs as non-root (UID 1000), cap_drop ALL, no-new-privileges
- No outbound network except optional canarytokens webhook
# Trap House: Architecture

## System Topology

Nine containers across two Docker networks. The intel store is a SQLite file on
a bind mount (not a container); the log-shipper, mitre-mapper, and frontend all
open it directly.

```
                        Internet
                           |
                    trap-external (bridge)
                           |
        +----------+-------+--------+-------------+
        |          |                |             |
    endlessh    cowrie         deception-gw    (frontend/grafana
    (tarpit)   (honeypot)       (FastAPI)       host ports bound
        |          |                |            to 127.0.0.1)
        |          |  JSON logs     |
        +----------+----------------+
                   |
          data/logs, data/db (bind mounts on the host)
                   |
    trap-internal (bridge, internal: true)
                   |
   +-----------+---+------------+-----------+---------+
   |           |                |           |         |
 socket-    log-shipper     mitre-mapper  loki     grafana
 proxy         |                |           ^         ^
 (docker    writes           reads/writes   |         |
  API)      SQLite +          SQLite         +---------+
   ^         Loki              |          frontend reads SQLite (ro)
   |          |                |          and serves the SOC dashboard
 endlessh    (log-shipper reads endlessh logs
 logs         through the socket-proxy, not the raw socket)
```

## Networks

### trap-external
Attacker-facing bridge. Services here accept inbound connections from the
internet. Containers: endlessh, cowrie, deception-gw. The frontend and grafana
also attach here only so their host ports (bound to 127.0.0.1) work; they expose
nothing to the internet.

### trap-internal
Backend bridge with `internal: true`, so these containers cannot reach the
internet. Containers: socket-proxy, log-shipper, mitre-mapper, loki, grafana,
frontend.

### Shared data (bind mounts, not a network)
- `data/logs/cowrie`, `data/logs/deception-gw`: honeypot JSONL logs. Written by
  the honeypots, read by log-shipper.
- `data/db`: the SQLite intel store (`trap-house.db`). Written by log-shipper and
  mitre-mapper, read (read-only) by the frontend.

## Container Specifications

All images are pinned by sha256 digest. Every service drops all capabilities,
sets `no-new-privileges`, has memory/PID/CPU ceilings, and rotates its
json-file logs.

### endlessh
- Image: `lscr.io/linuxserver/endlessh` (digest-pinned)
- Host port: `${ENDLESSH_PORT}` -> 2222 (22222 in dev and prod)
- Network: trap-external
- Read-only rootfs: no (s6-overlay incompatible; hardened via cap_drop + tmpfs)
- Purpose: accept SSH connections and drip-feed a banner at ~1 byte/second.

### cowrie
- Image: `cowrie/cowrie:sha-a2887ca` (digest-pinned)
- Host ports: `${COWRIE_SSH_PORT}` -> 2222, `${COWRIE_TELNET_PORT}` -> 2223
- Network: trap-external
- Read-only rootfs: no (needs a writable var volume for the emulated shell)
- Purpose: SSH/Telnet honeypot. Curated userdb, custom honeyfs, hostname
  corp-webapp-01, modern Ubuntu banner and uname. Logs JSON to the bind mount.

### deception-gw
- Image: custom build (`services/deception-gw/Dockerfile`)
- Host port: `${DECEPTION_PORT}` -> 8000 (8080 dev, 80 prod)
- Network: trap-external
- Read-only rootfs: yes (tmpfs for /tmp)
- Purpose: FastAPI fake corporate web app with the 5-layer deception maze.

### socket-proxy
- Image: `tecnativa/docker-socket-proxy:0.3.0` (digest-pinned)
- Network: trap-internal
- Read-only rootfs: no
- Purpose: scoped, read-only Docker API gateway (containers section only, writes
  denied). Lets log-shipper read endlessh container logs without mounting the
  raw Docker socket, which would otherwise be a direct path to host root.

### log-shipper
- Image: custom build (`services/log-shipper/Dockerfile`)
- Network: trap-internal
- Read-only rootfs: yes (tmpfs for /tmp)
- Purpose: read Cowrie and deception-gw JSONL and endlessh logs (via the
  socket-proxy), normalize to the shared event schema, write to SQLite, push to
  Loki.

### mitre-mapper
- Image: custom build (`services/mitre-mapper/Dockerfile`)
- Network: trap-internal
- Read-only rootfs: yes (tmpfs for /tmp)
- Purpose: load the MITRE technique YAML, map events via static and regex
  matching, track processed events, and build attacker risk profiles.

### loki
- Image: `grafana/loki:3.4.2` (digest-pinned)
- Network: trap-internal
- Read-only rootfs: no (writable data volume)
- Purpose: log aggregation. Receives pushes from log-shipper, queried by Grafana.

### grafana
- Image: `grafana/grafana:11.5.2` (digest-pinned)
- Host port: `${GRAFANA_PORT}` -> 3000, bound to 127.0.0.1 (SSH tunnel)
- Networks: trap-internal, trap-external (localhost host port only)
- Read-only rootfs: no (writable data volume)
- Purpose: metrics dashboard over Loki. Anonymous access disabled in prod.

### frontend
- Image: custom build (`services/frontend/Dockerfile`)
- Host port: `${FRONTEND_PORT}` -> 8001, bound to 127.0.0.1 (SSH tunnel)
- Networks: trap-external (localhost host port), trap-internal
- Read-only rootfs: yes (tmpfs for /tmp)
- Purpose: custom FastAPI SOC dashboard. Reads the SQLite store read-only and
  serves the Leaflet attack map, MITRE heatmap, session replay, and timeline.

## Port Mapping

| Service       | Container Port | Dev Host Port | Prod Host Port     |
|---------------|----------------|---------------|--------------------|
| host SSH      | n/a            | (your box)    | 22                 |
| endlessh      | 2222           | 22222         | 22222              |
| cowrie SSH    | 2222           | 2222          | 2222               |
| cowrie Telnet | 2223           | 2223          | 2223               |
| deception-gw  | 8000           | 8080          | 80                 |
| grafana       | 3000           | 127.0.0.1:3000 | 127.0.0.1 (tunnel) |
| frontend      | 8001           | 127.0.0.1:8001 | 127.0.0.1 (tunnel) |

## Data Flow

1. Attacker connects to endlessh, cowrie, or deception-gw.
2. The honeypot logs the interaction as JSON (to the bind mount, or to container
   stdout for endlessh).
3. log-shipper reads those logs (endlessh via the socket-proxy), normalizes to
   the event schema, writes to SQLite, and pushes to Loki.
4. mitre-mapper reads unprocessed events, maps them to ATT&CK techniques, marks
   them processed, and updates attacker profiles.
5. grafana queries Loki for log-based metrics.
6. frontend queries SQLite for the attack map, heatmap, session replay, timeline.

## MITRE ATT&CK Mapping Approach

`config/mitre-techniques.yaml` drives two matchers in mitre-mapper:
- Static event-type mapping (e.g. SSH brute force -> T1110.001, SQL injection ->
  T1190, webshell -> T1505.003, valid accounts -> T1078).
- Regex/heuristic pattern matching over event details (e.g. credential file
  access -> T1003.008, account discovery -> T1087, tool transfer -> T1105).

Matching is deterministic (no ML). Events that match no technique are still
recorded as processed so the mapper never re-scans them.

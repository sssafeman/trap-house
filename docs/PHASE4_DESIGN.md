# Trap House Phase 4: Threat Intelligence Dashboard Design

## Overview
Two-component dashboard: Grafana + Loki for log metrics, custom FastAPI frontend for the SOC visualization layer. The frontend is the portfolio showpiece.

## Component 1: Grafana + Loki
- Loki receives logs from log-shipper (Phase 4 upgrade: add Loki push to shipper)
- Grafana dashboards for time-series metrics:
  - Events per minute (line chart)
  - Event type distribution (pie chart)
  - Top attacker IPs (bar gauge)
  - MITRE technique distribution (bar chart)
- Accessed via SSH tunnel only (port 3000, no external exposure)
- Provisioned dashboards via JSON config, not manual setup

## Component 2: Custom Frontend (services/frontend/)

### Visual Design
- Dark SOC theme: background #0a0e14, panels #111820, accent #00d4ff (cyan), danger #ff4444, text #c5cdd6
- Monospace font for data, sans-serif for labels
- Grid layout: top row (stats summary), middle (map + heatmap), bottom (timeline + session replay)
- Auto-refresh every 10 seconds via JavaScript polling

### Frontend File Structure
```
services/frontend/
  Dockerfile
  requirements.txt
  app.py          (FastAPI app, serves API + static files)
  templates/
    base.html     (layout, nav, auto-refresh JS)
    dashboard.html (main dashboard page)
  static/
    css/
      style.css    (dark SOC theme)
    js/
      dashboard.js (main dashboard logic)
      attack-map.js (Leaflet map)
      mitre-heatmap.js (MITRE grid)
      session-replay.js (session timeline)
      timeline.js (event timeline with filtering)
```

### API Endpoints (FastAPI, querying SQLite)

| Method | Path | Query | Returns |
|--------|------|-------|---------|
| GET | /api/stats | SELECT count(*) events, count(DISTINCT source_ip) attackers, count(DISTINCT session_id) sessions, count(DISTINCT technique_id) techniques FROM events LEFT JOIN techniques | {events, attackers, sessions, techniques} |
| GET | /api/attackers | SELECT source_ip, event_count, session_count, risk_score, tools_detected, mitre_techniques, top_username, last_seen FROM attackers ORDER BY risk_score DESC LIMIT 100 | [{source_ip, event_count, ...}] |
| GET | /api/events | SELECT event_id, timestamp, source_service, source_ip, event_type, mitre_technique, command, username FROM events ORDER BY timestamp DESC LIMIT ?offset= | [{event_id, timestamp, ...}] |
| GET | /api/events/filter | WHERE source_service=? AND event_type=? AND source_ip=? | filtered events |
| GET | /api/techniques | SELECT technique_id, name, tactic, count(*) as count FROM techniques GROUP BY technique_id ORDER BY count DESC | [{technique_id, name, tactic, count}] |
| GET | /api/sessions | SELECT session_id, source_ip, source_service, start_time, end_time, event_count, mitre_techniques, layers_reached FROM sessions ORDER BY start_time DESC LIMIT 50 | [{session_id, ...}] |
| GET | /api/sessions/{id}/events | SELECT event_id, timestamp, event_type, source_service, command, username, mitre_technique FROM events WHERE session_id=? ORDER BY timestamp | [{event_id, ...}] |
| GET | /api/attack-map | SELECT source_ip, count(*) as attacks FROM events WHERE source_ip != '' GROUP BY source_ip ORDER BY attacks DESC LIMIT 100 | [{source_ip, attacks}] |
| GET | /api/timeline | SELECT timestamp, event_type, source_service, source_ip FROM events ORDER BY timestamp DESC LIMIT 200 | [{timestamp, event_type, ...}] |
| GET | /health | n/a | {status: ok} |

### Attack Map (Leaflet.js)
- Leaflet with dark tile layer (CartoDB Dark Matter)
- Markers sized by attack count from that IP
- Popup shows IP, event count, top techniques, risk score
- Color: green (low risk < 15), yellow (medium < 30), red (high >= 30)
- Since IPs are internal Docker IPs in dev, markers will cluster around localhost. In production with real attacker IPs, the map shows global attack origins. Add a note in the UI: "Geo locations based on source IP. Dev mode shows internal Docker IPs."
- Use a free IP geolocation API (ip-api.com) for lat/long lookup, cached server-side

### MITRE Heatmap
- Grid layout: rows are tactics (reconnaissance, initial-access, execution, persistence, credential-access, discovery, command-and-control, lateral-movement, defense-evasion)
- Columns are techniques (T-codes)
- Cell color intensity = frequency (darker = more events)
- Cell shows technique ID and count on hover
- Click a cell to filter timeline to that technique

### Session Replay
- Step-by-step view of a selected session
- Shows: timestamp, event_type, source_service, command/username, MITRE technique
- Visual progression through deception layers: SSH -> Web Login -> Dashboard -> SQL Injection -> Webshell -> Config
- Each step is a card in a vertical timeline
- Color-coded by layer: blue (SSH), green (web), orange (SQLi), red (webshell), purple (config)

### Attack Timeline
- Horizontal scrolling timeline of recent events
- Each event is a colored dot: blue (cowrie), cyan (deception-gw), gray (endlessh)
- Hover shows event details
- Filter bar: by service, event type, source IP
- Auto-refresh adds new events to the right

### JavaScript Libraries
- Leaflet 1.9.4 (map, from CDN)
- No framework. Vanilla JS with fetch() for API calls.
- No build step needed.

### CSS Approach
- CSS Grid for layout
- CSS custom properties for theme colors
- No CSS framework. Hand-written, minimal.
- Responsive: works on desktop, degrades gracefully on mobile

## Grafana + Loki Integration

### Loki
- Image: grafana/loki:3.4.2 (pin by tag)
- Port: 3100 (internal only)
- Receives log pushes from log-shipper
- Config: /etc/loki/local-config.yaml (minimal single-instance)

### Grafana
- Image: grafana/grafana:11.5.2 (pin by tag)
- Port: 3000 (dev only, SSH tunnel in prod)
- Data source: Loki (http://loki:3100)
- Pre-provisioned dashboard via provisioning config

### Log Shipper Upgrade
Add Loki push to the log-shipper: after writing to SQLite, also push to Loki via HTTP.
Loki push API: POST http://loki:3100/loki/api/v1/push
Format: {streams: [{stream: {service: "cowrie"}, values: [[timestamp_ns, log_line]]}]}

## Security
- Frontend on trap-internal network only (no external access)
- Grafana on trap-internal only (SSH tunnel in production)
- No CORS needed (frontend and API served from same FastAPI app)
- All read-only queries, no write operations in the frontend API
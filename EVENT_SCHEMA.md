# Trap House: Event Schema

All honeypot services and the log-shipper use this shared JSON schema. Every log entry is a single JSON object, one per line (JSONL format).

## Base Event

```json
{
  "timestamp": "2026-06-29T12:00:00.000Z",
  "event_id": "uuid-v4",
  "source_service": "cowrie|endlessh|deception-gw",
  "source_ip": "203.0.113.45",
  "source_port": 54321,
  "dest_port": 2222,
  "event_type": "auth_attempt",
  "session_id": "uuid-v4",
  "attacker_fingerprint": {
    "user_agent": "curl/8.0.1",
    "ssh_client": "SSH-2.0-libssh-0.9.0",
    "tool": "hydra|nmap|sqlmap|manual|unknown"
  },
  "mitre_technique": "T1110.001",
  "mitre_tactic": "credential-access",
  "details": {},
  "raw_data": {}
}
```

### Stored columns

The log-shipper writes each event to the `events` table with these additional
columns pulled out of the raw event for easy querying: `cowrie_session`,
`protocol` (`ssh` / `http`), `username`, and `command`.

### Event types

The canonical set below is what the services emit and the dashboard reasons
about. Cowrie produces additional pass-through event types (for example
`session_connect`, `session_disconnect`, `client_version`, `client_kex`,
`command_failed`, `file_upload`, `file_download`) that the log-shipper maps
1:1 from Cowrie's native `eventid`; events matching no MITRE technique are still
stored and marked processed. The most analytically relevant types are:

### auth_attempt
Failed authentication on any honeypot service.
details: { "username": "root", "password": "[REDACTED]", "attempts": 5 }

### auth_success
Successful authentication (honeypot accepted credentials).
details: { "username": "admin", "password": "[REDACTED]", "credentials_source": "decoy_file_1" }

### command_exec
Attacker executed a command in the fake shell.
details: { "command": "whoami", "output": "root", "exit_code": 0 }

### file_access
Attacker accessed a decoy file.
details: { "file_path": "/home/admin/.env", "file_type": "decoy_credential", "canarytoken_id": "abc123" }

### sql_injection
Attacker performed SQL injection on deception-gw.
details: { "endpoint": "/api/users", "payload": "' OR 1=1 --", "rows_returned": 10000 }

### webshell_upload
Attacker uploaded a webshell.
details: { "filename": "shell.php", "upload_path": "/var/www/uploads/shell.php", "file_size": 2048 }

### credential_use
Decoy credential was used. The current implementation records the configured
canary mode locally and does not call an external canary service.
details: { "credential_type": "aws_key", "credential_id": "DECOY_AWS_CANARY_ID", "canarytoken_triggered": true }

### tarpit_connect
Connection accepted by Endlessh tarpit.
details: { "delay_seconds": 0, "bytes_sent": 0 }
(The shipper currently parses Endlessh ACCEPT lines only; a matching
tarpit_disconnect from CLOSE lines is a possible future addition.)

## Session Tracking

Every attacker interaction is grouped into a session. A session starts when an attacker connects to any honeypot service and ends after 30 minutes of inactivity. Sessions track the attacker's journey through the deception layers.

```json
{
  "session_id": "uuid-v4",
  "source_ip": "203.0.113.45",
  "start_time": "2026-06-29T12:00:00.000Z",
  "end_time": null,
  "layers_reached": ["ssh", "web_app", "database"],
  "events": ["event_id_1", "event_id_2"],
  "mitre_techniques": ["T1110.001", "T1190"],
  "attacker_fingerprint": { ... }
}
```

## Log File Locations

Each honeypot service writes JSONL to /var/log/trap-house/:
- Cowrie: /var/log/trap-house/cowrie.json (via bind mount, configured in cowrie.cfg)
- deception-gw: /var/log/trap-house/deception-gw.json (via bind mount, configured in config.py)
- Endlessh: stdout captured via `docker logs` (no file, read by log-shipper through Docker API)

log-shipper reads these files and writes normalized events to:
- the SQLite intel store (`data/db/trap-house.db`, `events` table)
- Loki (via HTTP push to http://loki:3100/loki/api/v1/push)
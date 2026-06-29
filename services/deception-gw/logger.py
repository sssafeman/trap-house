"""JSONL event logger for the deception-gw service.

Writes one JSON object per line to LOG_PATH, following the shared schema in
EVENT_SCHEMA.md. The log-shipper normalizes these into the intel store.
"""
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import config

# Maps event types to MITRE ATT&CK technique and tactic identifiers.
MITRE_MAP: dict[str, tuple[str, str]] = {
    "auth_attempt": ("T1110.001", "credential-access"),
    "auth_success": ("T1078", "defense-evasion"),
    "command_exec": ("T1059", "execution"),
    "file_access": ("T1083", "discovery"),
    "sql_injection": ("T1190", "initial-access"),
    "webshell_upload": ("T1505.003", "persistence"),
    "credential_use": ("T1552.001", "credential-access"),
}


def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with millisecond Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def detect_tool(user_agent: str) -> str:
    """Classify the attacker tool from a User-Agent string."""
    ua = (user_agent or "").lower()
    if "sqlmap" in ua:
        return "sqlmap"
    if "hydra" in ua:
        return "hydra"
    if "nmap" in ua:
        return "nmap"
    if "curl" in ua or "wget" in ua or "python" in ua:
        return "manual"
    if ua:
        return "unknown"
    return "unknown"


def build_fingerprint(user_agent: str) -> dict[str, Any]:
    """Build the attacker_fingerprint block from request headers."""
    return {
        "user_agent": user_agent or "",
        "ssh_client": None,
        "tool": detect_tool(user_agent),
    }


def log_event(
    event_type: str,
    source_ip: str,
    source_port: int,
    session_id: Optional[str],
    details: dict[str, Any],
    user_agent: str = "",
    dest_port: int = 8000,
    raw_data: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Write a single event to the JSONL log and return the event object."""
    technique, tactic = MITRE_MAP.get(event_type, ("", ""))
    event: dict[str, Any] = {
        "timestamp": _now_iso(),
        "event_id": str(uuid.uuid4()),
        "source_service": "deception-gw",
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "event_type": event_type,
        "session_id": session_id,
        "attacker_fingerprint": build_fingerprint(user_agent),
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "details": details,
        "raw_data": raw_data or {},
    }
    _write(event)
    return event


def _write(event: dict[str, Any]) -> None:
    """Append a single event as one JSON line. Failures are swallowed so a
    logging error never breaks the attacker-facing response."""
    try:
        os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)
        with open(config.LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
    except OSError:
        pass

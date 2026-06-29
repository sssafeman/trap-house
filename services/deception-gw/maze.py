"""Maze state machine and session management.

Tracks each attacker's progression through the 5 deception layers, signs and
verifies session cookies, and computes the progressive authentication delay.
All state is in memory. There is no real database.
"""
import uuid
from typing import Any, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import config

# Layer names keyed by route, for tracking how deep an attacker has gone.
LAYER_NAMES: dict[int, str] = {
    1: "web_login",
    2: "dashboard",
    3: "sql_injection",
    4: "webshell",
    5: "aws_keys",
}

# Maximum cookie age in seconds (30 minutes of inactivity ends a session).
SESSION_MAX_AGE: int = 1800


class Maze:
    """Holds cross-request maze state: per-IP failure counts and the cookie
    serializer. Sessions themselves live in the signed cookie."""

    def __init__(self) -> None:
        self._serializer = URLSafeTimedSerializer(config.SESSION_SECRET)
        self._failures_by_ip: dict[str, int] = {}

    # Progressive authentication delay -------------------------------------

    def record_failure(self, ip: str) -> int:
        """Increment and return the failure count for an IP."""
        self._failures_by_ip[ip] = self._failures_by_ip.get(ip, 0) + 1
        return self._failures_by_ip[ip]

    def failure_count(self, ip: str) -> int:
        """Return the current failure count for an IP."""
        return self._failures_by_ip.get(ip, 0)

    def reset_failures(self, ip: str) -> None:
        """Clear the failure count for an IP after a successful login."""
        self._failures_by_ip.pop(ip, None)

    def delay_for(self, count: int) -> int:
        """Return the delay in seconds for the nth failure: min(2^n, cap)."""
        if count <= 0:
            return 0
        return min(2 ** count, config.AUTH_DELAY_CAP)

    # Session cookie handling ----------------------------------------------

    def new_session(self, username: str) -> dict[str, Any]:
        """Create a fresh session dict after a successful login."""
        return {
            "session_id": str(uuid.uuid4()),
            "username": username,
            "current_layer": 2,
            "failed_logins": 0,
            "commands_run": 0,
            "files_accessed": 0,
        }

    def sign(self, session: dict[str, Any]) -> str:
        """Serialize and sign a session dict into a cookie value."""
        return self._serializer.dumps(session)

    def load(self, cookie: Optional[str]) -> Optional[dict[str, Any]]:
        """Verify and load a session from a cookie value. Returns None if the
        cookie is missing, tampered with, or expired."""
        if not cookie:
            return None
        try:
            data = self._serializer.loads(cookie, max_age=SESSION_MAX_AGE)
        except (BadSignature, SignatureExpired):
            return None
        if isinstance(data, dict) and "session_id" in data:
            return data
        return None

    def advance(self, session: dict[str, Any], layer: int) -> None:
        """Advance the session to a deeper layer if it is not already there."""
        if layer > session.get("current_layer", 1):
            session["current_layer"] = layer

"""Configuration for the deception-gw fake corporate web app.

All secrets here are decoys. No real credentials, no real infrastructure.
"""
import os

# Path to the JSONL event log. The container mounts /var/log/trap-house.
LOG_PATH: str = os.environ.get("LOG_PATH", "/var/log/trap-house/deception-gw.json")

# Signing key for session cookies. Overridden by SESSION_SECRET in production.
SESSION_SECRET: str = os.environ.get("SESSION_SECRET", "changeme-secret-key")

# Canarytokens are disabled by default. When false, canary events are logged
# locally as "would_trigger_canary" with no network egress.
ENABLE_CANARYTOKENS: bool = os.environ.get("ENABLE_CANARYTOKENS", "false").lower() == "true"

# Company branding for the fake corporate app.
COMPANY_NAME: str = "NordTech Solutions"

# Layer 1 decoy credentials. These match Cowrie's planted .env file so an
# attacker who pivots from SSH to the web app finds the same logins work.
DECOY_CREDENTIALS: dict[str, str] = {
    "admin": "TrapH0use!2026",
    "devops": "D3v0ps_S3cur1ty",
    "backup": "b@ckup_s3rv3r_99",
}

# Maps a decoy username to a label used in auth_success logging.
CREDENTIAL_SOURCE: dict[str, str] = {
    "admin": "decoy_file_1",
    "devops": "decoy_file_2",
    "backup": "decoy_file_3",
}

# Deeper decoy credentials planted inside the maze. They lead in circles.
DEEPER_CREDENTIALS: dict[str, str] = {
    "backup_admin": "B@ckup!P@ss",
    "db_admin": "M@z3Loop#999",
}

# Fake AWS keys shown on /admin/config. The access key id embeds a canary
# marker so it is recognizable if it ever shows up in real logs.
FAKE_AWS_ACCESS_KEY: str = "AKIATRAPHOUSE0000DEC0Y"
FAKE_AWS_SECRET_KEY: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYTRAPHOUSEKEY"
FAKE_AWS_CANARY_ID: str = "AKIA-DECOY-001"

# Progressive auth delay. Delay on the nth failure is min(2^n, AUTH_DELAY_CAP).
AUTH_DELAY_CAP: int = 30

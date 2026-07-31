"""Configuration for the deception-gw fake corporate web app.

All secrets here are decoys. No real credentials, no real infrastructure.
"""
import os

# Path to the JSONL event log. The container mounts /var/log/trap-house.
LOG_PATH: str = os.environ.get("LOG_PATH", "/var/log/trap-house/deception-gw.json")

# Signing key for session cookies. Production overrides this with a random
# value through the production Compose file.
SESSION_SECRET: str = os.environ.get(
    "SESSION_SECRET", "local-development-only-session-secret"
)

# Canary mode is disabled by default. The current implementation records the
# mode locally and does not make external canary webhook requests.
ENABLE_CANARYTOKENS: bool = os.environ.get("ENABLE_CANARYTOKENS", "false").lower() == "true"

# Company branding for the fake corporate app.
COMPANY_NAME: str = "NordTech Solutions"

# Layer 1 decoy credentials. These match Cowrie's planted .env file so an
# attacker who pivots from SSH to the web app finds the same logins work.
DECOY_CREDENTIALS: dict[str, str] = {
    "admin": "NordTech@Admin#2024",
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

# Clearly nonfunctional values shown on /admin/config. They are intentionally
# labeled as decoys so source scanners do not mistake them for cloud secrets.
FAKE_AWS_ACCESS_KEY: str = "DECOY_AWS_ACCESS_KEY_ID"
FAKE_AWS_SECRET_KEY: str = "DECOY_AWS_SECRET_ACCESS_KEY"
FAKE_AWS_CANARY_ID: str = "DECOY_AWS_CANARY_ID"

# Progressive auth delay. Delay on the nth failure is min(2^n, AUTH_DELAY_CAP).
AUTH_DELAY_CAP: int = 30

# Resource bounds. This service is bound directly to the internet, so every
# attacker-driven accumulator needs a ceiling to prevent memory exhaustion.
MAX_UPLOAD_BYTES: int = 1024 * 1024        # Reject uploads larger than 1 MiB.
MAX_SANDBOX_BYTES: int = 4 * 1024 * 1024   # Cap total bytes stored per sandbox.
MAX_SANDBOX_FILES: int = 50                # Cap files stored per sandbox.
MAX_SANDBOXES: int = 2048                  # Evict oldest sandboxes past this.
MAX_TRACKED_IPS: int = 8192               # Evict oldest failure counters past this.

# Trust the X-Forwarded-For header only when a known reverse proxy sets it.
# When the app is bound directly to a public port (the default), the header is
# fully attacker-controlled and must be ignored so logged source IPs are real.
TRUST_XFF: bool = os.environ.get("TRUST_XFF", "false").lower() == "true"

# Domain used for decoy email addresses sprinkled into the fake user dataset.
# Leave blank to disable. Use a domain you control if you want outbound use to
# be observable.
CANARY_EMAIL_DOMAIN: str = os.environ.get("CANARY_EMAIL_DOMAIN", "")

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "log-shipper"))
sys.path.insert(0, str(ROOT / "services" / "deception-gw"))

import shipper  # noqa: E402
from fake_fs import WebshellSandbox  # noqa: E402


class DataIntegrityTests(unittest.TestCase):
    def test_cowrie_raw_password_is_redacted(self):
        raw = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-07-31T12:00:00+00:00",
            "session": "session-1",
            "src_ip": "192.0.2.10",
            "username": "root",
            "password": "not-for-storage",
        }

        event = shipper.normalize_cowrie(raw)

        self.assertEqual(json.loads(event["details"])["password"], "[REDACTED]")
        self.assertEqual(json.loads(event["raw_data"])["password"], "[REDACTED]")

    def test_upload_replacement_replaces_bytes(self):
        sandbox = WebshellSandbox()

        path, stored = sandbox.upload("shell.php", "1234")
        self.assertTrue(stored)
        self.assertEqual(path, "/var/www/uploads/shell.php")
        self.assertEqual(sandbox._stored_bytes, 4)

        path, stored = sandbox.upload("shell.php", "12")
        self.assertTrue(stored)
        self.assertEqual(path, "/var/www/uploads/shell.php")
        self.assertEqual(sandbox._stored_bytes, 2)

    def test_upload_rejection_is_explicit(self):
        import config

        old_limit = config.MAX_SANDBOX_BYTES
        try:
            config.MAX_SANDBOX_BYTES = 1
            sandbox = WebshellSandbox()
            path, stored = sandbox.upload("large.bin", "12")
            self.assertEqual(path, "/var/www/uploads/large.bin")
            self.assertFalse(stored)
            self.assertEqual(sandbox._stored_bytes, 0)
        finally:
            config.MAX_SANDBOX_BYTES = old_limit

    def test_session_aggregation_updates_metadata(self):
        conn = shipper.sqlite3.connect(":memory:")
        conn.executescript(shipper.DATABASE_SCHEMA)
        first = {
            "session_id": "session-1",
            "source_ip": "192.0.2.10",
            "source_service": "cowrie",
            "timestamp": "2026-07-31T12:00:00+00:00",
            "mitre_technique": "T1110.001",
        }
        second = {
            "session_id": "session-1",
            "source_ip": "192.0.2.10",
            "source_service": "deception-gw",
            "timestamp": "2026-07-31T12:01:00+00:00",
            "mitre_technique": "T1190",
        }

        shipper._update_session(conn, first)
        shipper._update_session(conn, second)
        row = conn.execute(
            "SELECT start_time, end_time, event_count, mitre_techniques, layers_reached "
            "FROM sessions WHERE session_id = 'session-1'"
        ).fetchone()

        self.assertEqual(row[0], first["timestamp"])
        self.assertEqual(row[1], second["timestamp"])
        self.assertEqual(row[2], 2)
        self.assertEqual(set(json.loads(row[3])), {"T1110.001", "T1190"})
        self.assertEqual(set(json.loads(row[4])), {"cowrie", "deception-gw"})

    def test_session_aggregation_repairs_missing_end_time(self):
        conn = shipper.sqlite3.connect(":memory:")
        conn.executescript(shipper.DATABASE_SCHEMA)
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("legacy", "192.0.2.10", "cowrie", "2026-07-31T12:00:00+00:00", None, 1, "[]", "[]"),
        )
        event = {
            "session_id": "legacy",
            "source_ip": "192.0.2.10",
            "source_service": "cowrie",
            "timestamp": "2026-07-31T12:01:00+00:00",
            "mitre_technique": None,
        }
        shipper._update_session(conn, event)
        self.assertEqual(
            conn.execute("SELECT end_time FROM sessions WHERE session_id = 'legacy'").fetchone()[0],
            event["timestamp"],
        )


if __name__ == "__main__":
    unittest.main()

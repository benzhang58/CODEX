import json
import os
import shutil
import sys
import unittest
from pathlib import Path

os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"] = "/tmp/discere-test-storage"
os.environ["EMAIL_SUMMARIZER_OUTPUT_DIR"] = "/tmp/discere-test-output"
os.environ["EMAIL_SUMMARIZER_PUBLIC_BASE_URL"] = "https://discere-test.example"
os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = "false"
os.environ["EMAIL_SUMMARIZER_ENCRYPTION_KEY"] = "test-only-encryption-key"
os.environ["OPENAI_API_KEY"] = "test-openai-key"
os.environ["WHITELIST_SENDERS"] = "should-not-leak@example.com"
os.environ["IMAP_USER"] = "global-imap@example.com"
os.environ["IMAP_PASSWORD"] = "global-imap-password"
os.environ["SMTP_USER"] = "global-smtp@example.com"
os.environ["SMTP_PASSWORD"] = "global-smtp-password"
os.environ["SUMMARY_RECIPIENT"] = "global-recipient@example.com"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import dashboard_api


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"], ignore_errors=True)
        shutil.rmtree(os.environ["EMAIL_SUMMARIZER_OUTPUT_DIR"], ignore_errors=True)
        dashboard_api.initialize_database()
        self.client = TestClient(dashboard_api.app, base_url="https://discere-test.example")

    def signup(self, email: str) -> TestClient:
        client = TestClient(dashboard_api.app, base_url="https://discere-test.example")
        response = client.post(
            "/auth/signup",
            json={
                "email": email,
                "password": "StrongPass123!",
                "accept_terms": True,
                "accept_privacy": True,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return client

    def test_cookie_secure_defaults_on_for_https_public_base_url(self) -> None:
        self.assertTrue(dashboard_api.SESSION_COOKIE_SECURE)

    def test_new_accounts_do_not_inherit_global_account_scoped_settings(self) -> None:
        client = self.signup("fresh@example.com")
        response = client.get("/whitelist")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["contacts"], [])

        export_response = client.get("/auth/account/export")
        self.assertEqual(export_response.status_code, 200, export_response.text)
        payload = export_response.json()
        self.assertEqual(payload["settings"].get("IMAP_USER"), "fresh@example.com")
        self.assertEqual(payload["settings"].get("SMTP_USER"), "fresh@example.com")
        self.assertEqual(payload["settings"].get("SUMMARY_RECIPIENT"), "fresh@example.com")
        self.assertNotIn("global-imap@example.com", json.dumps(payload))
        self.assertNotIn("should-not-leak@example.com", json.dumps(payload))

    def test_cross_account_user_id_override_is_blocked(self) -> None:
        alice = self.signup("alice@example.com")
        bob = self.signup("bob@example.com")

        response = alice.post(
            "/whitelist",
            json={"user_id": "alice_example_com", "contacts": ["a@sender.com"]},
        )
        self.assertEqual(response.status_code, 200, response.text)

        response = bob.get("/whitelist")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["contacts"], [])

        response = bob.get("/whitelist", params={"user_id": "alice_example_com"})
        self.assertEqual(response.status_code, 403, response.text)

    def test_export_redacts_sensitive_values(self) -> None:
        client = self.signup("export@example.com")
        response = client.get("/auth/account/export")
        self.assertEqual(response.status_code, 200, response.text)
        settings = response.json()["settings"]
        self.assertNotIn("IMAP_PASSWORD", settings)
        self.assertNotIn("SMTP_PASSWORD", settings)
        self.assertNotIn("OPENAI_API_KEY", settings)
        self.assertIn("Content-Disposition", response.headers)

    def test_account_deletion_removes_account_scoped_database_rows_and_files(self) -> None:
        client = self.signup("delete@example.com")
        user_id = "delete_example_com"
        client.post("/bug-reports", json={"user_id": user_id, "title": "Bug", "description": "Details"})
        client.post(
            "/report-schedules",
            json={
                "user_id": user_id,
                "name": "Daily",
                "recipient_email": "delete@example.com",
                "interval_value": 1,
                "interval_unit": "days",
                "timezone": "America/Los_Angeles",
            },
        )
        user_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / user_id
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "marker.txt").write_text("private", encoding="utf-8")

        response = client.delete("/auth/account")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(user_dir.exists())

        with dashboard_api.get_db_connection() as connection:
            for table in ["users", "sessions", "report_schedules", "analytics_events", "bug_reports"]:
                count = connection.execute(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE user_id = ?",
                    (user_id,),
                ).fetchone()["count"]
                self.assertEqual(count, 0, table)

    def test_readiness_endpoint_is_safe_and_configured(self) -> None:
        response = self.client.get("/health/readiness")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("checks", payload)
        serialized = json.dumps(payload)
        self.assertNotIn("test-openai-key", serialized)
        self.assertNotIn("test-only-encryption-key", serialized)

    def test_rate_limit_blocks_repeated_login_attempts_when_enabled(self) -> None:
        original = os.environ.get("EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED", "")
        os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = "true"
        dashboard_api.RATE_LIMIT_BUCKETS.clear()
        try:
            for _ in range(20):
                response = self.client.post(
                    "/auth/login",
                    json={"email": "nobody@example.com", "password": "wrongpassword"},
                )
                self.assertEqual(response.status_code, 401, response.text)
            response = self.client.post(
                "/auth/login",
                json={"email": "nobody@example.com", "password": "wrongpassword"},
            )
            self.assertEqual(response.status_code, 429, response.text)
        finally:
            dashboard_api.RATE_LIMIT_BUCKETS.clear()
            os.environ["EMAIL_SUMMARIZER_RATE_LIMIT_ENABLED"] = original


if __name__ == "__main__":
    unittest.main()

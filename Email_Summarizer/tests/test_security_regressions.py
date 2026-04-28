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
os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = "100"
os.environ["EMAIL_SUMMARIZER_LIMIT_RUN_SUMMARIZER_PER_DAY"] = "10"

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

    def test_home_redirects_to_dashboard_when_session_is_valid(self) -> None:
        client = self.signup("home-redirect@example.com")
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307, response.text)
        self.assertEqual(response.headers.get("location"), "/dashboard")

    def test_home_stays_public_after_logout(self) -> None:
        client = self.signup("home-logout@example.com")
        logout_response = client.post("/auth/logout")
        self.assertEqual(logout_response.status_code, 200, logout_response.text)

        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)

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

    def test_cross_account_summary_and_attachment_access_is_blocked(self) -> None:
        alice = self.signup("summary-alice@example.com")
        bob = self.signup("summary-bob@example.com")
        alice_user_id = "summary_alice_example_com"
        bob_user_id = "summary_bob_example_com"

        alice_summary_dir = dashboard_api.get_user_json_summaries_dir(alice_user_id)
        alice_summary_dir.mkdir(parents=True, exist_ok=True)
        (alice_summary_dir / "secret.json").write_text(
            json.dumps(
                {
                    "summary_id": "secret",
                    "sender": "boss@example.com",
                    "title": "Private Alice summary",
                    "executive_summary": "Alice-only content",
                }
            ),
            encoding="utf-8",
        )

        alice_attachment_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / alice_user_id / "attachments"
        alice_attachment_dir.mkdir(parents=True, exist_ok=True)
        alice_attachment = alice_attachment_dir / "private.txt"
        alice_attachment.write_text("alice private attachment", encoding="utf-8")

        response = alice.get("/summaries/secret")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("Alice-only content", response.text)

        response = bob.get("/summaries/secret")
        self.assertEqual(response.status_code, 404, response.text)

        response = bob.get("/summaries/secret", params={"user_id": alice_user_id})
        self.assertEqual(response.status_code, 403, response.text)

        response = bob.get(
            "/attachments",
            params={"user_id": bob_user_id, "path": str(alice_attachment)},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_public_report_links_reject_path_traversal_even_with_valid_signature(self) -> None:
        user_id = "report_owner"
        private_dir = Path(os.environ["EMAIL_SUMMARIZER_STORAGE_DIR"]) / "users" / user_id
        private_dir.mkdir(parents=True, exist_ok=True)
        private_file = private_dir / "private.pdf"
        private_file.write_bytes(b"%PDF-1.4 private")

        traversal_path = f"{user_id}/../users/{user_id}/private.pdf"
        expires = int((dashboard_api.datetime.now() + dashboard_api.timedelta(minutes=5)).timestamp())
        signature = dashboard_api.sign_public_report_token(user_id, traversal_path, expires)

        response = self.client.get(
            "/public-report",
            params={"user_id": user_id, "path": traversal_path, "expires": expires, "sig": signature},
        )
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
            for table in ["users", "sessions", "report_schedules", "analytics_events", "bug_reports", "usage_counters"]:
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
        self.assertTrue(payload["checks"]["security_headers_enabled"])
        self.assertTrue(payload["checks"]["cors_origins_production_safe"])
        serialized = json.dumps(payload)
        self.assertNotIn("test-openai-key", serialized)
        self.assertNotIn("test-only-encryption-key", serialized)

    def test_security_headers_are_applied(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers.get("content-security-policy", ""))
        self.assertIn("max-age=31536000", response.headers.get("strict-transport-security", ""))

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

    def test_request_and_input_size_limits(self) -> None:
        client = self.signup("limits@example.com")

        response = client.post(
            "/bug-reports",
            json={"user_id": "limits_example_com", "title": "Bug", "description": "x" * (dashboard_api.MAX_BUG_DESCRIPTION_CHARS + 1)},
        )
        self.assertEqual(response.status_code, 413, response.text)

        response = client.post(
            "/summaries/combined",
            json={
                "user_id": "limits_example_com",
                "summary_ids": [f"summary-{index}" for index in range(dashboard_api.MAX_SUMMARY_IDS_PER_REQUEST + 1)],
            },
        )
        self.assertEqual(response.status_code, 413, response.text)

        original = os.environ.get("EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES", "")
        try:
            dashboard_api.MAX_REQUEST_BODY_BYTES = 10
            response = client.post(
                "/bug-reports",
                json={"user_id": "limits_example_com", "title": "Bug", "description": "Details"},
            )
            self.assertEqual(response.status_code, 413, response.text)
        finally:
            dashboard_api.MAX_REQUEST_BODY_BYTES = int(os.getenv("EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))
            if original:
                os.environ["EMAIL_SUMMARIZER_MAX_REQUEST_BODY_BYTES"] = original

    def test_admin_page_loads_and_admin_endpoints_require_access(self) -> None:
        page_response = self.client.get("/admin")
        self.assertEqual(page_response.status_code, 200, page_response.text)
        self.assertIn("Discere Admin", page_response.text)

        blocked_response = self.client.get("/admin/analytics")
        self.assertEqual(blocked_response.status_code, 403, blocked_response.text)

        original_key = os.environ.get("EMAIL_SUMMARIZER_ADMIN_KEY", "")
        os.environ["EMAIL_SUMMARIZER_ADMIN_KEY"] = "test-admin-key"
        try:
            allowed_response = self.client.get(
                "/admin/analytics",
                headers={"x-discere-admin-key": "test-admin-key"},
            )
            self.assertEqual(allowed_response.status_code, 200, allowed_response.text)
            self.assertIn("totals", allowed_response.json())

            monitoring_response = self.client.get(
                "/admin/monitoring",
                headers={"x-discere-admin-key": "test-admin-key"},
            )
            self.assertEqual(monitoring_response.status_code, 200, monitoring_response.text)
            self.assertIn("events", monitoring_response.json())
        finally:
            if original_key:
                os.environ["EMAIL_SUMMARIZER_ADMIN_KEY"] = original_key
            else:
                os.environ.pop("EMAIL_SUMMARIZER_ADMIN_KEY", None)

    def test_daily_usage_limits_are_enforced_per_account(self) -> None:
        client = self.signup("usage@example.com")
        original_chat_limit = os.environ.get("EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY", "")
        os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = "1"
        try:
            first_response = client.post(
                "/chat",
                json={"user_id": "usage_example_com", "question": "What happened?"},
            )
            self.assertEqual(first_response.status_code, 404, first_response.text)

            usage_response = client.get("/usage")
            self.assertEqual(usage_response.status_code, 200, usage_response.text)
            chat_usage = usage_response.json()["usage"]["chat"]
            self.assertEqual(chat_usage["count"], 1)
            self.assertEqual(chat_usage["limit"], 1)

            second_response = client.post(
                "/chat",
                json={"user_id": "usage_example_com", "question": "What happened again?"},
            )
            self.assertEqual(second_response.status_code, 429, second_response.text)
        finally:
            os.environ["EMAIL_SUMMARIZER_LIMIT_CHAT_PER_DAY"] = original_chat_limit or "100"

    def test_monitoring_records_security_events_without_sensitive_metadata(self) -> None:
        client = self.signup("monitor@example.com")
        response = client.get("/whitelist", params={"user_id": "other_user"})
        self.assertEqual(response.status_code, 403, response.text)

        dashboard_api.write_monitoring_event(
            "security",
            "manual_secret_test",
            "warning",
            user_id="monitor_example_com",
            metadata={"api_key": "should-redact", "safe": "visible"},
        )

        with dashboard_api.get_db_connection() as connection:
            rows = connection.execute(
                """
                SELECT category, event_name, severity, user_id, metadata_json
                FROM monitoring_events
                ORDER BY created_at DESC
                """
            ).fetchall()

        serialized = json.dumps([dict(row) for row in rows])
        self.assertIn("cross_account_user_id_override", serialized)
        self.assertIn("manual_secret_test", serialized)
        self.assertIn("[redacted]", serialized)
        self.assertNotIn("should-redact", serialized)


if __name__ == "__main__":
    unittest.main()
